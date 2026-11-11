from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from fastapi import HTTPException

from awe_backend.routes import graph as api
from awe_backend.graph_store import InvestigationStore
from awe_backend.schemas import DockerOperation, InvestigationCreate, TransformJob, TransformResume


def setup_resume(monkeypatch, tmp_path, *, operation_status="failed", parameters=None, secret_specs=None):
    job = TransformJob(
        id="job-1", project_id="project-1", investigation_id="investigation-1",
        transform_id="transform-1", status="running", entity_ids=["entity-1"],
        operation_id="operation-1", parameters=parameters or {"domain": "example.com"},
        created_at=datetime.now(timezone.utc),
    )
    monkeypatch.setattr(api, "_GRAPH_TRANSFORM_JOBS", {job.id: job})
    monkeypatch.setattr(api, "_GRAPH_TRANSFORM_SECRETS", {})
    transform = SimpleNamespace(
        id="transform-1", tool_key="amass", stages=[], input_types=["target"],
        parameters=secret_specs or [], requires_approval=False,
    )
    monkeypatch.setattr(api, "_graph_transforms", lambda *_: [transform])
    monkeypatch.setattr(api, "_graph_store", lambda *_: SimpleNamespace(get=lambda *_: SimpleNamespace(id="investigation-1")))
    entity = SimpleNamespace(id="entity-1", kind="target", value="example.com", label="example.com")
    monkeypatch.setattr(api, "_graph_bundle", lambda *_: SimpleNamespace(entities=[entity]))
    launch = Mock(return_value=DockerOperation(id="operation-2", kind="tool.amass", status="queued"))
    monkeypatch.setattr(api, "_launch_graph_transform_operation", launch)
    store = Mock()
    store.get.return_value = SimpleNamespace(target="example.com")
    store.project_dir.return_value = tmp_path
    manager = Mock()
    manager.get.return_value = DockerOperation(id="operation-1", kind="tool.amass", status=operation_status, message="Interrupted")
    return store, manager, launch


def resume(store, manager, payload=None):
    return api.resume_graph_transform(
        "project-1", "job-1", payload or TransformResume(), store=store,
        settings=Mock(), docker_operations=manager, docker_service=Mock(), repositories=Mock(),
    )


def test_resume_reuses_job_and_rejects_duplicate_active_run(monkeypatch, tmp_path):
    store, manager, launch = setup_resume(monkeypatch, tmp_path)

    result = resume(store, manager)

    assert result.id == "job-1"
    assert result.operation_id == "operation-2"
    assert result.status == "queued"
    assert launch.call_args.kwargs["resume"] is True
    manager.validate_checkpoint.assert_called_once()
    manager.cleanup_interrupted_container.assert_called_once()

    manager.get.return_value = DockerOperation(id="operation-2", kind="tool.amass", status="running")
    with pytest.raises(HTTPException) as exc:
        resume(store, manager)
    assert exc.value.status_code == 409
    assert launch.call_count == 1


def test_resume_preflight_blocks_before_checkpoint_cleanup_or_new_operation(monkeypatch, tmp_path):
    import docker
    from awe_backend.docker_service import DockerService
    store, manager, launch = setup_resume(monkeypatch, tmp_path)
    client = Mock()
    client.images.get.side_effect = docker.errors.ImageNotFound("required version missing")
    service = DockerService()
    service._client = lambda: client
    with pytest.raises(HTTPException) as error:
        api.resume_graph_transform("project-1", "job-1", TransformResume(), store=store, settings=Mock(), docker_operations=manager, docker_service=service, repositories=Mock())
    assert error.value.status_code == 409
    assert "Preflight failed" in error.value.detail
    launch.assert_not_called()
    manager.validate_checkpoint.assert_not_called()
    manager.cleanup_interrupted_container.assert_not_called()


@pytest.mark.parametrize('spec', [{"key": "token", "type": "secret"}, {"key": "token", "type": "text", "sensitive": True}])
def test_resume_requires_lost_secret_after_restart(monkeypatch, tmp_path, spec):
    store, manager, launch = setup_resume(
        monkeypatch, tmp_path, parameters={"domain": "example.com", "token": "[redacted]"},
        secret_specs=[spec],
    )

    with pytest.raises(HTTPException) as exc:
        resume(store, manager)
    assert exc.value.status_code == 422
    assert "token" in exc.value.detail
    launch.assert_not_called()

    result = resume(store, manager, TransformResume(parameters={"token": "replacement"}))
    assert result.status == "queued"
    assert launch.call_args.args[7]["token"] == "replacement"


def test_resumed_ingestion_does_not_duplicate_existing_graph_output(tmp_path):
    store = InvestigationStore(tmp_path)
    investigation = store.create("project-1", InvestigationCreate(name="Enumeration"))
    manifest = SimpleNamespace(output_types=["subdomain"], tool_key="amass")
    parsed = [{"domain": "www.example.com", "sources": ["amass"]}]

    first = api._ingest_graph_results("project-1", tmp_path, investigation.id, "example.com", None, manifest, parsed, provenance_id="job-1")
    second = api._ingest_graph_results("project-1", tmp_path, investigation.id, "example.com", None, manifest, parsed, provenance_id="job-1")

    saved = store.get("project-1", investigation.id)
    assert (first, second) == (1, 0)
    assert len(store.entities(saved)) == 1
    assert len(store.relationships(saved)) == 1
    assert saved.entity_ids == ["transform:job-1:0"]


def test_graph_transform_launch_passes_every_selected_entity_value_as_seed_input(monkeypatch, tmp_path):
    entities = [
        SimpleNamespace(id="sub-1", value="one.example.com", label="one.example.com"),
        SimpleNamespace(id="sub-2", value="two.example.com", label="two.example.com"),
    ]
    monkeypatch.setattr(api, "_graph_bundle", lambda *_: SimpleNamespace(entities=entities))
    manager = Mock()
    manager.start_tool.return_value = DockerOperation(id="operation", kind="tool.httpx", status="queued")
    transform = SimpleNamespace(tool_key="httpx", stages=[])

    operation = api._launch_graph_transform_operation(
        "project-1", tmp_path, "example.com", "investigation-1", transform,
        ["sub-1", "sub-2"], "sub-1", {}, "job-2", manager, Mock(), Mock(),
    )

    assert operation.id == "operation"
    assert manager.start_tool.call_args.kwargs["seed_values"] == ["one.example.com", "two.example.com"]
