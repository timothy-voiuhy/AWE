from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
import sys

import docker
import pytest
from fastapi import HTTPException

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from awe_backend import image_readiness as readiness
from awe_backend.docker_service import DockerService
from containers.tool_registry import TOOL_REGISTRY
from containers.parsers import PARSERS


def tool(**kwargs):
    return SimpleNamespace(image="registry.invalid/tool:2", dockerfile="", output_channels=["logs", "structured"], **kwargs)


def service(image=None):
    client = Mock()
    if image is None:
        client.images.get.side_effect = docker.errors.ImageNotFound("missing")
    else:
        client.images.get.return_value = image
    instance = DockerService()
    instance._client = lambda: client
    return instance, client


def image(**attrs):
    return SimpleNamespace(id="sha256:local", attrs=attrs)


@pytest.fixture(autouse=True)
def clear_cache():
    readiness._checks.clear()


def test_exact_reference_is_required_and_no_registry_access_for_missing_image():
    instance, client = service()
    state = readiness.image_state(tool(), instance, refresh=True)
    assert not state["image_present"]
    client.images.get.assert_called_once_with("registry.invalid/tool:2")
    client.images.get_registry_data.assert_not_called()


def test_inventory_matches_latest_alias_but_never_a_different_version():
    instance, client = service()
    client.images.list.return_value = [SimpleNamespace(tags=["docker.io/awe/tool:latest"], short_id="latest", attrs={}), SimpleNamespace(tags=["awe/tool:2"], short_id="two", attrs={})]
    assert [item["id"] for item in instance.images({"awe/tool"})] == ["latest"]
    assert instance.images({"awe/tool:1"}) == []
    assert readiness.canonical_reference("alpine") == readiness.canonical_reference("docker.io/library/alpine:latest")
    assert readiness.canonical_reference("localhost:5000/tool:2") == "localhost:5000/tool:2"


def test_registry_comparison_cache_expiry_and_pull_invalidation(monkeypatch):
    instance, client = service(image(RepoDigests=["registry.invalid/tool@sha256:old"]))
    client.images.get_registry_data.return_value.id = "sha256:new"
    assert readiness.image_state(tool(), instance)["update_status"] == "unchecked"
    state = readiness.image_state(tool(), instance, refresh=True)
    assert state["update_status"] == "outdated"
    assert state["update_checked_at"]
    assert readiness.image_state(tool(), instance)["update_status"] == "outdated"
    assert client.images.get_registry_data.call_count == 1
    client.images.pull.return_value = SimpleNamespace(short_id="local", tags=[tool().image])
    instance.pull_image(tool().image)
    assert readiness.image_state(tool(), instance)["update_status"] == "unchecked"
    readiness.image_state(tool(), instance, refresh=True)
    monkeypatch.setattr(readiness.time, "time", lambda: 10 ** 20)
    assert readiness.image_state(tool(), instance)["update_status"] == "unchecked"


@pytest.mark.parametrize("digests,remote,expected", [(["repo@sha256:current"], "sha256:current", "current"), ([], "sha256:new", "unknown")])
def test_registry_digest_comparison(digests, remote, expected):
    instance, client = service(image(RepoDigests=digests))
    client.images.get_registry_data.return_value.id = remote
    assert readiness.image_state(tool(), instance, refresh=True)["update_status"] == expected


def test_registry_failure_is_unknown_without_leaking_credentials():
    instance, client = service(image())
    client.images.get_registry_data.side_effect = RuntimeError("secret-registry-token")
    state = readiness.image_state(tool(), instance, refresh=True)
    assert state["update_status"] == "unknown"
    assert "secret-registry-token" not in str(state)


def test_build_fingerprint_tracks_inputs_but_respects_dockerignore(tmp_path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM scratch\nCOPY source /source\n")
    (tmp_path / ".dockerignore").write_text("ignored\n")
    (tmp_path / "source").write_text("one")
    (tmp_path / "ignored").write_text("one")
    fingerprint = readiness.context_fingerprint(str(dockerfile))
    (tmp_path / "ignored").write_text("two")
    assert readiness.context_fingerprint(str(dockerfile)) == fingerprint
    instance, _ = service(image(Config={"Labels": {readiness.BUILD_LABEL: fingerprint}}))
    built = tool()
    built.dockerfile = str(dockerfile)
    assert readiness.image_state(built, instance)["update_status"] == "current"
    (tmp_path / "source").write_text("two")
    assert readiness.image_state(built, instance)["update_status"] == "outdated"


def test_old_build_without_provenance_is_unknown(tmp_path):
    instance, _ = service(image())
    built = tool()
    built.dockerfile = str(tmp_path / "Dockerfile")
    assert readiness.image_state(built, instance)["update_status"] == "unknown"


def test_check_updates_deduplicates_shared_images():
    instance, client = service(image(RepoDigests=["repo@sha256:current"]))
    client.images.get_registry_data.return_value.id = "sha256:current"
    assert len(readiness.check_updates([tool(), tool()], instance)) == 1
    client.images.get_registry_data.assert_called_once()


def test_composite_preflight_checks_all_tools_and_structured_parser(monkeypatch):
    instance, _ = service()
    monkeypatch.setitem(TOOL_REGISTRY, "fixture", tool())
    monkeypatch.delitem(PARSERS, "fixture", raising=False)
    transform = SimpleNamespace(stages=[SimpleNamespace(tool_keys=["fixture", "fixture", "missing-fixture"])])
    report = readiness.transform_preflight(transform, instance)
    assert not report["ready"]
    assert len(report["tools"]) == 2
    assert {issue["code"] for issue in report["tools"][0]["issues"]} == {"image_missing", "parser_missing"}
    with pytest.raises(HTTPException) as error:
        readiness.require_ready(report)
    assert error.value.status_code == 409
    assert "Pull it" in error.value.detail


def test_logs_only_tool_does_not_require_parser_and_invalid_parser_blocks(monkeypatch, tmp_path):
    instance, _ = service(image())
    logs = tool()
    logs.output_channels = ["logs"]
    monkeypatch.setitem(TOOL_REGISTRY, "fixture", logs)
    assert readiness.tool_preflight(["fixture"], instance)["ready"]
    logs.output_channels = ["structured"]
    logs.parser_path = str(tmp_path / "parser.py")
    Path(logs.parser_path).write_text("def broken(:")
    monkeypatch.setitem(PARSERS, "fixture", lambda *_: [])
    report = readiness.tool_preflight(["fixture"], instance)
    assert not report["ready"]
    assert report["tools"][0]["issues"][0]["code"] == "parser_invalid"


def test_docker_unavailable_is_blocking(monkeypatch):
    instance, client = service()
    client.images.get.side_effect = docker.errors.DockerException("socket unavailable")
    monkeypatch.setitem(TOOL_REGISTRY, "fixture", tool())
    monkeypatch.setitem(PARSERS, "fixture", lambda *_: [])
    report = readiness.tool_preflight(["fixture"], instance)
    assert not report["ready"]
    assert report["tools"][0]["issues"][0]["code"] == "docker_unavailable"


def test_streamed_pull_does_not_claim_success_when_registry_returns_error():
    instance, client = service()
    client.api.pull.return_value = [{"status": "Pulling"}, {"error": "access denied"}]
    with pytest.raises(RuntimeError, match="access denied"):
        instance.pull_image("fixture:1", progress=lambda _: None)


def test_outdated_image_warns_without_blocking(monkeypatch):
    instance, client = service(image(RepoDigests=["repo@sha256:old"]))
    client.images.get_registry_data.return_value.id = "sha256:new"
    readiness.image_state(tool(), instance, refresh=True)
    monkeypatch.setitem(TOOL_REGISTRY, "fixture", tool())
    monkeypatch.setitem(PARSERS, "fixture", lambda *_: [])
    report = readiness.tool_preflight(["fixture"], instance)
    assert report["ready"]
    assert report["tools"][0]["issues"][0]["warning"]


@pytest.mark.skipif(__import__('os').environ.get('AWE_TEST_DOCKER') != '1', reason='Controlled Docker build requires AWE_TEST_DOCKER=1')
def test_real_build_records_provenance_and_source_change_is_outdated(tmp_path):
    import uuid
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM scratch\nCOPY content /content\n")
    (tmp_path / "content").write_text("controlled fixture")
    fixture = tool()
    fixture.image = f"awe/readiness-test:{uuid.uuid4().hex}"
    fixture.dockerfile = str(dockerfile)
    instance = DockerService()
    try:
        instance.build_image_path(str(dockerfile), fixture.image, progress=lambda _: None)
        assert readiness.image_state(fixture, instance)["update_status"] == "current"
        (tmp_path / "content").write_text("changed fixture")
        assert readiness.image_state(fixture, instance)["update_status"] == "outdated"
        instance.build_image_path(str(dockerfile), fixture.image)
        assert readiness.image_state(fixture, instance)["update_status"] == "current"
    finally:
        try:
            instance.remove_image(fixture.image)
        except docker.errors.ImageNotFound:
            pass
