from unittest.mock import Mock, patch

import pytest

from awe_backend.docker_operations import DockerOperationManager
from awe_backend.schemas import DockerOperation


def test_subfinder_command_runs_under_shell_instead_of_image_entrypoint(tmp_path):
    container = Mock()
    container.logs.return_value = iter(())
    container.attrs = {"State": {"ExitCode": 0}}
    container.short_id = "subfinder-container"
    container.id = "subfinder-container-id"

    client = Mock()
    client.images.list.return_value = [object()]
    client.containers.run.return_value = container
    service = Mock()
    service._client.return_value = client

    manager = DockerOperationManager()
    manager._items["operation"] = DockerOperation(id="operation", kind="tool.subfinder", status="running")
    manager._log = Mock()
    _, container_id = manager._run_tool_sync(
        "operation", "subfinder", {"domain": "example.com"}, tmp_path, service
    )

    options = client.containers.run.call_args.kwargs
    assert options["entrypoint"] == ["sh"]
    assert options["command"] == [
        "-c", "subfinder -d example.com -o /output/subfinder_results.txt -silent"
    ]
    assert container_id == "subfinder-container"
    container.remove.assert_called_once_with(force=True)


def test_recent_tool_runs_keep_output_available_after_container_cleanup():
    manager = DockerOperationManager()
    manager._items = {
        "image": DockerOperation(id="image", kind="image.pull.subfinder", status="completed", logs=["pull output"]),
        "tool": DockerOperation(id="tool", kind="tool.subfinder", status="failed", logs=["run output"]),
    }

    recent = manager.recent_tool_runs()

    assert [item.id for item in recent] == ["tool"]
    assert recent[0].logs == []
    assert manager.get("tool").logs == ["run output"]


def test_failed_tool_container_is_removed(tmp_path):
    container = Mock()
    container.logs.return_value = iter((b"tool error\n",))
    container.attrs = {"State": {"ExitCode": 1}}
    container.id = "failed-container-id"
    client = Mock()
    client.images.list.return_value = [object()]
    client.containers.run.return_value = container
    service = Mock()
    service._client.return_value = client
    manager = DockerOperationManager()
    manager._items["operation"] = DockerOperation(id="operation", kind="tool.subfinder", status="running")
    manager._log = Mock()

    with pytest.raises(RuntimeError, match="exited with code 1"):
        manager._run_tool_sync("operation", "subfinder", {"domain": "example.com"}, tmp_path, service)

    container.remove.assert_called_once_with(force=True)


def test_amass_output_directory_is_owned_by_image_user(tmp_path):
    container = Mock(id="amass-container", short_id="amass-container")
    container.logs.return_value = iter(())
    container.attrs = {"State": {"ExitCode": 0}}
    client = Mock()
    client.images.list.return_value = [object()]
    client.containers.run.return_value = container
    service = Mock()
    service._client.return_value = client
    workspace = tmp_path / "backend-workspace"
    host_workspace = tmp_path / "docker-host-workspace"
    output_dir = workspace / "project-1" / "amass-output"
    input_dir = workspace / "project-1" / "stage-input"
    input_dir.mkdir(parents=True)
    manager = DockerOperationManager(workspace_dir=workspace, docker_workspace_dir=host_workspace)
    manager._items["operation"] = DockerOperation(id="operation", kind="tool.amass", status="running")

    with patch("awe_backend.docker_operations.os.chown") as chown:
        manager._run_tool_sync("operation", "amass", {"domain": "example.com"}, output_dir, service, input_dir)

    chown.assert_called_once_with(output_dir, 1000, 1000)
    assert client.containers.run.call_args.kwargs["volumes"] == {
        str(host_workspace / "project-1" / "amass-output"): {"bind": "/output", "mode": "rw"},
        str(host_workspace / "project-1" / "stage-input"): {"bind": "/input", "mode": "ro"},
    }


def test_composite_resume_skips_checkpointed_tool_and_keeps_progress(tmp_path):
    manager = DockerOperationManager()
    manager._items["first"] = DockerOperation(id="first", kind="composite.test", status="queued", progress_total=2)
    stages = [{"name": "Enumerate", "tool_keys": ["subfinder", "amass"], "input_source": "seed"}]
    first_result = {"domain": "one.example.com", "sources": ["subfinder"]}
    second_result = {"domain": "two.example.com", "sources": ["amass"]}
    service = Mock()

    with patch.object(manager, "_run_tool_sync", side_effect=[([first_result], "first-container"), RuntimeError("interrupted")]):
        manager._run_composite("first", "test", stages, {"domain": "example.com"}, tmp_path, service)
    (tmp_path / "stage_1_subfinder").mkdir(exist_ok=True)
    (tmp_path / "stage_1_subfinder" / "subfinder_results.txt").write_text("one.example.com\n")
    assert manager.get("first").status == "failed"
    assert manager.get("first").progress_completed == 1

    manager._items["resumed"] = DockerOperation(id="resumed", kind="composite.test", status="queued", progress_total=2)
    with patch.object(manager, "_parse_output", return_value=[first_result]) as parse, patch.object(manager, "_run_tool_sync", return_value=([second_result], "second-container")) as run:
        manager._run_composite("resumed", "test", stages, {"domain": "example.com"}, tmp_path, service, resume=True)

    assert manager.get("resumed").status == "completed"
    assert manager.get("resumed").progress_completed == 2
    assert manager.get("resumed").result["parsed_count"] == 2
    parse.assert_called_once_with("subfinder", tmp_path / "stage_1_subfinder")
    assert run.call_args.args[1] == "amass"
    with pytest.raises(ValueError, match="changed"):
        manager.validate_checkpoint(tmp_path, "test", stages, {"domain": "different.example.com"})


def test_composite_resume_reruns_tool_when_checkpoint_output_is_missing(tmp_path):
    manager = DockerOperationManager()
    stages = [{"name": "Enumerate", "tool_keys": ["subfinder"], "input_source": "seed"}]
    params = {"domain": "example.com"}
    manager._save_checkpoint(tmp_path, manager._checkpoint_signature("test", stages, params), {"0:0:subfinder"})
    manager._items["resumed"] = DockerOperation(id="resumed", kind="composite.test", status="queued", progress_total=1)
    result = {"domain": "one.example.com", "sources": ["subfinder"]}

    def run_tool(_oid, _key, _params, output_dir, _service, *_args):
        output_dir.mkdir(parents=True)
        (output_dir / "subfinder_results.txt").write_text("one.example.com\n")
        return [result], "container"

    with patch.object(manager, "_parse_output") as parse, patch.object(manager, "_run_tool_sync", side_effect=run_tool) as run:
        manager._run_composite("resumed", "test", stages, params, tmp_path, Mock(), resume=True)

    assert manager.get("resumed").status == "completed"
    assert manager.get("resumed").progress_completed == 1
    parse.assert_not_called()
    run.assert_called_once()


def test_resume_cleans_up_interrupted_container():
    container = Mock(id="container-1", status="running", labels={"awe.operation_id": "operation-1"})
    client = Mock()
    client.containers.list.return_value = [container]
    client.containers.get.return_value = container
    service = Mock()
    service._client.return_value = client
    manager = DockerOperationManager()
    manager._items["operation-1"] = DockerOperation(
        id="operation-1", kind="tool.amass", status="failed",
        result={"active_container_id": "container-1"},
    )

    manager.cleanup_interrupted_container("operation-1", service)

    client.containers.list.assert_called_once_with(all=True, filters={"label": "awe.operation_id=operation-1"})
    container.stop.assert_called_once_with(timeout=5)
    container.remove.assert_called_once_with(force=True)


def test_tool_run_mounts_all_selected_graph_outputs_as_input_list(tmp_path):
    manager = DockerOperationManager()
    manager._items["operation"] = DockerOperation(id="operation", kind="tool.httpx", status="queued")
    captured = {}

    def run_tool(_oid, key, params, output_dir, _service, input_dir, *_args):
        captured.update({"key": key, "params": params, "input_dir": input_dir})
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "httpx_results.txt").write_text("https://one.example.com\n", encoding="utf-8")
        return [{"url": "https://one.example.com"}], "container"

    with patch.object(manager, "_run_tool_sync", side_effect=run_tool):
        manager._run_tool(
            "operation", "httpx", {"target": "example.com"}, tmp_path, Mock(),
            seed_values=["one.example.com", "two.example.com", "one.example.com"],
        )

    assert manager.get("operation").status == "completed"
    assert captured["key"] == "httpx"
    assert captured["params"]["input_file"] == "/input/input.txt"
    assert captured["input_dir"] == tmp_path / "_seed_inputs"
    assert (captured["input_dir"] / "input.txt").read_text(encoding="utf-8") == "one.example.com\ntwo.example.com\n"
    assert manager._has_completed_output(tmp_path)


def test_seed_input_file_is_not_treated_as_completed_tool_output(tmp_path):
    input_dir = DockerOperationManager._seed_input_dir(tmp_path, ["one.example.com"])

    assert input_dir == tmp_path / "_seed_inputs"
    assert not DockerOperationManager._has_completed_output(tmp_path)
