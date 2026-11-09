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
    manager = DockerOperationManager()
    manager._items["operation"] = DockerOperation(id="operation", kind="tool.amass", status="running")

    with patch("awe_backend.docker_operations.os.chown") as chown:
        manager._run_tool_sync("operation", "amass", {"domain": "example.com"}, tmp_path, service)

    chown.assert_called_once_with(tmp_path, 1000, 1000)


def test_composite_resume_skips_checkpointed_tool_and_keeps_progress(tmp_path):
    manager = DockerOperationManager()
    manager._items["first"] = DockerOperation(id="first", kind="composite.test", status="queued", progress_total=2)
    stages = [{"name": "Enumerate", "tool_keys": ["subfinder", "amass"], "input_source": "seed"}]
    first_result = {"domain": "one.example.com", "sources": ["subfinder"]}
    second_result = {"domain": "two.example.com", "sources": ["amass"]}
    service = Mock()

    with patch.object(manager, "_run_tool_sync", side_effect=[([first_result], "first-container"), RuntimeError("interrupted")]):
        manager._run_composite("first", "test", stages, {"domain": "example.com"}, tmp_path, service)
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
