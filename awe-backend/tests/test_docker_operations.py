from unittest.mock import Mock

import pytest

from awe_backend.docker_operations import DockerOperationManager
from awe_backend.schemas import DockerOperation


def test_subfinder_command_runs_under_shell_instead_of_image_entrypoint(tmp_path):
    container = Mock()
    container.logs.return_value = iter(())
    container.attrs = {"State": {"ExitCode": 0}}
    container.short_id = "subfinder-container"

    client = Mock()
    client.images.list.return_value = [object()]
    client.containers.run.return_value = container
    service = Mock()
    service._client.return_value = client

    manager = DockerOperationManager()
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
    client = Mock()
    client.images.list.return_value = [object()]
    client.containers.run.return_value = container
    service = Mock()
    service._client.return_value = client
    manager = DockerOperationManager()
    manager._log = Mock()

    with pytest.raises(RuntimeError, match="exited with code 1"):
        manager._run_tool_sync("operation", "subfinder", {"domain": "example.com"}, tmp_path, service)

    container.remove.assert_called_once_with(force=True)
