from unittest.mock import Mock

from awe_backend.docker_operations import DockerOperationManager


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
