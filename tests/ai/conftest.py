import json
from unittest.mock import MagicMock

import pytest

from ai.context import AiToolContext


@pytest.fixture
def fake_repo():
    """A MagicMock standing in for AweRepository — real DB integration is exercised
    manually (see the plan's verification section), not in this unit-level suite."""
    repo = MagicMock()
    repo.list_sessions.return_value = [{"id": "sess-1", "target": "example.com", "status": "completed"}]
    repo.get_session.return_value = {"id": "sess-1", "target": "example.com"}
    repo.session_summary.return_value = {"subdomain": 5, "http": 3}
    repo.get_results.return_value = [{"id": "r1", "category": "http", "data": {"url": "https://example.com"}}]
    repo.get_combined_values.return_value = ["https://example.com"]
    repo.count_results.return_value = 3
    repo.count_results_project.return_value = 10
    repo.get_tool_run_logs.return_value = {"subfinder": ["line1", "line2"]}
    repo.get_failed_tool_keys.return_value = []
    repo.list_auth_sessions.return_value = []
    repo.list_custom_pipelines.return_value = []
    repo.load_methodology_states.return_value = {}
    repo.get_methodology_summary.return_value = {"not_tested": 160}
    return repo


@pytest.fixture
def ctx(fake_repo):
    return AiToolContext(
        project_dir="/tmp/fake_project",
        repo=fake_repo,
        target="example.com",
        proxy_col=None,
        proxy_port=8080,
    )
