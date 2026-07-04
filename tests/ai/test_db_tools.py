import json

from forgeai import ToolRegistry

from ai.tools import db_tools


def _registry(ctx):
    reg = ToolRegistry()
    db_tools.register_all(reg, ctx)
    return reg


def test_read_only_tools_not_permission_gated(ctx):
    reg = _registry(ctx)
    for name in (
        "list_sessions", "get_session_summary", "get_results", "get_combined_values",
        "count_results", "get_tool_run_logs", "get_failed_tool_keys", "get_scope",
        "list_auth_sessions",
    ):
        spec = reg.get(name)
        assert spec is not None, f"tool '{name}' not registered"
        assert spec.requires_permission is False


def test_write_tools_are_permission_gated(ctx):
    reg = _registry(ctx)
    for name in ("save_scope", "create_auth_session"):
        spec = reg.get(name)
        assert spec is not None
        assert spec.requires_permission is True


async def test_list_sessions_returns_repo_data(ctx):
    reg = _registry(ctx)
    result = await reg.execute("list_sessions", {"limit": 10})
    assert result.success
    data = json.loads(result.content)
    assert data == [{"id": "sess-1", "target": "example.com", "status": "completed"}]
    ctx.repo.list_sessions.assert_called_once_with(limit=10)


async def test_get_results_passes_through_category_filter(ctx):
    reg = _registry(ctx)
    result = await reg.execute("get_results", {"session_id": "sess-1", "category": "http", "limit": 5})
    assert result.success
    ctx.repo.get_results.assert_called_once_with("sess-1", category="http", limit=5)


async def test_count_results_requires_category_when_no_session(ctx):
    reg = _registry(ctx)
    result = await reg.execute("count_results", {"session_id": "", "category": ""})
    assert not result.success
    assert "category is required" in result.content
