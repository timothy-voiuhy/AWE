import json

from forgeai import ToolRegistry

from ai.tools import container_tools


def _registry(ctx):
    reg = ToolRegistry()
    container_tools.register_all(reg, ctx)
    return reg


def test_permission_gating(ctx):
    reg = _registry(ctx)
    assert reg.get("list_container_tools").requires_permission is False
    assert reg.get("list_awe_containers").requires_permission is False
    assert reg.get("run_container_tool").requires_permission is True
    assert reg.get("stop_running_tool").requires_permission is True


async def test_list_container_tools_returns_known_tool(ctx):
    reg = _registry(ctx)
    result = await reg.execute("list_container_tools", {"category": ""})
    assert result.success
    tools = json.loads(result.content)
    keys = {t["key"] for t in tools}
    assert "subfinder" in keys or "amass" in keys  # at least one known recon tool present


async def test_run_container_tool_rejects_unknown_key(ctx):
    reg = _registry(ctx)
    result = await reg.execute("run_container_tool", {"tool_key": "not_a_real_tool", "params_json": "{}"})
    assert not result.success
    assert "unknown tool_key" in result.content


async def test_run_container_tool_rejects_bad_json(ctx):
    reg = _registry(ctx)
    result = await reg.execute("run_container_tool", {"tool_key": "subfinder", "params_json": "{not json"})
    assert not result.success
    assert "invalid params_json" in result.content
