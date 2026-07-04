import json

from forgeai import ToolRegistry

from ai.tools import methodology_tools


def _registry(ctx):
    reg = ToolRegistry()
    methodology_tools.register_all(reg, ctx)
    return reg


def test_permission_gating(ctx):
    reg = _registry(ctx)
    assert reg.get("set_methodology_status").requires_permission is True
    for name in ("list_methodology_categories", "get_vuln_description", "get_methodology_status"):
        assert reg.get(name).requires_permission is False


async def test_list_methodology_categories_matches_registry_json(ctx):
    reg = _registry(ctx)
    result = await reg.execute("list_methodology_categories", {})
    assert result.success
    categories = json.loads(result.content)
    ids = {c["id"] for c in categories}
    assert "authentication" in ids
    assert "authorization" in ids
    auth = next(c for c in categories if c["id"] == "authentication")
    assert "auth_jwt_algnone" in auth["vulnerability_ids"]


async def test_get_vuln_description_known_id(ctx):
    reg = _registry(ctx)
    result = await reg.execute("get_vuln_description", {"vuln_id": "auth_jwt_algnone"})
    assert result.success
    assert "JWT" in result.content


async def test_get_vuln_description_unknown_id(ctx):
    reg = _registry(ctx)
    result = await reg.execute("get_vuln_description", {"vuln_id": "not_a_real_id"})
    assert not result.success
    assert "unknown vuln_id" in result.content


async def test_set_methodology_status_rejects_bad_status(ctx):
    reg = _registry(ctx)
    result = await reg.execute(
        "set_methodology_status",
        {"vuln_id": "auth_jwt_algnone", "status": "bogus_status", "notes": ""},
    )
    assert not result.success


async def test_set_methodology_status_writes_full_state_map(ctx):
    ctx.repo.load_methodology_states.return_value = {"other_vuln": {"status": "vulnerable", "notes": "x"}}
    reg = _registry(ctx)
    result = await reg.execute(
        "set_methodology_status",
        {"vuln_id": "auth_jwt_algnone", "status": "tested_clean", "notes": "looks fine"},
    )
    assert result.success
    saved = ctx.repo.save_methodology_state.call_args[0][0]
    assert saved["auth_jwt_algnone"] == {"status": "tested_clean", "notes": "looks fine"}
    assert saved["other_vuln"] == {"status": "vulnerable", "notes": "x"}
