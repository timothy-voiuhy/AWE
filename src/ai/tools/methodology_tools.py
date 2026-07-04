"""AI tool wrappers over the Testing Methodology registry/state.

Reuses gui.testing_methodology's registry loader and description reader instead of
re-parsing resources/methodology/registry.json independently.
"""
from __future__ import annotations

import json

from forgeai import ToolRegistry

from ai.context import AiToolContext
from gui.testing_methodology import STATUS_ORDER, _load_registry, _read_description


def _make_list_methodology_categories(ctx: AiToolContext):
    def list_methodology_categories() -> str:
        """List every testing-methodology category and how many vulnerabilities each contains."""
        categories = _load_registry()
        return json.dumps([
            {
                "id": cat["id"],
                "name": cat["name"],
                "vulnerability_count": len(cat.get("vulnerabilities", [])),
                "vulnerability_ids": [v["id"] for v in cat.get("vulnerabilities", [])],
            }
            for cat in categories
        ])

    return list_methodology_categories


def _make_get_vuln_description(ctx: AiToolContext):
    def get_vuln_description(vuln_id: str) -> str:
        """Get the full testing-methodology write-up for one vulnerability (overview,
        how it works, where to look, testing steps, payloads, tools, remediation).

        Args:
            vuln_id: The vulnerability id, e.g. "auth_jwt_algnone" (see list_methodology_categories).
        """
        for cat in _load_registry():
            for vuln in cat.get("vulnerabilities", []):
                if vuln["id"] == vuln_id:
                    return _read_description(vuln["description_file"])
        return f"Error: unknown vuln_id '{vuln_id}'"

    return get_vuln_description


def _make_get_methodology_status(ctx: AiToolContext):
    def get_methodology_status(vuln_id: str = "") -> str:
        """Get testing status/notes for one vulnerability, or a status-count summary
        across the whole project if vuln_id is omitted.

        Args:
            vuln_id: Optional vulnerability id to look up a single status/notes pair.
        """
        if vuln_id:
            states = ctx.repo.load_methodology_states()
            state = states.get(vuln_id, {"status": "not_tested", "notes": ""})
            return json.dumps({vuln_id: state})
        return json.dumps(ctx.repo.get_methodology_summary())

    return get_methodology_status


def _make_set_methodology_status(ctx: AiToolContext):
    def set_methodology_status(vuln_id: str, status: str, notes: str = "") -> str:
        """Record the testing status/notes for one vulnerability in the Testing Flow tab.

        Args:
            vuln_id: The vulnerability id, e.g. "auth_jwt_algnone".
            status: One of not_tested, in_progress, tested_clean, vulnerable, na.
            notes: Free-text findings/notes to attach.
        """
        if status not in STATUS_ORDER:
            return f"Error: status must be one of {STATUS_ORDER}"
        states = ctx.repo.load_methodology_states()
        states[vuln_id] = {"status": status, "notes": notes}
        ctx.repo.save_methodology_state(states)
        return f"Updated '{vuln_id}' -> {status}"

    return set_methodology_status


def register_all(registry: ToolRegistry, ctx: AiToolContext) -> None:
    registry.register(_make_list_methodology_categories(ctx))
    registry.register(_make_get_vuln_description(ctx))
    registry.register(_make_get_methodology_status(ctx))
    registry.register(_make_set_methodology_status(ctx), requires_permission=True)
