"""AI tool wrappers over AweRepository — scan sessions, findings, scope, auth sessions.

Each ``_make_*`` factory closes over the project's AiToolContext and returns a plain
function with the exact signature/docstring forgeai derives the tool schema from — no
``ctx`` parameter leaks into what the model sees.
"""
from __future__ import annotations

import json

from forgeai import ToolRegistry

from ai.context import AiToolContext
from database.scope import ScopeConfig


def _make_list_sessions(ctx: AiToolContext):
    def list_sessions(limit: int = 50) -> str:
        """List this project's recent scan sessions, most recent first.

        Args:
            limit: Maximum number of sessions to return.
        """
        return json.dumps(ctx.repo.list_sessions(limit=limit), default=str)

    return list_sessions


def _make_get_session_summary(ctx: AiToolContext):
    def get_session_summary(session_id: str) -> str:
        """Get a session's details plus a per-category result-count breakdown.

        Args:
            session_id: The scan session's id, from list_sessions.
        """
        session = ctx.repo.get_session(session_id)
        if session is None:
            return f"Error: no session found with id '{session_id}'"
        summary = ctx.repo.session_summary(session_id)
        return json.dumps({"session": session, "result_counts": summary}, default=str)

    return get_session_summary


def _make_get_results(ctx: AiToolContext):
    def get_results(session_id: str, category: str = "", limit: int = 50) -> str:
        """Get findings/results recorded for a scan session, optionally filtered by category.

        Args:
            session_id: The scan session's id, from list_sessions.
            category: Optional result category filter (e.g. subdomain, http, crawl, params, vuln, osint, screenshot, portscan, dns).
            limit: Maximum number of results to return (0 = unlimited).
        """
        results = ctx.repo.get_results(session_id, category=category or None, limit=limit)
        return json.dumps(results, default=str)

    return get_results


def _make_get_combined_values(ctx: AiToolContext):
    def get_combined_values(session_id: str, category: str) -> str:
        """Get the deduplicated primary value list for a category in one session
        (e.g. the list of discovered subdomains, or crawled URLs).

        Args:
            session_id: The scan session's id, from list_sessions.
            category: Result category, e.g. subdomain, http, crawl, params.
        """
        return json.dumps(ctx.repo.get_combined_values(session_id, category))

    return get_combined_values


def _make_count_results(ctx: AiToolContext):
    def count_results(session_id: str = "", category: str = "") -> str:
        """Count results, either for one session or project-wide across all sessions.

        Args:
            session_id: Session id to count within. Leave blank to count across the whole project.
            category: Optional result category filter.
        """
        if session_id:
            n = ctx.repo.count_results(session_id, category or None)
        else:
            if not category:
                return "Error: category is required when session_id is not given"
            n = ctx.repo.count_results_project(category)
        return str(n)

    return count_results


def _make_get_tool_run_logs(ctx: AiToolContext):
    def get_tool_run_logs(session_id: str) -> str:
        """Get the raw captured stdout log lines for every tool run in a session.

        Args:
            session_id: The scan session's id, from list_sessions.
        """
        return json.dumps(ctx.repo.get_tool_run_logs(session_id))

    return get_tool_run_logs


def _make_get_failed_tool_keys(ctx: AiToolContext):
    def get_failed_tool_keys(session_id: str) -> str:
        """List the tool keys that failed during a scan session.

        Args:
            session_id: The scan session's id, from list_sessions.
        """
        return json.dumps(ctx.repo.get_failed_tool_keys(session_id))

    return get_failed_tool_keys


def _make_get_scope(ctx: AiToolContext):
    def get_scope() -> str:
        """Get the project's current in-scope/out-of-scope configuration."""
        return json.dumps(ctx.repo.get_scope().to_dict())

    return get_scope


def _make_save_scope(ctx: AiToolContext):
    def save_scope(in_scope: str, out_of_scope: str, include_subdomains: bool = True) -> str:
        """Replace the project's scope configuration with plain domain entries.

        Args:
            in_scope: Comma-separated list of in-scope domains (e.g. "example.com,api.example.com").
            out_of_scope: Comma-separated list of explicitly excluded domains.
            include_subdomains: Whether in-scope domain entries also cover their subdomains.
        """
        from database.scope import ScopeEntry

        entries = [ScopeEntry(value=v.strip(), entry_type="domain", in_scope=True)
                   for v in in_scope.split(",") if v.strip()]
        entries += [ScopeEntry(value=v.strip(), entry_type="domain", in_scope=False)
                    for v in out_of_scope.split(",") if v.strip()]
        config = ScopeConfig(entries=entries, include_subdomains=include_subdomains)
        ctx.repo.save_scope(config)
        return f"Scope saved: {len(entries)} entries"

    return save_scope


def _make_list_auth_sessions(ctx: AiToolContext):
    def list_auth_sessions() -> str:
        """List saved authenticated-session profiles (reusable headers/params for scans)."""
        return json.dumps(ctx.repo.list_auth_sessions(), default=str)

    return list_auth_sessions


def _make_create_auth_session(ctx: AiToolContext):
    def create_auth_session(name: str, headers_json: str, params_json: str = "[]") -> str:
        """Save a new authenticated-session profile for reuse across scans.

        Args:
            name: A short label for this auth session (e.g. "logged-in-user").
            headers_json: JSON array of {"name": ..., "value": ...} header objects.
            params_json: JSON array of {"name": ..., "value": ...} query-param objects.
        """
        try:
            headers = json.loads(headers_json)
            params = json.loads(params_json)
        except json.JSONDecodeError as exc:
            return f"Error: invalid JSON — {exc}"
        session_id = ctx.repo.create_auth_session(name, headers, params)
        return f"Created auth session '{name}' (id={session_id})"

    return create_auth_session


def register_all(registry: ToolRegistry, ctx: AiToolContext) -> None:
    registry.register(_make_list_sessions(ctx))
    registry.register(_make_get_session_summary(ctx))
    registry.register(_make_get_results(ctx))
    registry.register(_make_get_combined_values(ctx))
    registry.register(_make_count_results(ctx))
    registry.register(_make_get_tool_run_logs(ctx))
    registry.register(_make_get_failed_tool_keys(ctx))
    registry.register(_make_get_scope(ctx))
    registry.register(_make_save_scope(ctx), requires_permission=True)
    registry.register(_make_list_auth_sessions(ctx))
    registry.register(_make_create_auth_session(ctx), requires_permission=True)
