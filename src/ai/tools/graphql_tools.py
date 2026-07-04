"""AI tool wrappers over GraphQL querying/introspection.

Requests are routed through AWE's own proxy (http://127.0.0.1:<proxy_port>), exactly
like GraphqlPage's _GraphqlWorker, so AI-issued requests show up in HTTP History too.
Query-builder helpers are reused from gui.graphql_page rather than reimplemented.
"""
from __future__ import annotations

import json

import httpx
from forgeai import ToolRegistry

from ai.context import AiToolContext
from gui.graphql_page import _deep_query, _full_introspection_query, _wide_query


def _post_graphql(ctx: AiToolContext, endpoint: str, query: str, variables: dict | None = None) -> str:
    proxy = f"http://127.0.0.1:{ctx.proxy_port}"
    payload: dict = {"query": query}
    if variables:
        payload["variables"] = variables
    try:
        with httpx.Client(proxy=proxy, verify=False, follow_redirects=True, timeout=30.0) as client:
            resp = client.post(
                endpoint,
                headers={"Content-Type": "application/json"},
                content=json.dumps(payload).encode(),
            )
    except Exception as exc:
        return f"Error: request failed — {exc}"
    try:
        return json.dumps(resp.json(), indent=2)
    except Exception:
        return resp.text


def _make_graphql_query(ctx: AiToolContext):
    def graphql_query(endpoint: str, query: str, variables_json: str = "") -> str:
        """Send a GraphQL query/mutation to an endpoint through AWE's proxy (so it's
        also captured in HTTP History).

        Args:
            endpoint: The GraphQL endpoint URL.
            query: The GraphQL query or mutation document.
            variables_json: Optional JSON object of GraphQL variables.
        """
        variables = None
        if variables_json.strip():
            try:
                variables = json.loads(variables_json)
            except json.JSONDecodeError as exc:
                return f"Error: invalid variables_json — {exc}"
        return _post_graphql(ctx, endpoint, query, variables)

    return graphql_query


def _make_graphql_introspect(ctx: AiToolContext):
    def graphql_introspect(endpoint: str) -> str:
        """Run a full GraphQL introspection query against an endpoint to map its schema.

        Args:
            endpoint: The GraphQL endpoint URL.
        """
        return _post_graphql(ctx, endpoint, _full_introspection_query())

    return graphql_introspect


def _make_graphql_field_fuzz(ctx: AiToolContext):
    def graphql_field_fuzz(endpoint: str, root_field: str) -> str:
        """Probe a GraphQL root field with a deep nested query and a wide-alias query,
        useful for spotting missing depth/complexity limits (DoS surface).

        Args:
            endpoint: The GraphQL endpoint URL.
            root_field: The root query field to probe, e.g. "user" or "posts".
        """
        deep_result = _post_graphql(ctx, endpoint, _deep_query(root_field, depth=15))
        wide_result = _post_graphql(ctx, endpoint, _wide_query(root_field, n=200))
        return json.dumps({"deep_query_result": deep_result, "wide_query_result": wide_result})

    return graphql_field_fuzz


def register_all(registry: ToolRegistry, ctx: AiToolContext) -> None:
    registry.register(_make_graphql_query(ctx), requires_permission=True)
    registry.register(_make_graphql_introspect(ctx), requires_permission=True)
    registry.register(_make_graphql_field_fuzz(ctx), requires_permission=True)
