"""Aggregates every AWE tool module's register_all(registry, ctx) into one call."""
from __future__ import annotations

from forgeai import ToolRegistry

from ai.context import AiToolContext
from ai.tools import (
    container_tools,
    db_tools,
    graphql_tools,
    jwt_tools,
    methodology_tools,
    pipeline_tools,
    proxy_tools,
)


def register_all_tools(registry: ToolRegistry, ctx: AiToolContext) -> None:
    db_tools.register_all(registry, ctx)
    methodology_tools.register_all(registry, ctx)
    pipeline_tools.register_all(registry, ctx)
    container_tools.register_all(registry, ctx)
    proxy_tools.register_all(registry, ctx)
    jwt_tools.register_all(registry, ctx)
    graphql_tools.register_all(registry, ctx)
