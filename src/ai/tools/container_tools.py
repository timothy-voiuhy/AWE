"""AI tool wrappers over TOOL_REGISTRY / DockerManager.

run_container_tool reuses PipelineExecutor's command-building/volume-mounting/
result-parsing/result-saving via an ad-hoc single-step PipelineTemplate, instead of
re-implementing container orchestration here.
"""
from __future__ import annotations

import json

from forgeai import ToolRegistry

from ai.context import AiToolContext
from ai.tools.pipeline_tools import _execute_template
from containers.docker_manager import manager as docker_manager
from containers.tool_registry import TOOL_REGISTRY
from pipeline.models import PipelineStep, PipelineTemplate


def _make_list_container_tools(ctx: AiToolContext):
    def list_container_tools(category: str = "") -> str:
        """List the dockerized recon/vuln tools AWE can run, optionally filtered by category.

        Args:
            category: Optional category filter, e.g. subdomain, dns, portscan, http, crawl, params, fuzz, vuln, osint.
        """
        items = [
            {
                "key": key,
                "display_name": tool.display_name,
                "category": tool.category,
                "description": tool.description,
                "params": tool.param_spec(),
            }
            for key, tool in TOOL_REGISTRY.items()
            if not category or tool.category == category
        ]
        return json.dumps(items)

    return list_container_tools


def _make_run_container_tool(ctx: AiToolContext):
    def run_container_tool(tool_key: str, params_json: str = "{}") -> str:
        """Run a single dockerized tool against the project's target and wait for it to
        finish. This launches a real Docker container and writes results to the database.

        Args:
            tool_key: A tool key from list_container_tools (e.g. "subfinder", "nuclei").
            params_json: Optional JSON object of extra params for this tool (see its param_spec).
        """
        if tool_key not in TOOL_REGISTRY:
            return f"Error: unknown tool_key '{tool_key}'"
        try:
            params = json.loads(params_json) if params_json else {}
        except json.JSONDecodeError as exc:
            return f"Error: invalid params_json — {exc}"

        template = PipelineTemplate(
            key=f"adhoc_{tool_key}",
            name=f"Ad-hoc: {TOOL_REGISTRY[tool_key].display_name}",
            description="Single-tool run triggered by the AI assistant",
            steps=[PipelineStep(tool_key=tool_key, stage=0)],
            category="custom",
        )
        return _execute_template(ctx, template, params)

    return run_container_tool


def _make_list_awe_containers(ctx: AiToolContext):
    def list_awe_containers() -> str:
        """List all Docker containers AWE has created (running or stopped)."""
        return json.dumps(docker_manager.list_awe_containers())

    return list_awe_containers


def _make_stop_running_tool(ctx: AiToolContext):
    def stop_running_tool(container_id: str) -> str:
        """Stop a running AWE tool container.

        Args:
            container_id: Container id or short id, from list_awe_containers.
        """
        docker_manager.stop_container(container_id)
        return f"Stopped container '{container_id}'"

    return stop_running_tool


def register_all(registry: ToolRegistry, ctx: AiToolContext) -> None:
    registry.register(_make_list_container_tools(ctx))
    registry.register(_make_run_container_tool(ctx), requires_permission=True)
    registry.register(_make_list_awe_containers(ctx))
    registry.register(_make_stop_running_tool(ctx), requires_permission=True)
