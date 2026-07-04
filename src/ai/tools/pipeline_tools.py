"""AI tool wrappers over PIPELINE_REGISTRY / PipelineExecutor.

Pipelines are executed by calling PipelineExecutor.run() directly (not .start()) —
we're already off the Qt main thread inside a sync tool call (forgeai's ToolRegistry
runs sync tool functions via asyncio.to_thread), so there's no need to spin up a
second QThread. Qt signals still deliver synchronously to plain-function slots
without requiring an event loop, so we can collect step outcomes into a summary.
"""
from __future__ import annotations

import json

from forgeai import ToolRegistry

from ai.context import AiToolContext
from pipeline.definitions import PIPELINE_REGISTRY
from pipeline.executor import PipelineExecutor
from pipeline.models import PipelineStep, PipelineTemplate


def _execute_template(ctx: AiToolContext, template: PipelineTemplate, params: dict | None = None) -> str:
    executor = PipelineExecutor(
        template=template,
        project_dir=ctx.project_dir,
        target=ctx.target,
        params=params or {},
        mongo_uri=ctx.mongo_uri,
    )

    step_results: list[str] = []
    outcome: dict = {}

    executor.step_done.connect(lambda tool_key, status, count: step_results.append(f"{tool_key}: {status} ({count} results)"))
    executor.pipeline_done.connect(lambda session_id, success, msg: outcome.update(session_id=session_id, success=success, message=msg))

    executor.run()

    return json.dumps({
        "session_id": outcome.get("session_id", ""),
        "success": outcome.get("success", False),
        "summary": outcome.get("message", ""),
        "steps": step_results,
    })


def _make_list_pipelines(ctx: AiToolContext):
    def list_pipelines() -> str:
        """List every built-in pipeline template (key, name, category, tool sequence)."""
        return json.dumps([
            {
                "key": t.key,
                "name": t.name,
                "description": t.description,
                "category": t.category,
                "tool_keys": [s.tool_key for s in t.steps],
            }
            for t in PIPELINE_REGISTRY.values()
        ])

    return list_pipelines


def _make_run_pipeline(ctx: AiToolContext):
    def run_pipeline(pipeline_key: str, params_json: str = "{}") -> str:
        """Run a built-in pipeline against the project's target and wait for it to finish.
        This launches real Docker containers and writes results to the project's database.

        Args:
            pipeline_key: A key from list_pipelines (e.g. "quick_recon", "xss_scan").
            params_json: Optional JSON object of extra params merged into every step (e.g. {"threads": "20"}).
        """
        template = PIPELINE_REGISTRY.get(pipeline_key)
        if template is None:
            return f"Error: unknown pipeline_key '{pipeline_key}'"
        try:
            params = json.loads(params_json) if params_json else {}
        except json.JSONDecodeError as exc:
            return f"Error: invalid params_json — {exc}"
        return _execute_template(ctx, template, params)

    return run_pipeline


def _make_list_custom_pipelines(ctx: AiToolContext):
    def list_custom_pipelines() -> str:
        """List custom pipelines saved by the user for this project."""
        return json.dumps(ctx.repo.list_custom_pipelines(), default=str)

    return list_custom_pipelines


def _make_save_custom_pipeline(ctx: AiToolContext):
    def save_custom_pipeline(key: str, name: str, description: str, steps_json: str) -> str:
        """Save a custom multi-tool pipeline for later reuse.

        Args:
            key: A short unique key for this pipeline (e.g. "my_api_recon").
            name: Human-readable pipeline name.
            description: What this pipeline does.
            steps_json: JSON array of {"tool_key": ..., "stage": 0, "condition": "always", "input_category": null} objects.
        """
        try:
            steps = json.loads(steps_json)
        except json.JSONDecodeError as exc:
            return f"Error: invalid steps_json — {exc}"
        ctx.repo.save_custom_pipeline({
            "key": key,
            "name": name,
            "description": description,
            "steps": steps,
            "category": "custom",
        })
        return f"Saved custom pipeline '{key}' with {len(steps)} steps"

    return save_custom_pipeline


def register_all(registry: ToolRegistry, ctx: AiToolContext) -> None:
    registry.register(_make_list_pipelines(ctx))
    registry.register(_make_run_pipeline(ctx), requires_permission=True)
    registry.register(_make_list_custom_pipelines(ctx))
    registry.register(_make_save_custom_pipeline(ctx), requires_permission=True)
