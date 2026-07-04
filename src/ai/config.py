"""Bridges AWE's per-project SettingsRepository to a forgeai AgentConfig.

Provider/model are never forced — an unset value falls back only to a UI-level
suggestion (see _DEFAULT_MODEL_FOR), never to a value silently persisted on the
user's behalf.
"""
from __future__ import annotations

from pathlib import Path

from forgeai import AgentConfig
from forgeai.multiagent import MultiAgentConfig

from database.settings_repository import Keys, SettingsRepository

_DEFAULT_MODEL_FOR = {
    "anthropic": "claude-sonnet-5",
    "openai": "gpt-4o-mini",
    "ollama": "llama3.1",
}

_PROMPT_PATH = Path(__file__).parent / "prompts" / "awe_system_prompt.md"

_DEFAULT_SUPERVISOR_PROMPT = (
    "You are the supervisor of an AWE pentest team. Break the user's request into a "
    "set of independent recon/testing tasks that worker agents can run in parallel "
    "using AWE's tools (findings/DB, pipelines, dockerized recon/vuln tools, proxy "
    "traffic, JWT, GraphQL, testing methodology). Keep tasks self-contained — a worker "
    "only sees its own task description and context, not the other tasks."
)
_DEFAULT_WORKER_PROMPT = (
    "You are a pentest worker agent with access to AWE's recon/vuln/proxy/JWT/GraphQL/"
    "methodology tools. Complete your assigned task thoroughly, using tools as needed, "
    "and report concrete findings — cite what a tool actually returned, don't invent "
    "results."
)
_DEFAULT_REVIEWER_PROMPT = (
    "You are a read-only pentest reviewer. Cross-check the worker results against the "
    "original request and AWE's testing methodology; flag missed coverage, unsupported "
    "claims, or findings that need follow-up. Never suggest modifying state yourself."
)


def load_agent_config(settings: SettingsRepository) -> AgentConfig:
    provider = settings.get(Keys.LLM_PROVIDER, default="anthropic") or "anthropic"
    model = settings.get(Keys.LLM_MODEL, default="") or _DEFAULT_MODEL_FOR.get(provider, "gpt-4o-mini")
    api_key = settings.get(Keys.LLM_API_KEY, default="") or None
    base_url = settings.get(Keys.LLM_BASE_URL, default="") or None

    return AgentConfig(
        provider=provider,
        model=model,
        api_key=api_key,
        base_url=base_url,
        system_prompt=_PROMPT_PATH,
        skills_dir=None,  # skills are registered programmatically, see ai.skills.methodology_skill
    )


def load_multi_agent_config(settings: SettingsRepository) -> MultiAgentConfig:
    base = load_agent_config(settings)
    max_workers_raw = settings.get(Keys.LLM_MAX_WORKERS, default="3") or "3"
    try:
        max_workers = int(max_workers_raw)
    except (TypeError, ValueError):
        max_workers = 3

    return MultiAgentConfig.from_agent_config(
        base,
        max_workers=max_workers,
        supervisor_prompt=settings.get(Keys.LLM_SUPERVISOR_PROMPT, default="") or _DEFAULT_SUPERVISOR_PROMPT,
        worker_prompt=settings.get(Keys.LLM_WORKER_PROMPT, default="") or _DEFAULT_WORKER_PROMPT,
        reviewer_prompt=settings.get(Keys.LLM_REVIEWER_PROMPT, default="") or _DEFAULT_REVIEWER_PROMPT,
    )
