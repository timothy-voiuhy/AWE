"""Bridges AWE's per-project SettingsRepository to a forgeai AgentConfig.

Provider/model are never forced — an unset value falls back only to a UI-level
suggestion (see _DEFAULT_MODEL_FOR), never to a value silently persisted on the
user's behalf.
"""
from __future__ import annotations

from pathlib import Path

from forgeai import AgentConfig

from database.settings_repository import Keys, SettingsRepository

_DEFAULT_MODEL_FOR = {
    "anthropic": "claude-sonnet-5",
    "openai": "gpt-4o-mini",
    "ollama": "llama3.1",
}

_PROMPT_PATH = Path(__file__).parent / "prompts" / "awe_system_prompt.md"


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
