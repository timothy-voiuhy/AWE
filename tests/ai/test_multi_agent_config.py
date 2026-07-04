from database.settings_repository import Keys
from ai.config import (
    _DEFAULT_REVIEWER_PROMPT,
    _DEFAULT_SUPERVISOR_PROMPT,
    _DEFAULT_WORKER_PROMPT,
    load_multi_agent_config,
)


class FakeSettings:
    def __init__(self, values: dict | None = None):
        self._values = values or {}

    def get(self, key, default=None):
        return self._values.get(key, default)


def test_load_multi_agent_config_uses_pentest_defaults_when_unset():
    settings = FakeSettings({Keys.LLM_PROVIDER: "anthropic", Keys.LLM_MODEL: "claude-sonnet-5"})
    config = load_multi_agent_config(settings)

    assert config.max_workers == 3
    assert config.supervisor.system_prompt == _DEFAULT_SUPERVISOR_PROMPT
    assert config.worker.system_prompt == _DEFAULT_WORKER_PROMPT
    assert config.reviewer.system_prompt == _DEFAULT_REVIEWER_PROMPT
    assert config.supervisor.provider == "anthropic"
    assert config.worker.model == "claude-sonnet-5"


def test_load_multi_agent_config_respects_max_workers_override():
    settings = FakeSettings({Keys.LLM_PROVIDER: "openai", Keys.LLM_MAX_WORKERS: "7"})
    config = load_multi_agent_config(settings)
    assert config.max_workers == 7


def test_load_multi_agent_config_respects_prompt_overrides():
    settings = FakeSettings(
        {
            Keys.LLM_PROVIDER: "anthropic",
            Keys.LLM_SUPERVISOR_PROMPT: "custom supervisor",
            Keys.LLM_WORKER_PROMPT: "custom worker",
            Keys.LLM_REVIEWER_PROMPT: "custom reviewer",
        }
    )
    config = load_multi_agent_config(settings)
    assert config.supervisor.system_prompt == "custom supervisor"
    assert config.worker.system_prompt == "custom worker"
    assert config.reviewer.system_prompt == "custom reviewer"


def test_load_multi_agent_config_falls_back_on_invalid_max_workers():
    settings = FakeSettings({Keys.LLM_PROVIDER: "anthropic", Keys.LLM_MAX_WORKERS: "not_a_number"})
    config = load_multi_agent_config(settings)
    assert config.max_workers == 3
