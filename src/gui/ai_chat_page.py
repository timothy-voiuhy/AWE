"""AI Chat page — a themed forgeai Agent (or MultiAgentRuntime) wired into AWE's
per-project tools/skills, chosen by the Keys.LLM_MULTI_AGENT setting."""
from __future__ import annotations

import asyncio
import logging

from PySide6.QtWidgets import QVBoxLayout, QWidget
from forgeai import Agent, ToolRegistry
from forgeai.multiagent import MultiAgentRuntime
from forgeai.ui import ChatWidget
from forgeai.ui.widgets.multiagent_widget import MultiAgentChatWidget

from ai.config import load_agent_config, load_multi_agent_config
from ai.context import AiToolContext
from ai.skills.methodology_skill import build_methodology_skill_classes
from ai.theme import awe_forgeai_qss
from ai.tools import register_all_tools
from database.settings_repository import Keys, SettingsRepository

log = logging.getLogger(__name__)


class AiChatPage(QWidget):
    def __init__(
        self,
        project_dir: str,
        repo,
        target: str,
        proxy_col,
        proxy_port: int,
        mongo_uri: str = "mongodb://localhost:27017",
        parent=None,
    ):
        super().__init__(parent)
        self.setObjectName("AiChatPage")

        settings = SettingsRepository(project_dir, mongo_uri)
        ctx = AiToolContext(
            project_dir=project_dir,
            repo=repo,
            target=target,
            proxy_col=proxy_col,
            proxy_port=proxy_port,
            mongo_uri=mongo_uri,
        )

        self.agent = None
        self.runtime = None

        multi_agent_enabled = (settings.get(Keys.LLM_MULTI_AGENT, default="false") or "false") == "true"
        if multi_agent_enabled:
            self.chat_widget = self._build_multi_agent_widget(settings, ctx)
        else:
            self.chat_widget = self._build_single_agent_widget(settings, ctx)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.chat_widget)

        self.setStyleSheet(awe_forgeai_qss())

    def _build_single_agent_widget(self, settings: SettingsRepository, ctx: AiToolContext) -> QWidget:
        config = load_agent_config(settings)
        self.agent = Agent(config)

        register_all_tools(self.agent.tools, ctx)
        for skill_cls in build_methodology_skill_classes():
            self.agent.skills.register_skill(skill_cls)
        self._register_skill_activation_tool()

        try:
            asyncio.ensure_future(self.agent.start())
        except RuntimeError:
            log.exception("No running asyncio loop — was install_qasync() called before this page was built?")

        return ChatWidget(self.agent, self)

    def _build_multi_agent_widget(self, settings: SettingsRepository, ctx: AiToolContext) -> QWidget:
        # Fresh ToolRegistry (not the single-agent path's) — the methodology
        # skill-activation tool is intentionally not registered here: step-gated
        # skills are a single-conversation concept and don't map cleanly onto a
        # supervisor/worker/reviewer trio. Plain methodology tools (get_vuln_description,
        # set_methodology_status, ...) remain available to every worker.
        registry = ToolRegistry()
        register_all_tools(registry, ctx)

        multi_config = load_multi_agent_config(settings)
        self.runtime = MultiAgentRuntime(multi_config, registry)
        return MultiAgentChatWidget(self.runtime, self)

    def _register_skill_activation_tool(self) -> None:
        """SkillManager.activate_skill() must be called explicitly — nothing does
        this automatically, so the agent needs a tool to trigger it itself when it
        judges a multi-step methodology workflow is the right approach."""
        agent = self.agent

        def activate_methodology_skill(category_id: str, user_request: str) -> str:
            """Activate a step-gated testing-methodology workflow for one vulnerability
            category, scoping tool access to that workflow's steps until it completes.

            Args:
                category_id: Methodology category id from list_methodology_categories (e.g. "authentication").
                user_request: What the user wants to test — used to plan the workflow's steps.
            """
            skill_id = f"methodology_{category_id}"
            try:
                agent.skills.activate_skill(agent.conversation_id, skill_id, user_request)
            except KeyError:
                return f"Error: unknown methodology category '{category_id}'"
            return f"Activated '{skill_id}'. Tool access is now scoped to this workflow's steps."

        self.agent.tools.register(activate_methodology_skill)

    def receive_context(self, payload: dict) -> None:
        """Slot for the "Send to AI" hooks — primes the chat input without auto-sending."""
        kind = payload.get("kind", "context")
        source = payload.get("source_page", "")
        text = payload.get("text", "")
        prefix = f"[{kind} from {source}]\n" if source else f"[{kind}]\n"
        self.chat_widget.input_box.setPlainText(prefix + text)

    def stop_agent(self) -> None:
        target = self.runtime if self.runtime is not None else self.agent
        if target is None:
            return
        try:
            asyncio.ensure_future(target.stop())
        except RuntimeError:
            pass
