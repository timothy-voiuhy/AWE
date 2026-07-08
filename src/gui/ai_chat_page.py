"""AI Chat page — themed forgeai Agent(s) (or a MultiAgentRuntime) wired into
AWE's per-project tools/skills, chosen by the Keys.LLM_MULTI_AGENT setting.

Single-agent mode supports multiple concurrent chats as tabs, each with its
own Agent/conversation, a persisted history so closed chats can be reopened,
and a quick provider/model switcher. Multi-agent mode stays a single
supervisor/worker/reviewer session — tabs don't map cleanly onto that, so it
is rebuilt fresh whenever settings change instead.
"""
from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox, QHBoxLayout, QInputDialog, QLabel, QLineEdit, QMenu,
    QPushButton, QTabWidget, QToolButton, QVBoxLayout, QWidget,
)
from forgeai import Agent, FileConversationStore, ToolRegistry
from forgeai.llm.factory import list_providers
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

_COMBO = (
    "QComboBox{background:#11111B;color:#CDD6F4;border:1px solid #45475A;"
    "border-radius:4px;padding:0 6px;min-height:22px;font-size:9px;}"
    "QComboBox::drop-down{border:none;}"
    "QComboBox QAbstractItemView{background:#1E1E2E;color:#CDD6F4;"
    "selection-background-color:#313244;border:1px solid #45475A;}"
)
_LINE = (
    "QLineEdit{background:#11111B;color:#CDD6F4;border:1px solid #45475A;"
    "border-radius:4px;padding:0 6px;min-height:22px;font-size:9px;}"
    "QLineEdit:focus{border-color:#94E2D5;}"
)
_BTN = (
    "QPushButton,QToolButton{background:#313244;color:#CDD6F4;border:1px solid #45475A;"
    "border-radius:4px;padding:0 10px;min-height:22px;font-size:9px;}"
    "QPushButton:hover,QToolButton:hover{background:#45475A;}"
)
_TABS = (
    "QTabBar::tab{background:#181825;color:#6C7086;padding:4px 14px;"
    "border:none;font-size:9px;}"
    "QTabBar::tab:selected{background:#11111B;color:#CDD6F4;"
    "border-bottom:2px solid #94E2D5;}"
    "QTabWidget::pane{border:none;}"
)


class _QuickSwitchBar(QWidget):
    """Provider/model quick-switch toolbar shown above a single-agent ChatWidget."""

    def __init__(self, agent: Agent, chat_widget: ChatWidget, parent=None):
        super().__init__(parent)
        self._agent = agent
        self._chat_widget = chat_widget
        self.setStyleSheet("background:#181825;")

        lay = QHBoxLayout(self)
        lay.setContentsMargins(8, 4, 8, 4)
        lay.setSpacing(6)

        prov_lbl = QLabel("Provider:")
        prov_lbl.setStyleSheet("color:#6C7086;font-size:9px;background:transparent;")
        lay.addWidget(prov_lbl)

        self._provider_combo = QComboBox()
        self._provider_combo.addItems(list_providers())
        self._provider_combo.setStyleSheet(_COMBO)
        lay.addWidget(self._provider_combo)

        model_lbl = QLabel("Model:")
        model_lbl.setStyleSheet("color:#6C7086;font-size:9px;background:transparent;")
        lay.addWidget(model_lbl)

        self._model_edit = QLineEdit()
        self._model_edit.setStyleSheet(_LINE)
        lay.addWidget(self._model_edit, stretch=1)

        apply_btn = QPushButton("Apply")
        apply_btn.setStyleSheet(_BTN)
        apply_btn.clicked.connect(self._on_apply)
        lay.addWidget(apply_btn)

        self._status_lbl = QLabel("")
        self._status_lbl.setStyleSheet("color:#6C7086;font-size:9px;background:transparent;")
        lay.addWidget(self._status_lbl)

        self.sync_from_agent()

    def sync_from_agent(self) -> None:
        """Refresh the combo/edit after the agent's config changed elsewhere
        (a slash command, or a settings reload)."""
        idx = self._provider_combo.findText(self._agent.config.provider)
        if idx >= 0:
            self._provider_combo.setCurrentIndex(idx)
        self._model_edit.setText(self._agent.config.model)
        self._status_lbl.setText("")

    def _on_apply(self) -> None:
        provider = self._provider_combo.currentText().strip()
        model = self._model_edit.text().strip()
        kwargs = {}
        if provider and provider != self._agent.config.provider:
            kwargs["provider"] = provider
        if model and model != self._agent.config.model:
            kwargs["model"] = model
        if not kwargs:
            return
        self._status_lbl.setText("Switching…")
        try:
            asyncio.ensure_future(self._do_switch(kwargs))
        except RuntimeError:
            log.exception("No running asyncio loop for quick-switch")

    async def _do_switch(self, kwargs: dict) -> None:
        await self._chat_widget.switch_llm(**kwargs)
        self.sync_from_agent()


class _ChatSessionWidget(QWidget):
    """One open chat tab: an Agent, its ChatWidget, and the quick-switch bar."""

    def __init__(self, agent: Agent, parent=None):
        super().__init__(parent)
        self.agent = agent
        self.chat_widget = ChatWidget(agent, self)
        self.quick_switch = _QuickSwitchBar(agent, self.chat_widget, self)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)
        lay.addWidget(self.quick_switch)
        lay.addWidget(self.chat_widget, stretch=1)


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

        self._project_dir = project_dir
        self._mongo_uri = mongo_uri
        self._settings = SettingsRepository(project_dir, mongo_uri)
        self._ctx = AiToolContext(
            project_dir=project_dir,
            repo=repo,
            target=target,
            proxy_col=proxy_col,
            proxy_port=proxy_port,
            mongo_uri=mongo_uri,
        )

        self._store = FileConversationStore(Path(project_dir) / ".awe_ai_chats")
        self._chat_counter = 0

        self.agent = None       # last-created single-agent tab's Agent (legacy convenience)
        self.runtime = None     # active MultiAgentRuntime, when in multi-agent mode
        self.tabs: QTabWidget | None = None

        self._multi_agent_enabled = (
            self._settings.get(Keys.LLM_MULTI_AGENT, default="false") or "false"
        ) == "true"

        self._root = QVBoxLayout(self)
        self._root.setContentsMargins(0, 0, 0, 0)
        self._root.setSpacing(0)
        self._body: QWidget | None = None
        self._build_body()

        self.setStyleSheet(awe_forgeai_qss())

    # ── body construction (single-agent tabs vs multi-agent) ──────────────────

    def _build_body(self) -> None:
        if self._body is not None:
            self._teardown_body(self._body)
            self._root.removeWidget(self._body)
            self._body.deleteLater()
            self._body = None

        if self._multi_agent_enabled:
            self.tabs = None
            self._body = self._build_multi_agent_widget()
        else:
            self._body = self._build_tabs()
        self._root.addWidget(self._body, stretch=1)

    def _teardown_body(self, body: QWidget) -> None:
        if isinstance(body, QTabWidget):
            for i in range(body.count()):
                w = body.widget(i)
                if isinstance(w, _ChatSessionWidget):
                    self._stop_agent_quietly(w.agent)
        elif self.runtime is not None:
            self._stop_runtime_quietly(self.runtime)
            self.runtime = None

    def _build_multi_agent_widget(self) -> QWidget:
        # Fresh ToolRegistry — the methodology skill-activation tool is intentionally
        # not registered here: step-gated skills are a single-conversation concept
        # and don't map cleanly onto a supervisor/worker/reviewer trio. Plain
        # methodology tools (get_vuln_description, set_methodology_status, ...)
        # remain available to every worker.
        registry = ToolRegistry()
        register_all_tools(registry, self._ctx)

        multi_config = load_multi_agent_config(self._settings)
        self.runtime = MultiAgentRuntime(multi_config, registry)
        return MultiAgentChatWidget(self.runtime, self)

    def _build_tabs(self) -> QTabWidget:
        tabs = QTabWidget()
        tabs.setStyleSheet(_TABS)
        tabs.setTabsClosable(True)
        tabs.tabCloseRequested.connect(self._on_tab_close_requested)
        tabs.tabBarDoubleClicked.connect(self._on_tab_rename)

        new_btn = QToolButton()
        new_btn.setText("+ New")
        new_btn.setToolTip("Start a new chat")
        new_btn.setStyleSheet(_BTN)
        new_btn.clicked.connect(lambda: self._new_chat())

        history_btn = QToolButton()
        history_btn.setText("History")
        history_btn.setToolTip("Reopen a previous chat")
        history_btn.setStyleSheet(_BTN)
        history_btn.clicked.connect(lambda: self._show_history_menu(history_btn))

        corner = QWidget()
        corner_lay = QHBoxLayout(corner)
        corner_lay.setContentsMargins(0, 0, 4, 0)
        corner_lay.setSpacing(4)
        corner_lay.addWidget(history_btn)
        corner_lay.addWidget(new_btn)
        tabs.setCornerWidget(corner, Qt.TopRightCorner)

        self.tabs = tabs
        self._new_chat()
        return tabs

    # ── chat tab lifecycle ─────────────────────────────────────────────────────

    def _new_chat(self, conversation_id: str | None = None) -> None:
        assert self.tabs is not None
        config = load_agent_config(self._settings)
        agent = Agent(config, conversation_id=conversation_id, store=self._store)
        register_all_tools(agent.tools, self._ctx)
        for skill_cls in build_methodology_skill_classes():
            agent.skills.register_skill(skill_cls)
        self._register_skill_activation_tool(agent)
        self.agent = agent

        session = _ChatSessionWidget(agent, self.tabs)
        self._chat_counter += 1
        idx = self.tabs.addTab(session, f"Chat {self._chat_counter}")
        self.tabs.setCurrentIndex(idx)

        reopening = conversation_id is not None

        async def _boot() -> None:
            await agent.start()
            if reopening:
                history = agent.get_conversation_history()
                if history:
                    session.chat_widget.load_history(history)

        try:
            asyncio.ensure_future(_boot())
        except RuntimeError:
            log.exception("No running asyncio loop — was install_qasync() called before this page was built?")

    def _on_tab_close_requested(self, index: int) -> None:
        assert self.tabs is not None
        if self.tabs.count() <= 1:
            return
        widget = self.tabs.widget(index)
        self.tabs.removeTab(index)
        if isinstance(widget, _ChatSessionWidget):
            self._stop_agent_quietly(widget.agent)
            widget.deleteLater()

    def _on_tab_rename(self, index: int) -> None:
        if index < 0 or self.tabs is None:
            return
        current = self.tabs.tabText(index)
        name, ok = QInputDialog.getText(self, "Rename Chat", "Chat name:", text=current)
        if ok and name.strip():
            self.tabs.setTabText(index, name.strip())

    def _show_history_menu(self, anchor: QWidget) -> None:
        assert self.tabs is not None
        menu = QMenu(self)
        open_ids = {
            self.tabs.widget(i).agent.conversation_id
            for i in range(self.tabs.count())
            if isinstance(self.tabs.widget(i), _ChatSessionWidget)
        }
        try:
            ids = self._store.list_ids()
        except Exception:
            ids = []

        any_entry = False
        for cid in ids:
            if cid in open_ids:
                continue
            try:
                data = self._store.load(cid)
            except Exception:
                continue
            messages = data.get("messages", [])
            preview = next(
                (m["content"][:50] for m in messages if m.get("role") == "user" and m.get("content")),
                cid[:8],
            )
            act = menu.addAction(preview)
            act.triggered.connect(lambda _checked=False, c=cid: self._new_chat(conversation_id=c))
            any_entry = True

        if not any_entry:
            act = menu.addAction("No saved chats")
            act.setEnabled(False)

        menu.exec(anchor.mapToGlobal(anchor.rect().bottomLeft()))

    def _register_skill_activation_tool(self, agent: Agent) -> None:
        """SkillManager.activate_skill() must be called explicitly — nothing does
        this automatically, so the agent needs a tool to trigger it itself when it
        judges a multi-step methodology workflow is the right approach."""

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

        agent.tools.register(activate_methodology_skill)

    # ── settings reload ─────────────────────────────────────────────────────────

    def reload_settings(self) -> None:
        """Called after Settings → AI is saved. Reconfigures already-open chats to
        match the new provider/model/prompts without losing conversation history.
        A change to the single-agent/multi-agent toggle rebuilds the whole page
        body instead, since the two modes don't share a widget shape."""
        self._settings = SettingsRepository(self._project_dir, self._mongo_uri)
        multi_agent_now = (self._settings.get(Keys.LLM_MULTI_AGENT, default="false") or "false") == "true"

        if multi_agent_now != self._multi_agent_enabled:
            self._multi_agent_enabled = multi_agent_now
            self._build_body()
            return

        if multi_agent_now:
            # Multi-agent conversations aren't persisted across config edits today —
            # rebuild the runtime fresh against the new provider/model/prompts.
            self._build_body()
            return

        new_config = load_agent_config(self._settings)
        if self.tabs is None:
            return
        for i in range(self.tabs.count()):
            session = self.tabs.widget(i)
            if isinstance(session, _ChatSessionWidget):
                try:
                    asyncio.ensure_future(self._reload_session(session, new_config))
                except RuntimeError:
                    log.exception("No running asyncio loop for settings reload")

    async def _reload_session(self, session: _ChatSessionWidget, new_config) -> None:
        try:
            await session.agent.reload_config(new_config)
        except Exception as exc:
            session.chat_widget.add_system_message(f"✗ Settings reload failed: {exc}")
            return
        session.quick_switch.sync_from_agent()
        session.chat_widget.add_system_message(
            f"✔ Settings reloaded — now using provider={session.agent.config.provider} "
            f"model={session.agent.config.model}"
        )

    # ── misc lifecycle helpers ───────────────────────────────────────────────────

    def _stop_agent_quietly(self, agent: Agent) -> None:
        try:
            asyncio.ensure_future(agent.stop())
        except RuntimeError:
            pass

    def _stop_runtime_quietly(self, runtime: MultiAgentRuntime) -> None:
        try:
            asyncio.ensure_future(runtime.stop())
        except RuntimeError:
            pass

    def receive_context(self, payload: dict) -> None:
        """Slot for the "Send to AI" hooks — primes the active chat's input
        without auto-sending."""
        kind = payload.get("kind", "context")
        source = payload.get("source_page", "")
        text = payload.get("text", "")
        prefix = f"[{kind} from {source}]\n" if source else f"[{kind}]\n"
        input_box = self._active_input_box()
        if input_box is not None:
            input_box.setPlainText(prefix + text)

    def _active_input_box(self):
        if self._multi_agent_enabled:
            return getattr(self._body, "input_box", None)
        if self.tabs is None or self.tabs.count() == 0:
            return None
        session = self.tabs.currentWidget()
        return session.chat_widget.input_box if isinstance(session, _ChatSessionWidget) else None

    def stop_agent(self) -> None:
        if self.runtime is not None:
            self._stop_runtime_quietly(self.runtime)
        if self.tabs is not None:
            for i in range(self.tabs.count()):
                w = self.tabs.widget(i)
                if isinstance(w, _ChatSessionWidget):
                    self._stop_agent_quietly(w.agent)
