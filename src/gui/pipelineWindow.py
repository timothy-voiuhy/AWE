"""
Pipeline Runner Window — configuration, execution, session history.
"""
import subprocess
from datetime import datetime

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QComboBox, QDialog, QFileDialog, QFrame, QHBoxLayout, QLabel,
    QLineEdit, QListWidget, QListWidgetItem, QMainWindow, QMessageBox,
    QProgressBar, QPushButton, QScrollArea, QSplitter, QTabWidget,
    QTextEdit, QVBoxLayout, QWidget, QFormLayout,
)

from database.mongo import ping
from database.mongod_manager import ensure_running
from database.repository import AweRepository
from database.settings_repository import SettingsRepository
from gui.pipelineEditorDialog import (
    PipelineEditorDialog, pipeline_from_dict, pipeline_to_dict,
)
from gui.resultsWindow import ResultsWindow
from gui.settingsWindow import SettingsWindow
from pipeline.definitions import PIPELINE_REGISTRY
from pipeline.executor import PipelineExecutor
from pipeline.models import PipelineTemplate
from pipeline.scope import parse_scope_text
from containers.tool_registry import TOOL_REGISTRY

_MONGO_URI = "mongodb://localhost:27017"

_STATUS_ICON = {
    "running":   ("●", "#89B4FA"),
    "completed": ("✓", "#A6E3A1"),
    "failed":    ("✗", "#F38BA8"),
    "cancelled": ("⊘", "#FAB387"),
    "skipped":   ("⏭", "#6C7086"),
    "pending":   ("○", "#6C7086"),
}


# ── Desktop notification ──────────────────────────────────────────────────────

def _notify(title: str, body: str):
    try:
        subprocess.run(
            ["notify-send", "-a", "AWE", "-t", "6000", title, body],
            capture_output=True, timeout=3,
        )
    except Exception:
        pass


# ── Mongo startup thread ──────────────────────────────────────────────────────

class _MongoStarter(QThread):
    done = Signal(bool, str)
    def run(self):
        ok, msg = ensure_running()
        self.done.emit(ok, msg)


# ── Live monitor row ──────────────────────────────────────────────────────────

class _StepRow(QWidget):
    selected         = Signal(str)   # tool_key — emitted on click
    rerun_requested  = Signal(str)   # tool_key — emitted on right-click rerun

    def __init__(self, tool_key: str, display_name: str, stage: int, parent=None):
        super().__init__(parent)
        self.tool_key = tool_key
        self._selected = False
        row = QHBoxLayout(self)
        row.setContentsMargins(4, 2, 4, 2)
        row.setSpacing(8)

        self._icon = QLabel("○")
        self._icon.setFixedWidth(16)
        self._icon.setFont(QFont("monospace", 10))
        self._icon.setStyleSheet("color: #6C7086;")
        row.addWidget(self._icon)

        badge = QLabel(f"S{stage}")
        badge.setFixedWidth(24)
        badge.setObjectName("certStepBadge")
        row.addWidget(badge)

        self._name = QLabel(display_name)
        self._name.setFixedWidth(140)
        self._name.setFont(QFont("Cascadia Code", 9))
        row.addWidget(self._name)

        self._count = QLabel("")
        self._count.setFixedWidth(60)
        self._count.setFont(QFont("Cascadia Code", 9))
        self._count.setStyleSheet("color: #A6E3A1;")
        row.addWidget(self._count)

        self._last = QLabel("")
        self._last.setFont(QFont("Cascadia Code", 8))
        self._last.setStyleSheet("color: #9399B2;")
        self._last.setTextInteractionFlags(Qt.TextSelectableByMouse)
        row.addWidget(self._last, stretch=1)

        self.setCursor(Qt.PointingHandCursor)
        self._update_selection_style()

    # ── selection ─────────────────────────────────────────────────────────────

    def set_selected(self, value: bool):
        self._selected = value
        self._update_selection_style()

    def _update_selection_style(self):
        if self._selected:
            self.setStyleSheet(
                "background:#2A2A3E; border-left:3px solid #89B4FA; border-radius:2px;")
        else:
            self.setStyleSheet("")

    def mousePressEvent(self, ev):
        self.selected.emit(self.tool_key)
        super().mousePressEvent(ev)

    def contextMenuEvent(self, ev):
        from PySide6.QtWidgets import QMenu
        menu = QMenu(self)
        a_rerun = menu.addAction("↺  Rerun this tool")
        chosen = menu.exec(ev.globalPos())
        if chosen == a_rerun:
            self.rerun_requested.emit(self.tool_key)

    # ── status/log ────────────────────────────────────────────────────────────

    def set_status(self, status: str, count: int = 0):
        icon, color = _STATUS_ICON.get(status, ("?", "#CDD6F4"))
        self._icon.setText(icon)
        self._icon.setStyleSheet(f"color: {color};")
        if count:
            self._count.setText(str(count))

    def append_log(self, line: str):
        self._last.setText(line[:80])


class _MonitorPanel(QWidget):
    """
    Split monitor panel:
      Left  — stage-grouped list of _StepRow widgets with per-stage rerun buttons
      Right — full buffered log for the selected tool
    """
    rerun_stage = Signal(int)   # stage_num
    rerun_tool  = Signal(str)   # tool_key

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        splitter = QSplitter(Qt.Horizontal)
        splitter.setStyleSheet(
            "QSplitter::handle{background:#313244; width:2px;}")
        splitter.setChildrenCollapsible(False)

        # ── left: step list ───────────────────────────────────────────────────
        step_scroll = QScrollArea()
        step_scroll.setWidgetResizable(True)
        step_scroll.setFrameShape(QFrame.NoFrame)
        self._container = QWidget()
        self._vbox = QVBoxLayout(self._container)
        self._vbox.setSpacing(1)
        self._vbox.setContentsMargins(2, 2, 2, 2)
        self._vbox.addStretch()
        step_scroll.setWidget(self._container)
        splitter.addWidget(step_scroll)

        # ── right: per-tool log ───────────────────────────────────────────────
        log_panel = QWidget()
        log_vb = QVBoxLayout(log_panel)
        log_vb.setContentsMargins(4, 2, 4, 4)
        log_vb.setSpacing(2)

        log_hdr = QHBoxLayout()
        self._log_title = QLabel("Select a tool to view its log")
        self._log_title.setObjectName("certStepLabel")
        log_hdr.addWidget(self._log_title)
        log_hdr.addStretch()
        self._clear_tool_log_btn = QPushButton("Clear")
        self._clear_tool_log_btn.setFixedHeight(22)
        self._clear_tool_log_btn.setEnabled(False)
        self._clear_tool_log_btn.clicked.connect(self._clear_selected_log)
        log_hdr.addWidget(self._clear_tool_log_btn)
        log_vb.addLayout(log_hdr)

        self._tool_log = QTextEdit()
        self._tool_log.setReadOnly(True)
        self._tool_log.setFont(QFont("Cascadia Code", 9))
        self._tool_log.setObjectName("certLogView")
        log_vb.addWidget(self._tool_log)
        splitter.addWidget(log_panel)

        splitter.setSizes([280, 720])
        layout.addWidget(splitter)

        # state
        self._rows: dict[str, _StepRow] = {}
        self._log_buffer: dict[str, list[str]] = {}   # tool_key → full log lines
        self._selected_key: str | None = None
        self._stage_rerun_btns: dict[int, QPushButton] = {}
        self._is_running = False

    # ── public API ────────────────────────────────────────────────────────────

    def set_running(self, running: bool) -> None:
        """Disable stage rerun buttons while a pipeline is active."""
        self._is_running = running
        for btn in self._stage_rerun_btns.values():
            btn.setEnabled(not running)

    def populate(self, steps):
        # Clear all existing widgets (stage headers + step rows)
        while self._vbox.count():
            item = self._vbox.takeAt(0)
            if item.widget():
                item.widget().setParent(None)
        self._rows.clear()
        self._log_buffer.clear()
        self._stage_rerun_btns.clear()
        self._selected_key = None
        self._tool_log.clear()
        self._log_title.setText("Select a tool to view its log")
        self._clear_tool_log_btn.setEnabled(False)

        # Group steps by stage
        stages: dict[int, list] = {}
        for step in steps:
            stages.setdefault(step.stage, []).append(step)

        _HDR_SS = (
            "QWidget{background:#252540;border-radius:3px;}"
            "QLabel{color:#6C7086;font-size:9px;font-weight:bold;background:transparent;}"
        )
        _BTN_SS = (
            "QPushButton{background:#1A1A2E;color:#89B4FA;border:1px solid #313244;"
            "border-radius:3px;font-size:8px;padding:0 6px;min-height:18px;max-height:18px;}"
            "QPushButton:hover{background:#252540;border-color:#89B4FA;}"
            "QPushButton:disabled{color:#45475A;border-color:#252540;}"
        )

        for stage_num in sorted(stages.keys()):
            # Stage header row
            hdr_w = QWidget()
            hdr_w.setStyleSheet(_HDR_SS)
            hdr_hl = QHBoxLayout(hdr_w)
            hdr_hl.setContentsMargins(6, 2, 4, 2)
            hdr_hl.setSpacing(6)
            hdr_hl.addWidget(QLabel(f"Stage {stage_num}"))
            hdr_hl.addStretch()
            rerun_btn = QPushButton(f"↺ Rerun S{stage_num}")
            rerun_btn.setStyleSheet(_BTN_SS)
            rerun_btn.setEnabled(not self._is_running)
            _sn = stage_num   # capture for lambda
            rerun_btn.clicked.connect(lambda checked=False, sn=_sn: self.rerun_stage.emit(sn))
            hdr_hl.addWidget(rerun_btn)
            self._stage_rerun_btns[stage_num] = rerun_btn
            self._vbox.addWidget(hdr_w)

            for step in stages[stage_num]:
                tool = TOOL_REGISTRY.get(step.tool_key)
                name = tool.display_name if tool else step.tool_key
                r = _StepRow(step.tool_key, name, step.stage)
                r.selected.connect(self._on_row_selected)
                r.rerun_requested.connect(self.rerun_tool)
                self._vbox.addWidget(r)
                self._rows[step.tool_key] = r
                self._log_buffer[step.tool_key] = []

        self._vbox.addStretch()

        # Auto-select first tool
        if self._rows:
            first_key = next(iter(self._rows))
            self._on_row_selected(first_key)

    def on_started(self, key: str):
        r = self._rows.get(key)
        if r:
            r.set_status("running")

    def on_log(self, key: str, line: str):
        r = self._rows.get(key)
        if r:
            r.append_log(line)
        buf = self._log_buffer.get(key)
        if buf is not None:
            buf.append(line)
        if key == self._selected_key:
            self._tool_log.append(line)
            self._scroll_log_to_end()

    def on_done(self, key: str, status: str, count: int):
        r = self._rows.get(key)
        if r:
            r.set_status(status, count)

    # ── internal ──────────────────────────────────────────────────────────────

    def _on_row_selected(self, key: str):
        if self._selected_key and self._selected_key in self._rows:
            self._rows[self._selected_key].set_selected(False)
        self._selected_key = key
        if key in self._rows:
            self._rows[key].set_selected(True)

        tool = TOOL_REGISTRY.get(key)
        name = tool.display_name if tool else key
        self._log_title.setText(f"Log — {name}")
        self._clear_tool_log_btn.setEnabled(True)

        self._tool_log.clear()
        buf = self._log_buffer.get(key, [])
        if buf:
            self._tool_log.setPlainText("\n".join(buf))
            self._scroll_log_to_end()

    def _clear_selected_log(self):
        self._tool_log.clear()
        if self._selected_key and self._selected_key in self._log_buffer:
            self._log_buffer[self._selected_key].clear()

    def _scroll_log_to_end(self):
        from PySide6.QtGui import QTextCursor
        c = self._tool_log.textCursor()
        c.movePosition(QTextCursor.End)
        self._tool_log.setTextCursor(c)


# ── Main window ───────────────────────────────────────────────────────────────

class PipelineWindow(QMainWindow):
    def __init__(self, project_dir: str, target: str = "", parent=None):
        super().__init__(parent)
        self.setWindowTitle("Pipeline Runner")
        self.resize(1300, 800)
        self._project_dir = project_dir
        self._executor: PipelineExecutor | None = None
        self._current_session_id = ""
        self._repo    = AweRepository(project_dir, _MONGO_URI)
        self._settings = SettingsRepository(project_dir, _MONGO_URI)
        self._custom_templates: dict[str, PipelineTemplate] = {}

        self._stale_session_ids: set[str] = set()
        self._build_ui()
        if target:
            self._targetEdit.setText(target)
        self._load_custom_pipelines()
        self._refresh_pipeline_combo()
        self._refresh_sessions()
        self._start_mongo()

    # ── UI construction ───────────────────────────────────────────────────────

    def _build_ui(self):
        root = QWidget()
        self.setCentralWidget(root)
        vbox = QVBoxLayout(root)
        vbox.setContentsMargins(8, 4, 8, 8)
        vbox.setSpacing(0)
        toolbar = self._build_toolbar()
        toolbar.setFixedHeight(36)
        vbox.addWidget(toolbar)
        vbox.addWidget(self._hline())
        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(self._build_history_panel())
        splitter.addWidget(self._build_main_panel())
        splitter.setSizes([270, 1000])
        vbox.addWidget(splitter)

    def _build_toolbar(self) -> QWidget:
        w = QWidget()
        row = QHBoxLayout(w)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(8)

        self._runBtn = QPushButton("▶  Run Pipeline")
        self._runBtn.setObjectName("primaryButton")
        self._runBtn.clicked.connect(self._start_pipeline)
        row.addWidget(self._runBtn)

        self._stopBtn = QPushButton("■  Stop")
        self._stopBtn.clicked.connect(self._stop_pipeline)
        self._stopBtn.setEnabled(False)
        row.addWidget(self._stopBtn)

        self._retryBtn = QPushButton("↺  Retry Failed")
        self._retryBtn.clicked.connect(self._retry_failed)
        self._retryBtn.setEnabled(False)
        row.addWidget(self._retryBtn)

        self._resumeBtn = QPushButton("▶▶  Resume")
        self._resumeBtn.setToolTip("Continue an interrupted session from where it stopped")
        self._resumeBtn.clicked.connect(self._resume_selected_session)
        self._resumeBtn.setEnabled(False)
        row.addWidget(self._resumeBtn)

        self._viewBtn = QPushButton("View Results")
        self._viewBtn.clicked.connect(self._open_results)
        row.addWidget(self._viewBtn)

        settingsBtn = QPushButton("⚙ Settings")
        settingsBtn.clicked.connect(self._open_settings)
        row.addWidget(settingsBtn)

        row.addStretch()

        self._progressBar = QProgressBar()
        self._progressBar.setFixedWidth(220)
        self._progressBar.setTextVisible(True)
        self._progressBar.setVisible(False)
        row.addWidget(self._progressBar)

        self._mongoStatus = QLabel("⬤ …")
        self._mongoStatus.setObjectName("certDialogSubtitle")
        row.addWidget(self._mongoStatus)
        return w

    def _build_history_panel(self) -> QWidget:
        w = QWidget()
        vbox = QVBoxLayout(w)
        vbox.setContentsMargins(0, 0, 4, 0)
        vbox.setSpacing(2)

        hdr = QLabel("Session History")
        hdr.setObjectName("certStepLabel")
        vbox.addWidget(hdr)

        self._sessionList = QListWidget()
        self._sessionList.setFont(QFont("Cascadia Code", 9))
        self._sessionList.setObjectName("siteMapTreeView")
        self._sessionList.currentItemChanged.connect(self._on_session_selected)
        self._sessionList.setContextMenuPolicy(Qt.CustomContextMenu)
        self._sessionList.customContextMenuRequested.connect(self._session_context_menu)
        vbox.addWidget(self._sessionList, stretch=1)

        btn_row = QHBoxLayout()
        btn_row.setContentsMargins(0, 2, 0, 0)
        delBtn = QPushButton("Delete")
        delBtn.clicked.connect(self._delete_session)
        btn_row.addWidget(delBtn)
        refreshBtn = QPushButton("Refresh")
        refreshBtn.clicked.connect(self._refresh_sessions)
        btn_row.addWidget(refreshBtn)
        vbox.addLayout(btn_row)
        return w

    def _build_main_panel(self) -> QWidget:
        w = QWidget()
        vbox = QVBoxLayout(w)
        vbox.setContentsMargins(0, 0, 0, 0)
        self._mainTabs = QTabWidget()
        self._mainTabs.setObjectName("dockerLeftTabs")
        self._mainTabs.addTab(self._build_config_tab(),  "Configuration")
        self._mainTabs.addTab(self._build_monitor_tab(), "Live Monitor")
        self._mainTabs.addTab(self._build_log_tab(),     "Full Log")
        vbox.addWidget(self._mainTabs)
        return w

    def _build_config_tab(self) -> QWidget:
        w = QWidget()
        vbox = QVBoxLayout(w)
        vbox.setSpacing(10)

        form = QFormLayout()

        # Pipeline selector + editor buttons
        pipe_row = QHBoxLayout()
        self._pipelineCombo = QComboBox()
        self._pipelineCombo.currentIndexChanged.connect(self._on_pipeline_changed)
        pipe_row.addWidget(self._pipelineCombo, stretch=1)
        newBtn  = QPushButton("New…")
        editBtn = QPushButton("Edit…")
        delBtn  = QPushButton("Delete")
        newBtn.clicked.connect(self._new_pipeline)
        editBtn.clicked.connect(self._edit_pipeline)
        delBtn.clicked.connect(self._delete_pipeline)
        pipe_row.addWidget(newBtn)
        pipe_row.addWidget(editBtn)
        pipe_row.addWidget(delBtn)
        form.addRow("Pipeline:", pipe_row)

        self._targetEdit = QLineEdit()
        self._targetEdit.setPlaceholderText("example.com")
        self._targetEdit.setObjectName("urlText")
        form.addRow("Target:", self._targetEdit)

        self._inScopeEdit = QLineEdit()
        self._inScopeEdit.setPlaceholderText("*.example.com, example.com  (blank = all in scope)")
        self._inScopeEdit.setObjectName("urlText")
        form.addRow("In scope:", self._inScopeEdit)

        self._outScopeEdit = QLineEdit()
        self._outScopeEdit.setPlaceholderText("dev.example.com, staging.example.com")
        self._outScopeEdit.setObjectName("urlText")
        form.addRow("Exclude:", self._outScopeEdit)

        vbox.addLayout(form)

        self._descLabel = QLabel()
        self._descLabel.setObjectName("certDialogSubtitle")
        self._descLabel.setWordWrap(True)
        vbox.addWidget(self._descLabel)

        vbox.addWidget(self._hline())

        stepsHdr = QLabel("Pipeline Steps")
        stepsHdr.setObjectName("certStepLabel")
        vbox.addWidget(stepsHdr)

        self._stepsPreview = QTextEdit()
        self._stepsPreview.setReadOnly(True)
        self._stepsPreview.setFont(QFont("Cascadia Code", 9))
        self._stepsPreview.setObjectName("certLogView")
        self._stepsPreview.setMaximumHeight(220)
        vbox.addWidget(self._stepsPreview)
        vbox.addStretch()
        return w

    def _build_monitor_tab(self) -> QWidget:
        w = QWidget()
        vbox = QVBoxLayout(w)
        vbox.setContentsMargins(0, 0, 0, 0)
        vbox.setSpacing(0)
        self._stageLabel = QLabel("No pipeline running")
        self._stageLabel.setObjectName("dockerStatusMsg")
        self._stageLabel.setContentsMargins(6, 3, 6, 3)
        vbox.addWidget(self._stageLabel)
        self._monitor = _MonitorPanel()
        self._monitor.rerun_stage.connect(self._rerun_stage)
        self._monitor.rerun_tool.connect(self._rerun_tool)
        vbox.addWidget(self._monitor, stretch=1)
        return w

    def _build_log_tab(self) -> QWidget:
        w = QWidget()
        vbox = QVBoxLayout(w)
        vbox.setContentsMargins(4, 4, 4, 4)
        clearBtn = QPushButton("Clear")
        clearBtn.clicked.connect(lambda: self._logView.clear())
        row = QHBoxLayout()
        row.addWidget(clearBtn)
        row.addStretch()
        vbox.addLayout(row)
        self._logView = QTextEdit()
        self._logView.setReadOnly(True)
        self._logView.setFont(QFont("Cascadia Code", 9))
        self._logView.setObjectName("certLogView")
        vbox.addWidget(self._logView)
        return w

    # ── Pipeline run control ──────────────────────────────────────────────────

    def _start_pipeline(
        self,
        retry_keys: set[str] | None = None,
        session_id: str | None = None,
        target: str | None = None,
        in_scope: list | None = None,
        out_scope: list | None = None,
    ):
        _target   = target    or self._targetEdit.text().strip()
        _in_scope = in_scope  if in_scope  is not None else parse_scope_text(self._inScopeEdit.text())
        _out_scope = out_scope if out_scope is not None else parse_scope_text(self._outScopeEdit.text())

        if not _target:
            self._log("[!] Enter a target domain")
            return
        ok, msg = ping(_MONGO_URI)
        if not ok:
            self._log(f"[!] MongoDB: {msg}")
            return

        tmpl = self._current_template()
        if not tmpl:
            return

        steps_to_run = (tmpl.steps if not retry_keys else
                        [s for s in tmpl.steps if s.tool_key in retry_keys])

        self._logView.clear()
        self._monitor.populate(steps_to_run)
        self._monitor.set_running(True)
        self._mainTabs.setCurrentIndex(1)

        self._progressBar.setMaximum(len(steps_to_run))
        self._progressBar.setValue(0)
        self._progressBar.setVisible(True)
        self._stageLabel.setText(f"Running: {tmpl.name}  →  {_target}")

        self._executor = PipelineExecutor(
            template=tmpl,
            project_dir=self._project_dir,
            target=_target,
            in_scope=_in_scope,
            out_of_scope=_out_scope,
            retry_tool_keys=retry_keys,
            session_id=session_id,
            mongo_uri=_MONGO_URI,
        )
        self._executor.step_started.connect(
            lambda k, n, s: (self._monitor.on_started(k), self._log(f"[S{s}] ▶ {n}")))
        self._executor.step_log.connect(
            lambda k, l: (self._monitor.on_log(k, l), self._log(f"  [{k}] {l}")))
        self._executor.step_done.connect(self._on_step_done)
        self._executor.stage_done.connect(lambda n: self._stageLabel.setText(f"Stage {n} done"))
        self._executor.pipeline_done.connect(self._on_pipeline_done)
        self._executor.progress.connect(lambda d, t: self._progressBar.setValue(d))
        self._executor.start()

        self._runBtn.setEnabled(False)
        self._stopBtn.setEnabled(True)
        self._retryBtn.setEnabled(False)
        self._resumeBtn.setEnabled(False)

    def _stop_pipeline(self):
        if self._executor:
            self._executor.stop()
        self._stopBtn.setEnabled(False)

    def _retry_failed(self):
        if not self._current_session_id:
            return
        failed = set(self._repo.get_failed_tool_keys(self._current_session_id))
        if not failed:
            QMessageBox.information(self, "Nothing to retry", "No failed steps in this session.")
            return
        self._start_pipeline(retry_keys=failed, session_id=self._current_session_id)

    def _resume_selected_session(self):
        sid = self._current_session_id
        if not sid:
            return
        self._resume_session(sid)

    def _resume_session(self, session_id: str):
        """Continue an interrupted session by re-running every non-completed step."""
        session_doc = self._repo.get_session(session_id)
        if not session_doc:
            return
        tmpl = (PIPELINE_REGISTRY.get(session_doc["pipeline_key"]) or
                self._custom_templates.get(session_doc["pipeline_key"]))
        if not tmpl:
            QMessageBox.warning(self, "Unknown pipeline",
                                f"Cannot find pipeline '{session_doc['pipeline_key']}' "
                                "to resume this session.")
            return

        # Mark any lingering running/pending tool runs as failed (containers are gone)
        self._repo.reset_running_tool_runs(session_id)

        statuses  = self._repo.get_tool_run_statuses(session_id)
        done_keys = {k for k, v in statuses.items() if v in ("completed", "skipped")}
        remaining = {s.tool_key for s in tmpl.steps} - done_keys
        if not remaining:
            QMessageBox.information(self, "Already complete",
                                    "All steps in this session have already completed.")
            return

        # Pre-fill the UI target/scope so the operator can see what's resuming
        self._targetEdit.setText(session_doc.get("target", ""))

        self._start_pipeline(
            retry_keys=remaining,
            session_id=session_id,
            target=session_doc.get("target"),
            in_scope=session_doc.get("in_scope"),
            out_scope=session_doc.get("out_of_scope"),
        )

    def _rerun_stage(self, stage_num: int):
        """Rerun all tools in a given stage, appending results to the current session."""
        sid = self._current_session_id
        if not sid:
            self._log("[!] Select a session first")
            return
        session_doc = self._repo.get_session(sid)
        if not session_doc:
            return
        tmpl = (PIPELINE_REGISTRY.get(session_doc["pipeline_key"]) or
                self._custom_templates.get(session_doc["pipeline_key"]))
        if not tmpl:
            return
        keys = {s.tool_key for s in tmpl.steps if s.stage == stage_num}
        if not keys:
            return
        self._start_pipeline(
            retry_keys=keys,
            session_id=sid,
            target=session_doc.get("target"),
            in_scope=session_doc.get("in_scope"),
            out_scope=session_doc.get("out_of_scope"),
        )

    def _rerun_tool(self, tool_key: str):
        """Rerun a single tool, appending results to the current session."""
        sid = self._current_session_id
        if not sid:
            self._log("[!] Select a session first")
            return
        session_doc = self._repo.get_session(sid)
        if not session_doc:
            return
        tmpl = (PIPELINE_REGISTRY.get(session_doc["pipeline_key"]) or
                self._custom_templates.get(session_doc["pipeline_key"]))
        if not tmpl:
            return
        self._start_pipeline(
            retry_keys={tool_key},
            session_id=sid,
            target=session_doc.get("target"),
            in_scope=session_doc.get("in_scope"),
            out_scope=session_doc.get("out_of_scope"),
        )

    def _session_context_menu(self, pos):
        item = self._sessionList.itemAt(pos)
        if item is None:
            return
        sid = item.data(Qt.UserRole)
        if not sid:
            return

        session_doc = self._repo.get_session(sid)
        if not session_doc:
            return
        tmpl = (PIPELINE_REGISTRY.get(session_doc.get("pipeline_key", "")) or
                self._custom_templates.get(session_doc.get("pipeline_key", "")))

        running = self._executor is not None and self._executor.isRunning()
        is_stale = sid in getattr(self, "_stale_session_ids", set())

        menu = QMenu(self)

        a_resume = menu.addAction("▶▶  Resume (continue from interruption)")
        a_resume.setEnabled(is_stale and not running)

        menu.addSeparator()

        a_retry = menu.addAction("↺  Retry Failed tools")
        a_retry.setEnabled(not running)

        # Per-stage submenu
        stage_menu = menu.addMenu("↺  Rerun Stage…")
        stage_menu.setEnabled(bool(tmpl) and not running)
        if tmpl:
            stages: dict[int, list] = {}
            for step in tmpl.steps:
                stages.setdefault(step.stage, []).append(step)
            for sn in sorted(stages.keys()):
                names = ", ".join(
                    (TOOL_REGISTRY.get(s.tool_key).display_name
                     if TOOL_REGISTRY.get(s.tool_key) else s.tool_key)
                    for s in stages[sn]
                )
                a = stage_menu.addAction(f"Stage {sn}  ({names[:40]})")
                a.setData(sn)

        menu.addSeparator()

        a_tools = menu.addAction("☰  Rerun Specific Tools…")
        a_tools.setEnabled(bool(tmpl) and not running)

        menu.addSeparator()
        a_view   = menu.addAction("⊡  View Results")
        a_delete = menu.addAction("✕  Delete Session")

        chosen = menu.exec(self._sessionList.viewport().mapToGlobal(pos))
        if chosen is None:
            return

        self._current_session_id = sid   # ensure actions target the right session

        if chosen == a_resume:
            self._resume_session(sid)
        elif chosen == a_retry:
            failed = set(self._repo.get_failed_tool_keys(sid))
            if not failed:
                QMessageBox.information(self, "Nothing to retry", "No failed steps.")
                return
            self._start_pipeline(retry_keys=failed, session_id=sid,
                                  target=session_doc.get("target"),
                                  in_scope=session_doc.get("in_scope"),
                                  out_scope=session_doc.get("out_of_scope"))
        elif chosen == a_view:
            self._resultsWindow = ResultsWindow(
                session_id=sid, repo=self._repo, parent=self)
            self._resultsWindow.show()
        elif chosen == a_delete:
            self._repo.delete_session(sid)
            if self._current_session_id == sid:
                self._current_session_id = ""
                self._retryBtn.setEnabled(False)
                self._resumeBtn.setEnabled(False)
            self._refresh_sessions()
        elif chosen == a_tools and tmpl:
            self._pick_and_rerun_tools(sid, session_doc, tmpl)
        elif chosen is not None and chosen.parent() is stage_menu:
            sn = chosen.data()
            if sn is not None:
                keys = {s.tool_key for s in tmpl.steps if s.stage == sn}
                self._start_pipeline(retry_keys=keys, session_id=sid,
                                      target=session_doc.get("target"),
                                      in_scope=session_doc.get("in_scope"),
                                      out_scope=session_doc.get("out_of_scope"))

    def _pick_and_rerun_tools(self, sid: str, session_doc: dict, tmpl):
        """Open a checklist dialog so the user can pick specific tools to rerun."""
        from PySide6.QtWidgets import (
            QDialog, QVBoxLayout, QDialogButtonBox, QCheckBox, QScrollArea, QWidget,
        )
        statuses = self._repo.get_tool_run_statuses(sid)

        dlg = QDialog(self)
        dlg.setWindowTitle("Rerun Specific Tools")
        dlg.setMinimumWidth(360)
        vb = QVBoxLayout(dlg)
        vb.setSpacing(6)

        lbl = QLabel("Select the tools to rerun:")
        lbl.setStyleSheet("color:#CDD6F4; font-size:10px;")
        vb.addWidget(lbl)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.NoFrame)
        inner = QWidget()
        inner_vb = QVBoxLayout(inner)
        inner_vb.setSpacing(3)

        checks: list[QCheckBox] = []
        for step in tmpl.steps:
            tool = TOOL_REGISTRY.get(step.tool_key)
            name = tool.display_name if tool else step.tool_key
            st   = statuses.get(step.tool_key, "pending")
            icon = _STATUS_ICON.get(st, ("○", "#CDD6F4"))[0]
            cb = QCheckBox(f"{icon}  S{step.stage}  {name}")
            cb.setProperty("tool_key", step.tool_key)
            cb.setStyleSheet("color:#CDD6F4; font-size:10px;")
            inner_vb.addWidget(cb)
            checks.append(cb)

        inner_vb.addStretch()
        scroll.setWidget(inner)
        vb.addWidget(scroll, stretch=1)

        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        bb.accepted.connect(dlg.accept)
        bb.rejected.connect(dlg.reject)
        vb.addWidget(bb)

        if dlg.exec() != QDialog.Accepted:
            return

        keys = {cb.property("tool_key") for cb in checks if cb.isChecked()}
        if not keys:
            return
        self._start_pipeline(retry_keys=keys, session_id=sid,
                              target=session_doc.get("target"),
                              in_scope=session_doc.get("in_scope"),
                              out_scope=session_doc.get("out_of_scope"))

    # ── Executor signals ──────────────────────────────────────────────────────

    def _on_step_done(self, key: str, status: str, count: int):
        self._monitor.on_done(key, status, count)
        icon = {"completed": "✓", "skipped": "⏭", "failed": "✗"}.get(status, "?")
        self._log(f"  [{key}] {icon} {status}  ({count})")

    def _on_pipeline_done(self, session_id: str, success: bool, message: str):
        self._current_session_id = session_id
        icon = "✓" if success else "✗"
        self._log(f"\n{icon} Pipeline finished — {message}")
        self._stageLabel.setText(f"{icon} Done: {message}")
        self._progressBar.setVisible(False)
        self._runBtn.setEnabled(True)
        self._stopBtn.setEnabled(False)
        self._retryBtn.setEnabled(True)
        self._resumeBtn.setEnabled(False)
        self._monitor.set_running(False)
        self._refresh_sessions()
        _notify("AWE — Pipeline finished", message)

    # ── Session history ───────────────────────────────────────────────────────

    def _refresh_sessions(self):
        self._sessionList.clear()
        self._stale_session_ids: set[str] = set()
        try:
            sessions = self._repo.list_sessions(100)
        except Exception:
            return
        for s in sessions:
            status = s.get("status", "")
            # A session that is still "running" but the app is not executing it
            # is stale (app was closed mid-run).
            executor_active = (self._executor is not None and self._executor.isRunning()
                               and self._executor._session_id == s["id"])
            is_stale = status == "running" and not executor_active
            if is_stale:
                self._stale_session_ids.add(s["id"])
                icon, color = "⚡", "#FAB387"   # amber lightning = interrupted
            else:
                icon, color = _STATUS_ICON.get(status, ("○", "#CDD6F4"))

            dt = (s.get("started_at") or "")[:16].replace("T", " ")
            summary = self._repo.session_summary(s["id"])
            counts  = "  ".join(f"{k[0].upper()}{v}" for k, v in summary.items())
            scope_hint = ""
            if s.get("in_scope"):
                scope_hint = f"  [scope: {', '.join(s['in_scope'][:2])}]"
            stale_hint = "  ⟲ interrupted" if is_stale else ""
            text = (f"{icon} {s.get('pipeline_name','?')}  {dt}{stale_hint}\n"
                    f"   {s.get('target','')}  {counts}{scope_hint}")
            item = QListWidgetItem(text)
            item.setData(Qt.UserRole, s["id"])
            item.setForeground(QColor(color))
            self._sessionList.addItem(item)

    def _on_session_selected(self, current, _prev):
        if current is None:
            return
        sid = current.data(Qt.UserRole)
        if sid:
            self._current_session_id = sid
            self._retryBtn.setEnabled(True)
            self._viewBtn.setToolTip(f"View results for session {sid[:12]}…")
            is_stale = sid in getattr(self, "_stale_session_ids", set())
            running  = self._executor is not None and self._executor.isRunning()
            self._resumeBtn.setEnabled(is_stale and not running)
            self._load_session_into_ui(sid)

    def _load_session_into_ui(self, session_id: str):
        """Populate Config, Monitor, and Log tabs with a historical session."""
        session_doc = self._repo.get_session(session_id)
        if not session_doc:
            return
        running = self._executor is not None and self._executor.isRunning()

        # ── Config tab — always update ────────────────────────────────────────
        self._targetEdit.setText(session_doc.get("target", ""))
        in_scope  = session_doc.get("in_scope")  or []
        out_scope = session_doc.get("out_of_scope") or []
        self._inScopeEdit.setText(", ".join(in_scope))
        self._outScopeEdit.setText(", ".join(out_scope))

        pipeline_key = session_doc.get("pipeline_key", "")
        idx = self._pipelineCombo.findData(pipeline_key)
        if idx >= 0:
            self._pipelineCombo.blockSignals(True)
            self._pipelineCombo.setCurrentIndex(idx)
            self._pipelineCombo.blockSignals(False)
            self._on_pipeline_changed()

        if running:
            return  # don't stomp the live monitor / log

        tool_runs = self._repo.get_tool_runs(session_id)

        # ── Monitor tab ───────────────────────────────────────────────────────
        tmpl = self._current_template()
        if tmpl:
            self._monitor.populate(tmpl.steps)
            for run in tool_runs:
                key    = run.get("tool_key", "")
                status = run.get("status", "pending")
                count  = run.get("result_count", 0)
                if key:
                    self._monitor.on_done(key, status, count)
            self._monitor.set_running(False)

        # ── Log tab ───────────────────────────────────────────────────────────
        self._logView.clear()
        dt = (session_doc.get("started_at") or "")[:19].replace("T", " ")
        completed_dt = (session_doc.get("completed_at") or "—")[:19].replace("T", " ")
        status_val   = session_doc.get("status", "?").upper()
        self._log(f"Session:   {session_id}")
        self._log(f"Pipeline:  {session_doc.get('pipeline_name','?')}")
        self._log(f"Target:    {session_doc.get('target','')}")
        self._log(f"Started:   {dt}")
        self._log(f"Finished:  {completed_dt}")
        self._log(f"Status:    {status_val}")
        self._log("─" * 56)

        for run in tool_runs:  # already sorted by stage/started_at from repo
            stage   = run.get("stage", 0)
            name    = run.get("display_name") or run.get("tool_key", "?")
            st      = run.get("status", "pending")
            count   = run.get("result_count", 0)
            t0      = (run.get("started_at")  or "")[:19].replace("T", " ")
            t1      = (run.get("completed_at") or "")[:19].replace("T", " ")
            err     = run.get("error_msg") or ""
            icon    = {"completed":"✓","failed":"✗","skipped":"⏭",
                       "running":"●","pending":"○"}.get(st, "?")

            duration = ""
            if t0 and t1:
                try:
                    from datetime import datetime as _dt
                    secs = int((_dt.fromisoformat(t1) - _dt.fromisoformat(t0))
                               .total_seconds())
                    duration = f"  {secs}s"
                except Exception:
                    pass

            self._log(f"  S{stage}  {icon}  {name:<22}  "
                      f"{st:<10}  {count:>5} results{duration}")
            if err:
                self._log(f"       ⚠ {err}")

        summary = self._repo.session_summary(session_id)
        if summary:
            self._log("─" * 56)
            self._log("Results:   " +
                      "  ".join(f"{k}: {v}" for k, v in summary.items()))
        self._stageLabel.setText(
            f"History: {session_doc.get('pipeline_name','?')}  ·  "
            f"{session_doc.get('target','')}  ·  {status_val}"
        )

    def _delete_session(self):
        item = self._sessionList.currentItem()
        if not item:
            return
        sid = item.data(Qt.UserRole)
        if sid:
            self._repo.delete_session(sid)
            if self._current_session_id == sid:
                self._current_session_id = ""
                self._retryBtn.setEnabled(False)
            self._refresh_sessions()

    # ── Pipeline config ───────────────────────────────────────────────────────

    def _refresh_pipeline_combo(self):
        self._pipelineCombo.blockSignals(True)
        current_key = self._pipelineCombo.currentData()
        self._pipelineCombo.clear()
        for tmpl in PIPELINE_REGISTRY.values():
            self._pipelineCombo.addItem(tmpl.name, tmpl.key)
        for key, tmpl in self._custom_templates.items():
            self._pipelineCombo.addItem(f"★ {tmpl.name}", key)
        idx = self._pipelineCombo.findData(current_key)
        if idx >= 0:
            self._pipelineCombo.setCurrentIndex(idx)
        self._pipelineCombo.blockSignals(False)
        self._on_pipeline_changed()

    def _current_template(self) -> PipelineTemplate | None:
        key = self._pipelineCombo.currentData()
        return (PIPELINE_REGISTRY.get(key) or self._custom_templates.get(key))

    def _on_pipeline_changed(self):
        tmpl = self._current_template()
        if not tmpl:
            return
        self._descLabel.setText(tmpl.description)
        stages: dict[int, list] = {}
        for step in tmpl.steps:
            stages.setdefault(step.stage, []).append(step)
        lines = []
        for sn in sorted(stages.keys()):
            lines.append(f"Stage {sn}  (parallel)")
            for step in stages[sn]:
                tool = TOOL_REGISTRY.get(step.tool_key)
                name = tool.display_name if tool else step.tool_key
                cond = f" [{step.condition}]" if step.condition != "always" else ""
                inp  = f" ← {step.input_category}" if step.input_category else ""
                lines.append(f"  • {name}{cond}{inp}")
        self._stepsPreview.setPlainText("\n".join(lines))

    # ── Custom pipeline CRUD ──────────────────────────────────────────────────

    def _load_custom_pipelines(self):
        try:
            docs = self._repo.list_custom_pipelines()
            self._custom_templates = {d["key"]: pipeline_from_dict(d) for d in docs}
        except Exception:
            self._custom_templates = {}

    def _new_pipeline(self):
        dlg = PipelineEditorDialog(parent=self)
        if dlg.exec() == QDialog.Accepted:
            tmpl = dlg.result_template()
            if tmpl:
                self._repo.save_custom_pipeline(pipeline_to_dict(tmpl))
                self._custom_templates[tmpl.key] = tmpl
                self._refresh_pipeline_combo()
                idx = self._pipelineCombo.findData(tmpl.key)
                if idx >= 0:
                    self._pipelineCombo.setCurrentIndex(idx)

    def _edit_pipeline(self):
        tmpl = self._current_template()
        if not tmpl:
            return
        if tmpl.key in PIPELINE_REGISTRY:
            # Editing a built-in — open editor prepopulated (saves as custom copy)
            dlg = PipelineEditorDialog(template=tmpl, parent=self)
        else:
            dlg = PipelineEditorDialog(template=tmpl, parent=self)
        if dlg.exec() == QDialog.Accepted:
            updated = dlg.result_template()
            if updated:
                self._repo.save_custom_pipeline(pipeline_to_dict(updated))
                self._custom_templates[updated.key] = updated
                self._refresh_pipeline_combo()

    def _delete_pipeline(self):
        key = self._pipelineCombo.currentData()
        if key in PIPELINE_REGISTRY:
            QMessageBox.information(self, "Cannot delete",
                                    "Built-in pipelines cannot be deleted.")
            return
        if key in self._custom_templates:
            self._repo.delete_custom_pipeline(key)
            del self._custom_templates[key]
            self._refresh_pipeline_combo()

    # ── Results + settings ────────────────────────────────────────────────────

    def _open_results(self):
        if self._current_session_id:
            self._resultsWindow = ResultsWindow(
                session_id=self._current_session_id,
                repo=self._repo,
                parent=self,
            )
        else:
            self._resultsWindow = ResultsWindow(
                output_dir=self._project_dir,
                parent=self,
            )
        self._resultsWindow.show()

    def _open_settings(self):
        dlg = SettingsWindow(self._project_dir, _MONGO_URI, parent=self)
        dlg.exec()

    # ── MongoDB startup ───────────────────────────────────────────────────────

    def _start_mongo(self):
        self._mongoStatus.setText("⬤ connecting…")
        self._mongoStatus.setStyleSheet("color: #F9E2AF;")
        self._mongoThread = _MongoStarter(self)
        self._mongoThread.done.connect(self._on_mongo_ready)
        self._mongoThread.start()

    def _on_mongo_ready(self, ok: bool, msg: str):
        if ok:
            self._mongoStatus.setText(f"⬤ {msg}")
            self._mongoStatus.setStyleSheet("color: #A6E3A1;")
            self._refresh_sessions()
        else:
            self._mongoStatus.setText(f"⬤ {msg}")
            self._mongoStatus.setStyleSheet("color: #F38BA8;")
            self._runBtn.setEnabled(False)

    # ── Utilities ─────────────────────────────────────────────────────────────

    def _log(self, text: str):
        self._logView.append(text)
        from PySide6.QtGui import QTextCursor
        c = self._logView.textCursor()
        c.movePosition(QTextCursor.End)
        self._logView.setTextCursor(c)

    @staticmethod
    def _hline() -> QFrame:
        f = QFrame()
        f.setFrameShape(QFrame.HLine)
        f.setObjectName("certDivider")
        return f
