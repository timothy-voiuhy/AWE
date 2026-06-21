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
    def __init__(self, tool_key: str, display_name: str, stage: int, parent=None):
        super().__init__(parent)
        self.tool_key = tool_key
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

    def set_status(self, status: str, count: int = 0):
        icon, color = _STATUS_ICON.get(status, ("?", "#CDD6F4"))
        self._icon.setText(icon)
        self._icon.setStyleSheet(f"color: {color};")
        if count:
            self._count.setText(str(count))

    def append_log(self, line: str):
        self._last.setText(line[:100])


class _MonitorPanel(QScrollArea):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWidgetResizable(True)
        self._container = QWidget()
        self._vbox = QVBoxLayout(self._container)
        self._vbox.setSpacing(2)
        self._vbox.setContentsMargins(4, 4, 4, 4)
        self._vbox.addStretch()
        self.setWidget(self._container)
        self._rows: dict[str, _StepRow] = {}

    def populate(self, steps):
        item = self._vbox.takeAt(self._vbox.count() - 1)
        del item
        for w in self._rows.values():
            w.setParent(None)
        self._rows.clear()
        for step in steps:
            tool = TOOL_REGISTRY.get(step.tool_key)
            name = tool.display_name if tool else step.tool_key
            r = _StepRow(step.tool_key, name, step.stage)
            self._vbox.addWidget(r)
            self._rows[step.tool_key] = r
        self._vbox.addStretch()

    def on_started(self, key: str):
        r = self._rows.get(key)
        if r: r.set_status("running")

    def on_log(self, key: str, line: str):
        r = self._rows.get(key)
        if r: r.append_log(line)

    def on_done(self, key: str, status: str, count: int):
        r = self._rows.get(key)
        if r: r.set_status(status, count)


# ── Main window ───────────────────────────────────────────────────────────────

class PipelineWindow(QMainWindow):
    def __init__(self, project_dir: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Pipeline Runner")
        self.resize(1300, 800)
        self._project_dir = project_dir
        self._executor: PipelineExecutor | None = None
        self._current_session_id = ""
        self._repo    = AweRepository(project_dir, _MONGO_URI)
        self._settings = SettingsRepository(project_dir, _MONGO_URI)
        self._custom_templates: dict[str, PipelineTemplate] = {}

        self._build_ui()
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
        vbox.setSpacing(4)

        hdr = QLabel("Session History")
        hdr.setObjectName("certStepLabel")
        vbox.addWidget(hdr)

        self._sessionList = QListWidget()
        self._sessionList.setFont(QFont("Cascadia Code", 9))
        self._sessionList.setObjectName("siteMapTreeView")
        self._sessionList.currentItemChanged.connect(self._on_session_selected)
        vbox.addWidget(self._sessionList)

        btn_row = QHBoxLayout()
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
        vbox.setContentsMargins(4, 4, 4, 4)
        self._stageLabel = QLabel("No pipeline running")
        self._stageLabel.setObjectName("dockerStatusMsg")
        vbox.addWidget(self._stageLabel)
        self._monitor = _MonitorPanel()
        vbox.addWidget(self._monitor)
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

    def _start_pipeline(self, retry_keys: set[str] | None = None):
        target = self._targetEdit.text().strip()
        if not target:
            self._log("[!] Enter a target domain")
            return
        ok, msg = ping(_MONGO_URI)
        if not ok:
            self._log(f"[!] MongoDB: {msg}")
            return

        tmpl = self._current_template()
        if not tmpl:
            return

        in_scope   = parse_scope_text(self._inScopeEdit.text())
        out_scope  = parse_scope_text(self._outScopeEdit.text())

        self._logView.clear()
        self._monitor.populate(tmpl.steps if not retry_keys else
                                [s for s in tmpl.steps if s.tool_key in retry_keys])
        self._mainTabs.setCurrentIndex(1)

        self._progressBar.setMaximum(len(tmpl.steps))
        self._progressBar.setValue(0)
        self._progressBar.setVisible(True)
        self._stageLabel.setText(f"Running: {tmpl.name}  →  {target}")

        self._executor = PipelineExecutor(
            template=tmpl,
            project_dir=self._project_dir,
            target=target,
            in_scope=in_scope,
            out_of_scope=out_scope,
            retry_tool_keys=retry_keys,
            mongo_uri=_MONGO_URI,
        )
        self._executor.step_started.connect(
            lambda k, n, s: (self._monitor.on_started(k), self._log(f"[S{s}] ▶ {n}")))
        self._executor.step_log.connect(
            lambda k, l: (self._monitor.on_log(k, l), self._log(f"  [{k}] {l}")))
        self._executor.step_done.connect(self._on_step_done)
        self._executor.stage_done.connect(lambda n: self._stageLabel.setText(f"Stage {n} done"))
        self._executor.pipeline_done.connect(self._on_pipeline_done)
        self._executor.progress.connect(
            lambda d, t: self._progressBar.setValue(d))
        self._executor.start()

        self._runBtn.setEnabled(False)
        self._stopBtn.setEnabled(True)
        self._retryBtn.setEnabled(False)

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
        self._start_pipeline(retry_keys=failed)

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
        self._refresh_sessions()
        _notify("AWE — Pipeline finished", message)

    # ── Session history ───────────────────────────────────────────────────────

    def _refresh_sessions(self):
        self._sessionList.clear()
        try:
            sessions = self._repo.list_sessions(100)
        except Exception:
            return
        for s in sessions:
            status = s.get("status", "")
            icon, color = _STATUS_ICON.get(status, ("○", "#CDD6F4"))
            dt = (s.get("started_at") or "")[:16].replace("T", " ")
            summary = self._repo.session_summary(s["id"])
            counts  = "  ".join(f"{k[0].upper()}{v}" for k, v in summary.items())
            scope_hint = ""
            if s.get("in_scope"):
                scope_hint = f"  [scope: {', '.join(s['in_scope'][:2])}]"
            text = (f"{icon} {s.get('pipeline_name','?')}  {dt}\n"
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
