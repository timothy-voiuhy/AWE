"""
Pipeline Runner Window — configuration, execution, session history.
"""
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from PySide6.QtCore import Qt, QThread, QTimer, Signal
from PySide6.QtGui import (
    QColor, QFont, QKeySequence, QPixmap, QShortcut, QTextCharFormat, QTextCursor,
)
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QDialog, QFileDialog, QFrame, QHBoxLayout,
    QLabel, QLineEdit, QListWidget, QListWidgetItem, QMainWindow, QMenu, QMessageBox,
    QPlainTextEdit, QPushButton, QScrollArea, QSizePolicy, QSplitter, QTabWidget,
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
from gui.threadrunners import register_monitored_thread
from gui.utilities.syntax_highlighter import SyntaxHighlighter
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
    "stopped":   ("⏹", "#FAB387"),
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

_ROW_BTN_SS = (
    "QPushButton{background:transparent;color:#6C7086;border:none;"
    "font-size:11px;padding:0 3px;min-width:20px;max-width:20px;"
    "min-height:20px;max-height:20px;}"
    "QPushButton:hover{color:#CDD6F4;background:#313244;border-radius:3px;}"
    "QPushButton:disabled{color:#313244;}"
)


class _StepRow(QWidget):
    selected                 = Signal(str)   # tool_key — emitted on click
    rerun_requested          = Signal(str)   # tool_key — emitted on rerun button / context menu
    rerun_parser_requested   = Signal(str)   # tool_key — emitted from context menu
    view_output_requested    = Signal(str)   # tool_key — emitted from context menu
    view_screenshots_requested = Signal(str)   # tool_key — emitted from context menu
    stop_requested           = Signal(str)   # tool_key — emitted on stop button
    check_toggled            = Signal(str, bool)   # tool_key, checked — batch-select checkbox

    def __init__(self, tool_key: str, display_name: str, stage: int, parent=None):
        super().__init__(parent)
        self.tool_key = tool_key
        self._selected = False
        self._row_running = False
        row = QHBoxLayout(self)
        row.setContentsMargins(4, 1, 4, 1)
        row.setSpacing(4)

        self._check = QCheckBox()
        self._check.setFixedWidth(16)
        self._check.setToolTip("Select for batch rerun")
        self._check.toggled.connect(lambda c: self.check_toggled.emit(self.tool_key, c))
        row.addWidget(self._check)

        # Status icon — use app default font so Unicode symbols render reliably
        self._icon = QLabel("○")
        self._icon.setFixedWidth(14)
        self._icon.setStyleSheet("color:#6C7086; font-size:11px;")
        row.addWidget(self._icon)

        badge = QLabel(f"S{stage}")
        badge.setFixedWidth(22)
        badge.setObjectName("certStepBadge")
        row.addWidget(badge)

        self._name = QLabel(display_name)
        self._name.setFont(QFont("Cascadia Code", 9))
        # Stretch so name takes the middle space; count and button stay right-aligned
        row.addWidget(self._name, stretch=1)

        self._count = QLabel("")
        self._count.setFixedWidth(44)
        self._count.setFont(QFont("Cascadia Code", 9))
        self._count.setStyleSheet("color:#A6E3A1; font-size:9px;")
        self._count.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        self._count.setVisible(False)   # hidden until a non-zero count is set
        row.addWidget(self._count)

        self._stop_btn = QPushButton("■")
        self._stop_btn.setToolTip("Stop this tool")
        self._stop_btn.setObjectName("stopBtn")
        self._stop_btn.setStyleSheet(_ROW_BTN_SS)
        self._stop_btn.clicked.connect(lambda: self.stop_requested.emit(self.tool_key))
        self._stop_btn.setVisible(False)
        row.addWidget(self._stop_btn)

        self._rerun_btn = QPushButton("↺")
        self._rerun_btn.setToolTip("Rerun this tool")
        self._rerun_btn.setStyleSheet(_ROW_BTN_SS)
        self._rerun_btn.clicked.connect(lambda: self.rerun_requested.emit(self.tool_key))
        row.addWidget(self._rerun_btn)

        self.setFixedHeight(26)
        self.setCursor(Qt.PointingHandCursor)
        self.setAttribute(Qt.WA_Hover, True)
        self._hovered = False
        self._update_style()

    # ── selection / hover ─────────────────────────────────────────────────────

    def set_selected(self, value: bool):
        self._selected = value
        self._update_style()

    def enterEvent(self, ev):
        self._hovered = True
        self._update_style()
        super().enterEvent(ev)

    def leaveEvent(self, ev):
        self._hovered = False
        self._update_style()
        super().leaveEvent(ev)

    def _update_style(self):
        if self._selected:
            bg     = "#2A2A3E"
            border = "border-left:3px solid #89B4FA;"
        elif self._hovered:
            bg     = "#222235"
            border = "border-left:3px solid #45475A;"
        else:
            bg     = "transparent"
            border = "border-left:3px solid transparent;"
        self.setStyleSheet(
            f"QWidget{{background:{bg};{border}border-radius:2px;}}"
            "QLabel{background:transparent;border:none;}"
            "QPushButton{background:transparent;color:#6C7086;border:none;"
            "font-size:11px;padding:0 3px;min-width:20px;max-width:20px;"
            "min-height:20px;max-height:20px;}"
            "QPushButton:hover{color:#CDD6F4;background:#313244;border-radius:3px;}"
            "QPushButton#stopBtn{color:#F38BA8;}"
            "QPushButton#stopBtn:hover{color:#F38BA8;background:#3D2130;}"
        )

    def mousePressEvent(self, ev):
        self.selected.emit(self.tool_key)
        super().mousePressEvent(ev)

    def contextMenuEvent(self, ev):
        from PySide6.QtWidgets import QMenu
        menu = QMenu(self)
        a_rerun         = menu.addAction("↺  Rerun this tool")
        a_rerun_parser  = menu.addAction("⟳  Rerun parser only")
        a_view_output   = menu.addAction("📄  View Raw Output")
        a_view_shots    = menu.addAction("🖼  View Screenshots")
        chosen = menu.exec(ev.globalPos())
        if chosen == a_rerun:
            self.rerun_requested.emit(self.tool_key)
        elif chosen == a_rerun_parser:
            self.rerun_parser_requested.emit(self.tool_key)
        elif chosen == a_view_output:
            self.view_output_requested.emit(self.tool_key)
        elif chosen == a_view_shots:
            self.view_screenshots_requested.emit(self.tool_key)

    # ── status/log ────────────────────────────────────────────────────────────

    def set_status(self, status: str, count: int = 0):
        icon, color = _STATUS_ICON.get(status, ("?", "#CDD6F4"))
        self._icon.setText(icon)
        self._icon.setStyleSheet(f"color:{color}; font-size:11px;")
        self._row_running = status == "running"
        self._stop_btn.setVisible(self._row_running)
        self._rerun_btn.setVisible(not self._row_running)
        # Rerun stays clickable even while OTHER tools are running elsewhere
        # in the pipeline — PipelineExecutor.add_tool_keys() lets the GUI hand
        # new tools to an already-running executor instead of starting a
        # second one. Only this row's OWN in-flight run blocks it (its button
        # is hidden above anyway; disabling too guards the sliver of time
        # between a rerun click and the container actually reporting started).
        self._rerun_btn.setEnabled(not self._row_running)
        if count:
            self._count.setText(str(count))
            self._count.setVisible(True)

    # ── batch-select checkbox ────────────────────────────────────────────────

    def is_checked(self) -> bool:
        return self._check.isChecked()

    def set_checked(self, value: bool) -> None:
        self._check.blockSignals(True)
        self._check.setChecked(value)
        self._check.blockSignals(False)

    def append_log(self, line: str):
        # Show last log line as a tooltip on the row rather than a cramped label
        self.setToolTip(line[:120] if line else "")


class _MonitorPanel(QWidget):
    """
    Split monitor panel:
      Left  — stage-grouped list of _StepRow widgets with per-stage rerun buttons
      Right — full buffered log for the selected tool
    """
    rerun_stage        = Signal(int)   # stage_num
    rerun_tool         = Signal(str)   # tool_key
    rerun_tool_parser  = Signal(str)   # tool_key
    view_tool_output   = Signal(str)   # tool_key
    view_screenshots   = Signal(str)   # tool_key
    rerun_selected     = Signal(object)   # set[str] of tool_key — batch rerun of checked rows
    stop_tool          = Signal(str)   # tool_key
    stop_stage         = Signal(int)   # stage_num

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        splitter = QSplitter(Qt.Horizontal)
        splitter.setStyleSheet(
            "QSplitter::handle{background:#313244; width:2px;}")
        splitter.setChildrenCollapsible(False)

        # ── left: selection toolbar + step list ─────────────────────────────────
        left_panel = QWidget()
        left_vb = QVBoxLayout(left_panel)
        left_vb.setContentsMargins(0, 0, 0, 0)
        left_vb.setSpacing(2)

        _sel_btn_ss = (
            "QPushButton{background:#1A1A2E;color:#89B4FA;border:1px solid #313244;"
            "border-radius:3px;font-size:8px;padding:0 6px;min-height:18px;max-height:18px;}"
            "QPushButton:hover{background:#252540;border-color:#89B4FA;}"
            "QPushButton:disabled{color:#45475A;border-color:#252540;}"
        )
        _run_sel_btn_ss = (
            "QPushButton{background:#1A2E1A;color:#A6E3A1;border:1px solid #313244;"
            "border-radius:3px;font-size:8px;padding:0 6px;min-height:18px;max-height:18px;}"
            "QPushButton:hover{background:#233A23;border-color:#A6E3A1;}"
            "QPushButton:disabled{color:#45475A;border-color:#252540;}"
        )

        sel_bar = QHBoxLayout()
        sel_bar.setContentsMargins(4, 2, 4, 2)
        sel_bar.setSpacing(6)
        self._selected_lbl = QLabel("")
        self._selected_lbl.setStyleSheet("color:#6C7086; font-size:9px;")
        sel_bar.addWidget(self._selected_lbl)
        sel_bar.addStretch()
        self._select_all_btn = QPushButton("Select All")
        self._select_all_btn.setStyleSheet(_sel_btn_ss)
        self._select_all_btn.clicked.connect(self._select_all)
        sel_bar.addWidget(self._select_all_btn)
        self._clear_sel_btn = QPushButton("Clear")
        self._clear_sel_btn.setStyleSheet(_sel_btn_ss)
        self._clear_sel_btn.clicked.connect(self._clear_selection)
        sel_bar.addWidget(self._clear_sel_btn)
        self._run_selected_btn = QPushButton("▶ Run Selected")
        self._run_selected_btn.setToolTip(
            "Run every checked tool together — tools in the same stage run "
            "in parallel, just like an automatic pipeline run."
        )
        self._run_selected_btn.setStyleSheet(_run_sel_btn_ss)
        self._run_selected_btn.setEnabled(False)
        self._run_selected_btn.clicked.connect(self._on_run_selected_clicked)
        sel_bar.addWidget(self._run_selected_btn)
        left_vb.addLayout(sel_bar)

        step_scroll = QScrollArea()
        step_scroll.setWidgetResizable(True)
        step_scroll.setFrameShape(QFrame.NoFrame)
        self._container = QWidget()
        self._vbox = QVBoxLayout(self._container)
        self._vbox.setSpacing(1)
        self._vbox.setContentsMargins(2, 2, 2, 2)
        self._vbox.addStretch()
        step_scroll.setWidget(self._container)
        self._step_scroll = step_scroll
        left_vb.addWidget(step_scroll, stretch=1)

        splitter.addWidget(left_panel)

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
        self._stage_stop_btns: dict[int, QPushButton] = {}
        self._stage_tools: dict[int, list[str]] = {}
        self._tool_stage: dict[str, int] = {}          # tool_key → stage_num
        self._running_tools: set[str] = set()
        self._checked_keys: set[str] = set()           # tool_key → batch-selected for rerun
        self._is_running = False

    # ── public API ────────────────────────────────────────────────────────────

    def set_running(self, running: bool) -> None:
        """Track pipeline running state. Rerun/stage/selection controls stay
        clickable while running — PipelineExecutor.add_tool_keys() lets the
        GUI hand new tools to an already-running executor rather than
        starting a competing one. Stage stop buttons are driven separately
        by on_started/on_done since they track per-tool activity."""
        self._is_running = running
        if not running:
            # Pipeline finished — disable all stage stop buttons and clear tracking
            for btn in self._stage_stop_btns.values():
                btn.setEnabled(False)
            self._running_tools.clear()

    def populate(self, steps):
        # Clear all existing widgets (stage headers + step rows)
        while self._vbox.count():
            item = self._vbox.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self._rows.clear()
        self._log_buffer.clear()
        self._stage_rerun_btns.clear()
        self._stage_stop_btns.clear()
        self._stage_tools.clear()
        self._tool_stage.clear()
        self._running_tools.clear()
        self._checked_keys.clear()
        self._selected_key = None
        self._tool_log.clear()
        self._log_title.setText("Select a tool to view its log")
        self._clear_tool_log_btn.setEnabled(False)
        self._update_selection_ui()

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
        _STOP_BTN_SS = (
            "QPushButton{background:#1A1A2E;color:#F38BA8;border:1px solid #313244;"
            "border-radius:3px;font-size:8px;padding:0 6px;min-height:18px;max-height:18px;}"
            "QPushButton:hover{background:#2D1B2E;border-color:#F38BA8;}"
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
            _sn = stage_num   # capture for lambda
            stop_btn = QPushButton(f"■ Stop S{stage_num}")
            stop_btn.setStyleSheet(_STOP_BTN_SS)
            stop_btn.setEnabled(self._is_running)
            stop_btn.clicked.connect(lambda checked=False, sn=_sn: self.stop_stage.emit(sn))
            hdr_hl.addWidget(stop_btn)
            self._stage_stop_btns[stage_num] = stop_btn
            rerun_btn = QPushButton(f"↺ Rerun S{stage_num}")
            rerun_btn.setStyleSheet(_BTN_SS)
            # Always enabled: clicking while a pipeline is running hands this
            # stage's tools to it via add_tool_keys() (see _rerun_stage).
            rerun_btn.setEnabled(True)
            rerun_btn.clicked.connect(lambda checked=False, sn=_sn: self.rerun_stage.emit(sn))
            hdr_hl.addWidget(rerun_btn)
            self._stage_rerun_btns[stage_num] = rerun_btn
            self._vbox.addWidget(hdr_w)

            self._stage_tools[stage_num] = []
            for step in stages[stage_num]:
                tool = TOOL_REGISTRY.get(step.tool_key)
                name = tool.display_name if tool else step.tool_key
                r = _StepRow(step.tool_key, name, step.stage)
                r.selected.connect(self._on_row_selected)
                r.rerun_requested.connect(self.rerun_tool)
                r.rerun_parser_requested.connect(self.rerun_tool_parser)
                r.view_output_requested.connect(self.view_tool_output)
                r.view_screenshots_requested.connect(self.view_screenshots)
                r.stop_requested.connect(self.stop_tool)
                r.check_toggled.connect(self._on_row_checked)
                self._vbox.addWidget(r)
                self._rows[step.tool_key] = r
                self._log_buffer[step.tool_key] = []
                self._stage_tools[stage_num].append(step.tool_key)
                self._tool_stage[step.tool_key] = stage_num

        self._vbox.addStretch()

        # Auto-select first tool
        if self._rows:
            first_key = next(iter(self._rows))
            self._on_row_selected(first_key)

    def on_started(self, key: str):
        r = self._rows.get(key)
        if r:
            r.set_status("running")
        self._running_tools.add(key)
        stage = self._tool_stage.get(key)
        if stage is not None:
            btn = self._stage_stop_btns.get(stage)
            if btn:
                btn.setEnabled(True)

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
        self._running_tools.discard(key)
        stage = self._tool_stage.get(key)
        if stage is not None:
            still_running = any(k in self._running_tools for k in self._stage_tools.get(stage, []))
            if not still_running:
                btn = self._stage_stop_btns.get(stage)
                if btn:
                    btn.setEnabled(False)

    def set_tool_log(self, key: str, lines: list[str]) -> None:
        """Pre-populate a tool's log buffer with persisted lines from the DB."""
        if key not in self._log_buffer:
            return
        self._log_buffer[key] = list(lines)
        if key == self._selected_key:
            self._tool_log.setPlainText("\n".join(lines))
            self._scroll_log_to_end()

    def reset_rows(self, keys: set[str]) -> None:
        """Reset status and log for specific tool keys, leaving all other rows intact."""
        for key in keys:
            r = self._rows.get(key)
            if r:
                r.set_status("pending")
            if key in self._log_buffer:
                self._log_buffer[key].clear()
        if self._selected_key in keys:
            self._tool_log.clear()

    def show_tool_logs(self, key: str, lines: list[str]) -> None:
        """Select a row, fill the log panel with lines, and scroll to the row."""
        if key in self._rows:
            if self._selected_key and self._selected_key in self._rows:
                self._rows[self._selected_key].set_selected(False)
            self._selected_key = key
            self._rows[key].set_selected(True)
            tool = TOOL_REGISTRY.get(key)
            self._log_title.setText(f"Log — {tool.display_name if tool else key}")
            self._clear_tool_log_btn.setEnabled(True)
            self._step_scroll.ensureWidgetVisible(self._rows[key])
        self._log_buffer[key] = lines
        self._tool_log.setPlainText("\n".join(lines))
        self._scroll_log_to_end()

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

    # ── batch selection ───────────────────────────────────────────────────────

    def _on_row_checked(self, key: str, checked: bool) -> None:
        if checked:
            self._checked_keys.add(key)
        else:
            self._checked_keys.discard(key)
        self._update_selection_ui()

    def _update_selection_ui(self) -> None:
        # Enabled purely on selection count — clicking it while a pipeline is
        # already running hands the batch to it via add_tool_keys() instead
        # of starting a competing PipelineExecutor (see PipelineWindow._start_pipeline).
        n = len(self._checked_keys)
        self._selected_lbl.setText(f"{n} selected" if n else "")
        self._run_selected_btn.setEnabled(n > 0)
        self._run_selected_btn.setText(f"▶ Run Selected ({n})" if n else "▶ Run Selected")

    def _select_all(self) -> None:
        for key, row in self._rows.items():
            row.set_checked(True)
            self._checked_keys.add(key)
        self._update_selection_ui()

    def _clear_selection(self) -> None:
        for row in self._rows.values():
            row.set_checked(False)
        self._checked_keys.clear()
        self._update_selection_ui()

    def _on_run_selected_clicked(self) -> None:
        if self._checked_keys:
            self.rerun_selected.emit(set(self._checked_keys))

    def _scroll_log_to_end(self):
        from PySide6.QtGui import QTextCursor
        c = self._tool_log.textCursor()
        c.movePosition(QTextCursor.End)
        self._tool_log.setTextCursor(c)


# ── Raw output viewer ────────────────────────────────────────────────────────

class _FindEdit(QLineEdit):
    """QLineEdit that clears itself on Escape."""
    def keyPressEvent(self, ev):
        if ev.key() == Qt.Key_Escape:
            self.clear()
        else:
            super().keyPressEvent(ev)


class _RawOutputViewer(QDialog):
    """Read-only viewer for a tool's raw output file — pretty-printed and
    syntax-highlighted for JSON/JSONL, plain monospace otherwise. Includes a
    Ctrl+F search bar: highlights every match, distinguishes the current one,
    and steps through with Enter / Shift+Enter or the ◀/▶ buttons."""

    def __init__(self, title: str, content: str, is_json: bool, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(False)
        self.resize(820, 640)
        self.setStyleSheet("QDialog{background:#181825;} QLabel{color:#6C7086;font-size:9px;}")

        self._matches: list[QTextCursor] = []
        self._match_index = -1

        self._match_fmt = QTextCharFormat()
        self._match_fmt.setBackground(QColor("#45475A"))
        self._current_fmt = QTextCharFormat()
        self._current_fmt.setBackground(QColor("#89B4FA"))
        self._current_fmt.setForeground(QColor("#1E1E2E"))

        vb = QVBoxLayout(self)
        vb.setContentsMargins(10, 10, 10, 10)
        vb.setSpacing(6)

        hdr = QLabel(title)
        hdr.setStyleSheet("color:#CDD6F4; font-weight:bold; font-size:11px;")
        vb.addWidget(hdr)

        # ── search bar ───────────────────────────────────────────────────────
        search_row = QHBoxLayout()
        search_row.setSpacing(4)
        search_lbl = QLabel("⌕")
        search_lbl.setStyleSheet("color:#6C7086; font-size:12px;")
        search_row.addWidget(search_lbl)

        self._search_edit = _FindEdit()
        self._search_edit.setPlaceholderText("Search output…  (Ctrl+F)")
        self._search_edit.setFixedHeight(24)
        self._search_edit.setStyleSheet(
            "QLineEdit{background:#11111B;color:#CDD6F4;border:1px solid #313244;"
            "border-radius:3px;padding:0 6px;font-size:10px;}"
            "QLineEdit:focus{border-color:#89B4FA;}"
        )
        self._search_edit.textChanged.connect(self._on_search_changed)
        self._search_edit.returnPressed.connect(self._find_next)
        search_row.addWidget(self._search_edit, stretch=1)

        _nav_ss = (
            "QPushButton{background:#313244;color:#CDD6F4;border:1px solid #45475A;"
            "border-radius:3px;font-size:10px;min-width:22px;max-width:22px;min-height:24px;}"
            "QPushButton:hover{background:#45475A;}"
            "QPushButton:disabled{color:#45475A;}"
        )
        self._prev_btn = QPushButton("▲")
        self._prev_btn.setStyleSheet(_nav_ss)
        self._prev_btn.setToolTip("Previous match (Shift+Enter)")
        self._prev_btn.clicked.connect(self._find_prev)
        search_row.addWidget(self._prev_btn)

        self._next_btn = QPushButton("▼")
        self._next_btn.setStyleSheet(_nav_ss)
        self._next_btn.setToolTip("Next match (Enter)")
        self._next_btn.clicked.connect(self._find_next)
        search_row.addWidget(self._next_btn)

        self._match_lbl = QLabel("")
        self._match_lbl.setFixedWidth(50)
        self._match_lbl.setStyleSheet("color:#6C7086; font-size:9px;")
        search_row.addWidget(self._match_lbl)
        vb.addLayout(search_row)

        # Shift+Enter → previous match (returnPressed alone can't see modifiers)
        shift_enter = QShortcut(QKeySequence("Shift+Return"), self._search_edit)
        shift_enter.activated.connect(self._find_prev)
        # Ctrl+F anywhere in the dialog focuses the search field
        focus_search = QShortcut(QKeySequence("Ctrl+F"), self)
        focus_search.activated.connect(
            lambda: (self._search_edit.setFocus(), self._search_edit.selectAll())
        )

        self._text = QPlainTextEdit()
        self._text.setReadOnly(True)
        self._text.setFont(QFont("Cascadia Code", 9))
        self._text.setStyleSheet(
            "QPlainTextEdit{background:#11111B;color:#CDD6F4;border:1px solid #313244;"
            "border-radius:4px;padding:6px;}"
        )
        self._text.setPlainText(content)
        if is_json:
            self._highlighter = SyntaxHighlighter(self._text.document())
        vb.addWidget(self._text, stretch=1)

        btn_row = QHBoxLayout()
        copy_btn = QPushButton("Copy All")
        copy_btn.clicked.connect(lambda: QApplication.clipboard().setText(self._text.toPlainText()))
        btn_row.addWidget(copy_btn)
        btn_row.addStretch()
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        btn_row.addWidget(close_btn)
        vb.addLayout(btn_row)

    # ── search ────────────────────────────────────────────────────────────────

    def _on_search_changed(self, text: str) -> None:
        self._matches = []
        self._match_index = -1
        if text:
            doc = self._text.document()
            cursor = QTextCursor(doc)
            while True:
                cursor = doc.find(text, cursor)
                if cursor.isNull():
                    break
                self._matches.append(QTextCursor(cursor))
            if self._matches:
                self._match_index = 0
        self._prev_btn.setEnabled(bool(self._matches))
        self._next_btn.setEnabled(bool(self._matches))
        if self._matches:
            self._goto_match(0)
        else:
            self._apply_highlights()
            self._update_match_label()

    def _goto_match(self, index: int) -> None:
        if not self._matches:
            return
        self._match_index = index % len(self._matches)
        cur = self._matches[self._match_index]
        self._text.setTextCursor(cur)
        self._text.ensureCursorVisible()
        self._apply_highlights()
        self._update_match_label()

    def _find_next(self) -> None:
        if self._matches:
            self._goto_match(self._match_index + 1)

    def _find_prev(self) -> None:
        if self._matches:
            self._goto_match(self._match_index - 1)

    def _apply_highlights(self) -> None:
        selections = []
        for i, cur in enumerate(self._matches):
            sel = QTextEdit.ExtraSelection()
            sel.cursor = cur
            sel.format = self._current_fmt if i == self._match_index else self._match_fmt
            selections.append(sel)
        self._text.setExtraSelections(selections)

    def _update_match_label(self) -> None:
        if not self._matches:
            self._match_lbl.setText("0/0" if self._search_edit.text() else "")
        else:
            self._match_lbl.setText(f"{self._match_index + 1}/{len(self._matches)}")


# ── Screenshot gallery viewer ────────────────────────────────────────────────

class _ImageGalleryViewer(QDialog):
    """Non-modal image gallery for a tool's screenshot output. Navigate with
    the Prev/Next buttons, Left/Right arrow keys, or the mouse wheel."""

    def __init__(self, title: str, paths: list[Path], parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(False)
        self.resize(900, 700)
        self.setStyleSheet("QDialog{background:#181825;} QLabel{color:#6C7086;font-size:9px;}")
        self.setFocusPolicy(Qt.StrongFocus)

        self._paths = paths
        self._index = 0
        self._current_pixmap: QPixmap | None = None

        self._wheel_locked = False
        self._wheel_cooldown = QTimer(self)
        self._wheel_cooldown.setSingleShot(True)
        self._wheel_cooldown.setInterval(180)
        self._wheel_cooldown.timeout.connect(lambda: setattr(self, "_wheel_locked", False))

        vb = QVBoxLayout(self)
        vb.setContentsMargins(10, 10, 10, 10)
        vb.setSpacing(6)

        hdr_row = QHBoxLayout()
        self._name_lbl = QLabel("")
        self._name_lbl.setStyleSheet("color:#CDD6F4; font-weight:bold; font-size:11px;")
        hdr_row.addWidget(self._name_lbl, stretch=1)
        self._count_lbl = QLabel("")
        self._count_lbl.setStyleSheet("color:#6C7086; font-size:9px;")
        hdr_row.addWidget(self._count_lbl)
        vb.addLayout(hdr_row)

        self._image_label = QLabel()
        self._image_label.setAlignment(Qt.AlignCenter)
        # Ignored size policy + 1px minimum: the (scaled) pixmap must not feed
        # its own size back into the layout, or each resize scales the image up
        # again and it zooms without bound.
        self._image_label.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Ignored)
        self._image_label.setMinimumSize(1, 1)
        self._image_label.setStyleSheet(
            "background:#11111B; border:1px solid #313244; border-radius:4px;"
        )
        vb.addWidget(self._image_label, stretch=1)

        _nav_ss = (
            "QPushButton{background:#313244;color:#CDD6F4;border:1px solid #45475A;"
            "border-radius:4px;padding:4px 14px;font-size:11px;}"
            "QPushButton:hover{background:#45475A;}"
            "QPushButton:disabled{color:#45475A;}"
        )
        nav_row = QHBoxLayout()
        self._prev_btn = QPushButton("◀  Prev")
        self._prev_btn.setStyleSheet(_nav_ss)
        self._prev_btn.clicked.connect(self._show_prev)
        nav_row.addWidget(self._prev_btn)
        nav_row.addStretch()
        copy_btn = QPushButton("Copy Path")
        copy_btn.setStyleSheet(_nav_ss)
        copy_btn.clicked.connect(self._copy_path)
        nav_row.addWidget(copy_btn)
        close_btn = QPushButton("Close")
        close_btn.setStyleSheet(_nav_ss)
        close_btn.clicked.connect(self.accept)
        nav_row.addWidget(close_btn)
        nav_row.addStretch()
        self._next_btn = QPushButton("Next  ▶")
        self._next_btn.setStyleSheet(_nav_ss)
        self._next_btn.clicked.connect(self._show_next)
        nav_row.addWidget(self._next_btn)
        vb.addLayout(nav_row)

        self._show_index(0)

    # ── navigation ────────────────────────────────────────────────────────────

    def _show_index(self, index: int) -> None:
        self._index = index % len(self._paths)
        path = self._paths[self._index]
        pix = QPixmap(str(path))
        if pix.isNull():
            self._current_pixmap = None
            self._image_label.setPixmap(QPixmap())
            self._image_label.setText(f"Could not load image:\n{path.name}")
            self._image_label.setStyleSheet(
                "color:#F38BA8; font-size:11px; background:#11111B;"
                "border:1px solid #313244; border-radius:4px;"
            )
        else:
            self._image_label.setStyleSheet(
                "background:#11111B; border:1px solid #313244; border-radius:4px;"
            )
            self._render_pixmap(pix)
        self._name_lbl.setText(path.name)
        self._count_lbl.setText(f"{self._index + 1} / {len(self._paths)}")
        self._prev_btn.setEnabled(len(self._paths) > 1)
        self._next_btn.setEnabled(len(self._paths) > 1)

    def _render_pixmap(self, pix: QPixmap) -> None:
        self._current_pixmap = pix
        target = self._image_label.size()
        if target.width() > 10 and target.height() > 10:
            scaled = pix.scaled(target, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        else:
            scaled = pix
        self._image_label.setPixmap(scaled)

    def resizeEvent(self, ev) -> None:
        super().resizeEvent(ev)
        if self._current_pixmap is not None and not self._current_pixmap.isNull():
            self._render_pixmap(self._current_pixmap)

    def _show_next(self) -> None:
        self._show_index(self._index + 1)

    def _show_prev(self) -> None:
        self._show_index(self._index - 1)

    def _copy_path(self) -> None:
        QApplication.clipboard().setText(str(self._paths[self._index]))

    # ── input ─────────────────────────────────────────────────────────────────

    def keyPressEvent(self, ev) -> None:
        if ev.key() in (Qt.Key_Right, Qt.Key_Down, Qt.Key_Space):
            self._show_next()
        elif ev.key() in (Qt.Key_Left, Qt.Key_Up):
            self._show_prev()
        elif ev.key() == Qt.Key_Escape:
            self.close()
        else:
            super().keyPressEvent(ev)

    def wheelEvent(self, ev) -> None:
        if self._wheel_locked or len(self._paths) <= 1:
            return
        self._wheel_locked = True
        self._wheel_cooldown.start()
        if ev.angleDelta().y() < 0:
            self._show_next()
        else:
            self._show_prev()


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
        self._output_viewers: list = []   # strong refs so non-modal viewers aren't GC'd
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

        self._initBtn = QPushButton("⊞  Initialize")
        self._initBtn.setToolTip(
            "Create a session and populate Live Monitor without running any "
            "tools — trigger individual tools/stages manually from there, "
            "or still click Run Pipeline to execute everything."
        )
        self._initBtn.clicked.connect(self._initialize_pipeline)
        row.addWidget(self._initBtn)

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
        self._monitor.rerun_tool_parser.connect(self._rerun_parser)
        self._monitor.view_tool_output.connect(self._view_tool_output)
        self._monitor.view_screenshots.connect(self._view_screenshots)
        self._monitor.rerun_selected.connect(self._rerun_selected)
        self._monitor.stop_tool.connect(self._stop_tool)
        self._monitor.stop_stage.connect(self._stop_stage)
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

    def _initialize_pipeline(self):
        """Create a session and populate Live Monitor with pending steps
        without running anything, so the operator can trigger individual
        tools/stages by hand from the monitor's rerun buttons — or still
        click Run Pipeline afterwards to execute everything."""
        _target    = self._targetEdit.text().strip()
        _in_scope  = parse_scope_text(self._inScopeEdit.text())
        _out_scope = parse_scope_text(self._outScopeEdit.text())

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

        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        output_dir = os.path.join(self._project_dir, "sessions", f"{tmpl.key}_{ts}")
        os.makedirs(output_dir, exist_ok=True)

        session_id = self._repo.create_session(
            pipeline_key=tmpl.key,
            pipeline_name=tmpl.name,
            target=_target,
            output_dir=output_dir,
            in_scope=_in_scope,
            out_of_scope=_out_scope,
        )
        # create_session() defaults new sessions to "running" — override since
        # nothing is executing yet. _STATUS_ICON / history list already know
        # how to render "pending".
        self._repo.update_session_status(session_id, "pending")

        self._current_session_id = session_id
        self._refresh_sessions()   # selects the new session, populates Monitor/Log tabs
        self._retryBtn.setEnabled(True)
        self._resumeBtn.setEnabled(False)
        self._mainTabs.setCurrentIndex(1)
        self._log(
            f"[i] Initialized '{tmpl.name}' → {_target}  "
            f"({len(tmpl.steps)} steps pending). Use the rerun buttons in "
            f"Live Monitor to run tools/stages manually, or click "
            f"Run Pipeline to execute everything."
        )

    def _start_pipeline(
        self,
        retry_keys: set[str] | None = None,
        session_id: str | None = None,
        target: str | None = None,
        in_scope: list | None = None,
        out_scope: list | None = None,
    ):
        if self._executor is not None and self._executor.isRunning():
            # Never replace self._executor while its QThread is still running —
            # dropping the last reference to a live QThread makes Qt abort the
            # process with "QThread: Destroyed while thread is still running".
            # For a targeted (re)run, hand the tools to the live executor
            # instead of refusing outright — but only if it's executing the
            # SAME session, otherwise we'd misattribute results to the wrong
            # session/output_dir.
            live_sid = getattr(self._executor, "_session_id", "")
            if retry_keys and session_id and session_id == live_sid \
                    and self._executor.add_tool_keys(set(retry_keys)):
                self._monitor.reset_rows(retry_keys)
                names = ", ".join(sorted(retry_keys))
                self._log(f"[i] Queued onto the running pipeline: {names}")
                return
            self._log(
                "[!] A pipeline is already running — stop it, or wait for it "
                "to finish, before starting another."
            )
            return

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

        if retry_keys and self._monitor._rows:
            # Partial rerun — reset only the targeted rows, keep everything else
            self._monitor.reset_rows(retry_keys)
        else:
            # Fresh run — rebuild the monitor from scratch
            self._logView.clear()
            self._monitor.populate(steps_to_run)
        self._monitor.set_running(True)
        self._mainTabs.setCurrentIndex(1)

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
        self._executor.session_started.connect(self._on_session_started)
        self._executor.step_started.connect(
            lambda k, n, s: (self._monitor.on_started(k), self._log(f"[S{s}] ▶ {n}")))
        self._executor.step_log.connect(
            lambda k, l: (self._monitor.on_log(k, l), self._log(f"  [{k}] {l}")))
        self._executor.step_done.connect(self._on_step_done)
        self._executor.stage_done.connect(lambda n: self._stageLabel.setText(f"Stage {n} done"))
        self._executor.pipeline_done.connect(self._on_pipeline_done)
        register_monitored_thread(self._executor, self, "Pipeline Executor")
        self._executor.start()

        self._runBtn.setEnabled(False)
        self._initBtn.setEnabled(False)
        self._stopBtn.setEnabled(True)
        self._retryBtn.setEnabled(False)
        self._resumeBtn.setEnabled(False)

    def _stop_pipeline(self):
        if self._executor:
            self._executor.stop()
        self._stopBtn.setEnabled(False)
        self._stageLabel.setText("⏹ Stopping — waiting for containers…")

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
        self._last_rerun_key = tool_key
        self._start_pipeline(
            retry_keys={tool_key},
            session_id=sid,
            target=session_doc.get("target"),
            in_scope=session_doc.get("in_scope"),
            out_scope=session_doc.get("out_of_scope"),
        )

    def _rerun_selected(self, tool_keys: set[str]):
        """Rerun a manually-checked batch of tools together, in a single
        PipelineExecutor — tools that share a stage run in parallel, exactly
        like an automatic run. This is the safe way to run several tools at
        once by hand: starting them via separate individual rerun clicks
        would spin up competing PipelineExecutor threads and crash Qt."""
        if not tool_keys:
            return
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
            retry_keys=set(tool_keys),
            session_id=sid,
            target=session_doc.get("target"),
            in_scope=session_doc.get("in_scope"),
            out_scope=session_doc.get("out_of_scope"),
        )

    def _rerun_parser(self, tool_key: str):
        """Re-run the output parser for a tool without re-running its container."""
        sid = self._current_session_id
        if not sid:
            self._log("[!] Select a session first")
            return
        session_doc = self._repo.get_session(sid)
        if not session_doc:
            return

        from containers.parsers import PARSERS
        parser = PARSERS.get(tool_key)
        if not parser:
            self._log(f"  [{tool_key}] No parser registered for this tool")
            return

        output_dir = session_doc.get("output_dir", "")
        if not output_dir:
            self._log(f"  [{tool_key}] Session has no output_dir")
            return

        # Find the most recent tool run for this key in the session
        tool_runs = self._repo.get_tool_runs(sid)
        run = next((r for r in reversed(tool_runs) if r.get("tool_key") == tool_key), None)
        if not run:
            self._log(f"  [{tool_key}] No previous run found in this session")
            return

        run_id = run.get("id", "")
        tool = TOOL_REGISTRY.get(tool_key)
        category = tool.category if tool else "misc"

        self._log(f"  [{tool_key}] ⟳ Re-running parser…")
        try:
            results = parser(output_dir)
            count = 0
            if results:
                count = self._repo.upsert_results(sid, run_id, category, results)
            self._log(f"  [{tool_key}] ✓ {len(results)} raw  →  {count} new unique")
            self._monitor.on_done(tool_key, "completed", len(results))
        except Exception as exc:
            self._log(f"  [{tool_key}] ✗ Parser error: {exc}")
            self._monitor.on_done(tool_key, "failed", 0)

    # ── raw output viewer ────────────────────────────────────────────────────

    _BINARY_EXTS = frozenset({
        ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".bmp",
        ".ttf", ".woff", ".woff2", ".eot", ".zip", ".gz", ".db", ".sqlite",
    })
    _MAX_VIEW_BYTES = 5 * 1024 * 1024   # 5 MB safety cap for the viewer
    _IMAGE_EXTS = frozenset({".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp"})

    def _view_tool_output(self, tool_key: str) -> None:
        """Locate the file(s) a tool wrote to the session's output_dir and
        open them in a syntax-highlighted (JSON) or plain-text viewer."""
        sid = self._current_session_id
        if not sid:
            self._log("[!] Select a session first")
            return
        session_doc = self._repo.get_session(sid)
        if not session_doc:
            return
        output_dir = session_doc.get("output_dir", "")
        if not output_dir or not os.path.isdir(output_dir):
            self._log(f"  [{tool_key}] Session has no output_dir")
            return

        all_files = sorted(
            p for p in Path(output_dir).rglob("*")
            if p.is_file() and not p.name.startswith(".")
            and p.suffix.lower() not in self._BINARY_EXTS
        )
        if not all_files:
            self._log(f"  [{tool_key}] No output files found")
            return

        # Match by tool key against the filename, ignoring separators/case —
        # covers the "<tool>_results.<ext>" convention most tools follow.
        # Falls back to every file in the session's output dir for outliers
        # (e.g. sqlmap writes a bare "log" file with no tool name in it).
        norm_key = tool_key.lower().replace("_", "").replace("-", "")
        matches = [
            p for p in all_files
            if norm_key in p.name.lower().replace("_", "").replace("-", "")
        ]
        candidates = matches or all_files

        if len(candidates) == 1:
            self._open_output_viewer(tool_key, candidates[0])
            return

        menu = QMenu(self)
        actions = {}
        for p in candidates:
            rel = p.relative_to(output_dir)
            actions[menu.addAction(str(rel))] = p
        chosen = menu.exec(self.cursor().pos())
        if chosen in actions:
            self._open_output_viewer(tool_key, actions[chosen])

    def _open_output_viewer(self, tool_key: str, path: Path) -> None:
        tool = TOOL_REGISTRY.get(tool_key)
        name = tool.display_name if tool else tool_key

        try:
            size = path.stat().st_size
            truncated = size > self._MAX_VIEW_BYTES
            with open(path, "rb") as f:
                raw = f.read(self._MAX_VIEW_BYTES if truncated else size).decode(
                    "utf-8", errors="replace"
                )
        except OSError as exc:
            self._log(f"  [{tool_key}] Could not read {path.name}: {exc}")
            return

        ext = path.suffix.lower()
        is_json = ext in (".json", ".jsonl")
        content = raw
        if not truncated:
            if ext == ".json":
                try:
                    content = json.dumps(json.loads(raw), indent=2)
                except (json.JSONDecodeError, ValueError):
                    pass
            elif ext == ".jsonl":
                pretty = []
                for line in raw.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        pretty.append(json.dumps(json.loads(line), indent=2))
                    except (json.JSONDecodeError, ValueError):
                        pretty.append(line)
                content = "\n\n".join(pretty)
            else:
                stripped = raw.strip()
                is_json = stripped.startswith(("{", "[")) and stripped.endswith(("}", "]"))
        if truncated:
            content += (
                f"\n\n… [truncated — showing first "
                f"{self._MAX_VIEW_BYTES // (1024 * 1024)} MB of {size / (1024 * 1024):.1f} MB]"
            )

        viewer = _RawOutputViewer(f"{name} — {path.name}", content, is_json, parent=self)
        self._output_viewers.append(viewer)
        viewer.finished.connect(
            lambda _=None, v=viewer: self._output_viewers.remove(v) if v in self._output_viewers else None
        )
        viewer.show()

    def _view_screenshots(self, tool_key: str) -> None:
        """Open every image found under the session's output_dir in a
        scrollable gallery viewer. Not tied to a specific tool's naming
        convention — screenshots (e.g. gowitness) are named after their
        target URL, not the tool, so this just shows whatever images exist."""
        sid = self._current_session_id
        if not sid:
            self._log("[!] Select a session first")
            return
        session_doc = self._repo.get_session(sid)
        if not session_doc:
            return
        output_dir = session_doc.get("output_dir", "")
        if not output_dir or not os.path.isdir(output_dir):
            self._log(f"  [{tool_key}] Session has no output_dir")
            return

        images = sorted(
            p for p in Path(output_dir).rglob("*")
            if p.is_file() and p.suffix.lower() in self._IMAGE_EXTS
        )
        if not images:
            self._log(f"  [{tool_key}] No screenshots found for this tool")
            return

        tool = TOOL_REGISTRY.get(tool_key)
        name = tool.display_name if tool else tool_key
        viewer = _ImageGalleryViewer(f"{name} — Screenshots", images, parent=self)
        self._output_viewers.append(viewer)
        viewer.finished.connect(
            lambda _=None, v=viewer: self._output_viewers.remove(v) if v in self._output_viewers else None
        )
        viewer.show()

    def _stop_tool(self, tool_key: str):
        if self._executor and self._executor.isRunning():
            self._executor.stop_tool(tool_key)

    def _stop_stage(self, stage_num: int):
        if not self._executor or not self._executor.isRunning():
            return
        tmpl = self._current_template()
        if not tmpl:
            return
        for step in tmpl.steps:
            if step.stage == stage_num:
                self._executor.stop_tool(step.tool_key)

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
            tw = self._find_target_window()
            if tw is not None:
                tw._resultsWindow.load_session(sid, self._repo)
                tw.OpenResultsWindow()
            else:
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

    def _on_session_started(self, session_id: str):
        """Fires as soon as the live executor knows its session id — before that,
        self._current_session_id stays "" for a fresh run (it used to only get
        set in _on_pipeline_done), which made the rerun/rerun-stage/rerun-selected
        buttons silently no-op ("Select a session first") for the entire
        duration of a pipeline's first run."""
        self._current_session_id = session_id

    def _on_step_done(self, key: str, status: str, count: int):
        self._monitor.on_done(key, status, count)
        icon = {"completed": "✓", "skipped": "⏭", "failed": "✗", "stopped": "⏹"}.get(status, "?")
        self._log(f"  [{key}] {icon} {status}  ({count})")

    def _on_pipeline_done(self, session_id: str, success: bool, message: str):
        self._current_session_id = session_id
        was_stopped = not success and bool(
            self._executor and self._executor._stop_event.is_set()
        )
        if success:
            icon, label = "✓", "Done"
        elif was_stopped:
            icon, label = "⏹", "Stopped"
        else:
            icon, label = "✗", "Failed"
        self._log(f"\n{icon} Pipeline {label} — {message}")
        self._stageLabel.setText(f"{icon} {label}: {message}")
        self._runBtn.setEnabled(True)
        self._initBtn.setEnabled(True)
        self._stopBtn.setEnabled(False)
        self._retryBtn.setEnabled(True)
        self._resumeBtn.setEnabled(was_stopped or not success)
        self._monitor.set_running(False)

        rerun_key   = getattr(self, "_last_rerun_key", None)
        self._last_rerun_key = None
        rerun_lines = list(self._monitor._log_buffer.get(rerun_key, [])) if rerun_key else []

        self._refresh_sessions()

        if rerun_key and rerun_lines:
            self._monitor.show_tool_logs(rerun_key, rerun_lines)

        _notify(f"AWE — Pipeline {label.lower()}", message)

    # ── Session history ───────────────────────────────────────────────────────

    def _refresh_sessions(self):
        prev_sid = self._current_session_id
        self._sessionList.clear()
        self._stale_session_ids: set[str] = set()
        try:
            sessions = self._repo.list_sessions(100)
        except Exception:
            return
        # Block signals while repopulating so that addItem on an empty list
        # does not fire currentItemChanged for the first item added, which
        # would trigger _load_session_into_ui prematurely and clear
        # _last_rerun_key before the intended setCurrentRow call below.
        self._sessionList.blockSignals(True)
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
        self._sessionList.blockSignals(False)

        # Restore the previously selected session.
        # Keep signals blocked for setCurrentRow too: if the session is at
        # index 0 Qt may have already set it as current (from the first addItem
        # while signals were blocked), so setCurrentRow(0) would be a no-op and
        # currentItemChanged would never fire.  Call _load_session_into_ui
        # directly instead so the monitor always refreshes.
        if prev_sid:
            for i in range(self._sessionList.count()):
                if self._sessionList.item(i).data(Qt.UserRole) == prev_sid:
                    self._sessionList.blockSignals(True)
                    self._sessionList.setCurrentRow(i)
                    self._sessionList.blockSignals(False)
                    self._current_session_id = prev_sid
                    self._load_session_into_ui(prev_sid)
                    break

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
            session_status = (self._repo.get_session(sid) or {}).get("status", "")
            resumable = (is_stale or session_status in ("stopped", "failed")) and not running
            self._resumeBtn.setEnabled(resumable)
            self._load_session_into_ui(sid)

    def _load_session_into_ui(self, session_id: str):
        """Populate Config, Monitor, and Log tabs with a historical session."""
        session_doc = self._repo.get_session(session_id)
        if not session_doc:
            return
        running = self._monitor._is_running

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
                    # A tool still marked "running" means the app was closed mid-run;
                    # the container is gone, so display it as stopped.
                    if status == "running":
                        status = "stopped"
                    self._monitor.on_done(key, status, count)
            try:
                tool_logs = self._repo.get_tool_run_logs(session_id)
                for key, lines in tool_logs.items():
                    if lines:
                        self._monitor.set_tool_log(key, lines)
            except Exception:
                pass
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

    def _find_target_window(self):
        """Walk the parent chain to find the TargetWindow that owns us."""
        ancestor = self.parent()
        while ancestor is not None:
            if hasattr(ancestor, "_switch_page") and hasattr(ancestor, "OpenResultsWindow"):
                return ancestor
            ancestor = ancestor.parent()
        return None

    def _open_results(self):
        tw = self._find_target_window()
        if tw is not None:
            if self._current_session_id:
                tw._resultsWindow.load_session(self._current_session_id, self._repo)
            tw.OpenResultsWindow()
            return
        # Fallback when not embedded in TargetWindow
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
        tw = self._find_target_window()
        if tw is not None:
            tw._switch_page(13)
            return
        # Fallback when not embedded in TargetWindow (e.g. standalone)
        dlg = SettingsWindow(self._project_dir, _MONGO_URI, parent=self)
        dlg.exec()

    # ── MongoDB startup ───────────────────────────────────────────────────────

    def _start_mongo(self):
        self._mongoStatus.setText("⬤ connecting…")
        self._mongoStatus.setStyleSheet("color: #F9E2AF;")
        self._mongoThread = _MongoStarter(self)
        self._mongoThread.done.connect(self._on_mongo_ready)
        register_monitored_thread(self._mongoThread, self, "Pipeline Mongo Starter")
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
            self._initBtn.setEnabled(False)

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
