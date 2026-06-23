"""
InterceptPage — real-time HTTP request intercept and edit.

Layout
──────
  toolbar: [Enable] toggle  |  scope hint  |  pending-count label
  ┌─ left (280 px) ──────────┐  ┌─ right (stretch) ────────────────┐
  │ Pending queue table       │  │  _CodeEdit (editable)            │
  │  # │ Method │ Host │ Path │  │  ──────────────────────────────  │
  │                            │  │  [▶ Forward]   [✕ Drop]        │
  └────────────────────────────┘  └──────────────────────────────────┘
"""
from __future__ import annotations

import base64
import logging
from pathlib import Path

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QApplication, QFrame, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QSplitter, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QWidget,
)

from gui.repeater import _CodeEdit

log = logging.getLogger(__name__)

_MONO  = QFont("Cascadia Code", 9)
_DARK  = "#1E1E2E"
_PANEL = "#181825"
_BORD  = "#313244"
_DIM   = "#6C7086"
_TEXT  = "#CDD6F4"
_GREEN = "#A6E3A1"
_RED   = "#F38BA8"
_YELL  = "#F9E2AF"

_BTN = (
    "QPushButton{background:#313244;color:#CDD6F4;border:1px solid #45475A;"
    "border-radius:4px;padding:0 10px;min-height:24px;font-size:9px;}"
    "QPushButton:hover{background:#45475A;}"
    "QPushButton:disabled{background:#181825;color:#45475A;border-color:#313244;}"
)
_BTN_GREEN = (
    "QPushButton{background:#1E3A2F;color:#A6E3A1;border:1px solid #A6E3A1;"
    "border-radius:4px;padding:0 12px;min-height:26px;font-size:9px;font-weight:bold;}"
    "QPushButton:hover{background:#2A4A3F;}"
    "QPushButton:disabled{background:#181825;color:#45475A;border-color:#313244;}"
)
_BTN_RED = (
    "QPushButton{background:#3A1E1E;color:#F38BA8;border:1px solid #F38BA8;"
    "border-radius:4px;padding:0 12px;min-height:26px;font-size:9px;}"
    "QPushButton:hover{background:#4A2A2A;}"
    "QPushButton:disabled{background:#181825;color:#45475A;border-color:#313244;}"
)
_TABLE_SS = (
    "QTableWidget{background:#11111B;color:#CDD6F4;border:none;"
    "gridline-color:#313244;font-family:'Cascadia Code';font-size:9px;}"
    "QTableWidget::item:selected{background:#313244;color:#CDD6F4;}"
    "QHeaderView::section{background:#181825;color:#6C7086;border:none;"
    "border-bottom:1px solid #313244;font-size:9px;padding:2px 6px;}"
)
_TOGGLE_ON = (
    "QPushButton{background:#1E3A2F;color:#A6E3A1;border:1px solid #A6E3A1;"
    "border-radius:4px;padding:0 12px;min-height:26px;font-size:9px;font-weight:bold;}"
    "QPushButton:hover{background:#2A4A3F;}"
)
_TOGGLE_OFF = (
    "QPushButton{background:#313244;color:#6C7086;border:1px solid #45475A;"
    "border-radius:4px;padding:0 12px;min-height:26px;font-size:9px;}"
    "QPushButton:hover{background:#45475A;}"
)


def _hline() -> QFrame:
    f = QFrame()
    f.setFrameShape(QFrame.HLine)
    f.setFixedHeight(1)
    f.setStyleSheet(f"background:{_BORD};border:none;")
    return f


class InterceptPage(QWidget):
    def __init__(self, proxy_port: int = 8080, parent=None):
        super().__init__(parent)
        self._proxy_port = proxy_port
        self._enabled    = False
        self._pending:   list[dict] = []        # latest snapshot from proxy
        self._current_req_id: str   = ""

        self._build_ui()

        self._poll_timer = QTimer(self)
        self._poll_timer.setInterval(250)
        self._poll_timer.timeout.connect(self._poll)
        self._poll_timer.start()

    # ── UI ─────────────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        self.setStyleSheet(f"background:{_DARK};color:{_TEXT};")
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(self._build_toolbar())
        root.addWidget(_hline())

        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)
        body.addWidget(self._build_queue())
        div = QFrame()
        div.setFixedWidth(1)
        div.setStyleSheet(f"background:{_BORD};")
        body.addWidget(div)
        body.addWidget(self._build_editor(), stretch=1)

        body_widget = QWidget()
        body_widget.setLayout(body)
        root.addWidget(body_widget, stretch=1)

    def _build_toolbar(self) -> QWidget:
        tb = QWidget()
        tb.setFixedHeight(42)
        tb.setStyleSheet(f"background:{_PANEL};")
        hl = QHBoxLayout(tb)
        hl.setContentsMargins(12, 0, 12, 0)
        hl.setSpacing(10)

        self._toggle_btn = QPushButton("Intercept: OFF")
        self._toggle_btn.setStyleSheet(_TOGGLE_OFF)
        self._toggle_btn.setFixedHeight(28)
        self._toggle_btn.clicked.connect(self._toggle_intercept)
        hl.addWidget(self._toggle_btn)

        hl.addWidget(QLabel("Scope regex (empty = all):"))
        self._scope_edit = QLineEdit()
        self._scope_edit.setPlaceholderText("e.g.  example\\.com")
        self._scope_edit.setFont(_MONO)
        self._scope_edit.setStyleSheet(
            f"QLineEdit{{background:#1E1E2E;color:{_TEXT};border:1px solid {_BORD};"
            f"border-radius:3px;padding:2px 6px;font-size:9px;}}"
        )
        self._scope_edit.setFixedHeight(26)
        hl.addWidget(self._scope_edit, stretch=1)

        self._count_lbl = QLabel("0 pending")
        self._count_lbl.setStyleSheet(f"color:{_DIM};font-size:9px;background:transparent;")
        hl.addWidget(self._count_lbl)
        return tb

    def _build_queue(self) -> QWidget:
        w  = QWidget()
        w.setFixedWidth(280)
        w.setStyleSheet(f"background:{_PANEL};")
        vb = QVBoxLayout(w)
        vb.setContentsMargins(0, 0, 0, 0)
        vb.setSpacing(0)

        hdr = QLabel("  Pending Requests")
        hdr.setFixedHeight(24)
        hdr.setStyleSheet(
            f"background:{_PANEL};color:{_DIM};font-size:9px;"
            f"border-bottom:1px solid {_BORD};"
        )
        vb.addWidget(hdr)

        self._queue_table = QTableWidget(0, 3)
        self._queue_table.setHorizontalHeaderLabels(["Method", "Host", "Path"])
        self._queue_table.setFont(_MONO)
        self._queue_table.setStyleSheet(_TABLE_SS)
        self._queue_table.verticalHeader().setVisible(False)
        self._queue_table.setSelectionBehavior(QTableWidget.SelectRows)
        self._queue_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._queue_table.horizontalHeader().setStretchLastSection(True)
        self._queue_table.setColumnWidth(0, 60)
        self._queue_table.setColumnWidth(1, 110)
        self._queue_table.itemSelectionChanged.connect(self._on_row_selected)
        vb.addWidget(self._queue_table, stretch=1)
        return w

    def _build_editor(self) -> QWidget:
        w  = QWidget()
        vb = QVBoxLayout(w)
        vb.setContentsMargins(0, 0, 0, 0)
        vb.setSpacing(0)

        hdr = QLabel("  Request Editor")
        hdr.setFixedHeight(24)
        hdr.setStyleSheet(
            f"background:{_PANEL};color:{_DIM};font-size:9px;"
            f"border-bottom:1px solid {_BORD};"
        )
        vb.addWidget(hdr)

        self._editor = _CodeEdit(read_only=False)
        self._editor.setPlaceholderText("Select a pending request from the left panel…")
        vb.addWidget(self._editor, stretch=1)

        # action buttons
        vb.addWidget(_hline())
        btn_row = QHBoxLayout()
        btn_row.setContentsMargins(12, 6, 12, 6)
        btn_row.setSpacing(8)
        btn_row.addStretch()

        self._fwd_btn = QPushButton("▶  Forward")
        self._fwd_btn.setStyleSheet(_BTN_GREEN)
        self._fwd_btn.setEnabled(False)
        self._fwd_btn.clicked.connect(self._on_forward)
        btn_row.addWidget(self._fwd_btn)

        self._drop_btn = QPushButton("✕  Drop")
        self._drop_btn.setStyleSheet(_BTN_RED)
        self._drop_btn.setEnabled(False)
        self._drop_btn.clicked.connect(self._on_drop)
        btn_row.addWidget(self._drop_btn)

        btn_widget = QWidget()
        btn_widget.setStyleSheet(f"background:{_PANEL};")
        btn_widget.setLayout(btn_row)
        vb.addWidget(btn_widget)
        return w

    # ── polling ────────────────────────────────────────────────────────────────

    def _poll(self) -> None:
        if not self._enabled:
            return
        client = self._control_client()
        if client is None:
            return
        try:
            pending = client.get_pending_intercept()
        except Exception:
            return

        self._pending = pending
        self._count_lbl.setText(
            f"{len(pending)} pending" if pending else "0 pending"
        )
        self._count_lbl.setStyleSheet(
            f"color:{_YELL if pending else _DIM};font-size:9px;background:transparent;"
        )

        # Rebuild the queue table (preserve selection if req_id still exists)
        self._queue_table.blockSignals(True)
        self._queue_table.setRowCount(len(pending))
        prev_id    = self._current_req_id
        select_row = -1
        for r, req in enumerate(pending):
            cells = [req.get("method","?"), req.get("host","?"), req.get("url","?")]
            for col, txt in enumerate(cells):
                item = QTableWidgetItem(txt)
                item.setForeground(QColor(_YELL))
                self._queue_table.setItem(r, col, item)
            if req.get("id") == prev_id:
                select_row = r

        self._queue_table.blockSignals(False)
        if select_row >= 0:
            self._queue_table.selectRow(select_row)
        elif pending and not self._current_req_id:
            self._queue_table.selectRow(0)

    # ── selection / action ─────────────────────────────────────────────────────

    def _on_row_selected(self) -> None:
        row = self._queue_table.currentRow()
        if row < 0 or row >= len(self._pending):
            self._current_req_id = ""
            self._fwd_btn.setEnabled(False)
            self._drop_btn.setEnabled(False)
            return
        req = self._pending[row]
        self._current_req_id = req.get("id", "")
        self._fwd_btn.setEnabled(True)
        self._drop_btn.setEnabled(True)
        self._editor.setPlainText(_render_request(req))

    def _on_forward(self) -> None:
        req_id = self._current_req_id
        if not req_id:
            return
        client = self._control_client()
        if client is None:
            return
        raw   = self._editor.toPlainText()
        hdrs, body = _parse_raw_request(raw)
        body_b64   = base64.b64encode(body).decode()
        client.resolve_intercept(req_id, "forward", hdrs, body_b64)
        self._clear_editor()

    def _on_drop(self) -> None:
        req_id = self._current_req_id
        if not req_id:
            return
        client = self._control_client()
        if client is None:
            return
        client.resolve_intercept(req_id, "drop", [], "")
        self._clear_editor()

    def _clear_editor(self) -> None:
        self._current_req_id = ""
        self._editor.setPlainText("")
        self._fwd_btn.setEnabled(False)
        self._drop_btn.setEnabled(False)

    # ── intercept toggle ──────────────────────────────────────────────────────

    def _toggle_intercept(self) -> None:
        self._enabled = not self._enabled
        client = self._control_client()
        scope  = self._scope_edit.text().strip()
        patterns = [scope] if scope else []
        if client:
            client.set_intercept(self._enabled, patterns)
        if self._enabled:
            self._toggle_btn.setText("Intercept: ON")
            self._toggle_btn.setStyleSheet(_TOGGLE_ON)
        else:
            self._toggle_btn.setText("Intercept: OFF")
            self._toggle_btn.setStyleSheet(_TOGGLE_OFF)
            self._queue_table.setRowCount(0)
            self._clear_editor()
            self._count_lbl.setText("0 pending")
            self._count_lbl.setStyleSheet(
                f"color:{_DIM};font-size:9px;background:transparent;"
            )

    # ── helpers ────────────────────────────────────────────────────────────────

    def _control_client(self):
        try:
            from proxy._control import ControlClient
            from config.config import RUNDIR
            port_file = Path(RUNDIR) / "tmp" / "proxy_control.txt"
            port = int(port_file.read_text().strip())
            return ControlClient(port)
        except Exception:
            return None


# ── request serialisation / parsing ──────────────────────────────────────────

def _render_request(req: dict) -> str:
    """Convert a pending-request dict to editable HTTP text."""
    method = req.get("method", "GET")
    url    = req.get("url", "/")
    # Show just path for the request line (server already known from CONNECT)
    from urllib.parse import urlsplit
    parsed = urlsplit(url)
    path   = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    lines = [f"{method} {path} HTTP/1.1"]
    for k, v in req.get("headers", []):
        lines.append(f"{k}: {v}")

    body_b64 = req.get("body_b64", "")
    if body_b64:
        try:
            body = base64.b64decode(body_b64).decode("utf-8", errors="replace")
        except Exception:
            body = ""
        if body:
            lines += ["", body]
    return "\n".join(lines)


def _parse_raw_request(text: str) -> tuple[list[list[str]], bytes]:
    """
    Parse the editor text back into headers list and body bytes.
    Returns ([[name, value], ...], body_bytes).
    """
    if "\n\n" in text:
        head, _, body_str = text.partition("\n\n")
    else:
        head, body_str = text, ""

    lines   = head.splitlines()
    headers = []
    for line in lines[1:]:   # skip request line
        if ":" in line:
            k, _, v = line.partition(":")
            headers.append([k.strip(), v.strip()])

    body = body_str.encode("utf-8", errors="replace")
    return headers, body
