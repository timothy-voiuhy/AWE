"""
WebSocketPage — dedicated tool for inspecting and replaying WebSocket traffic.

Layout
──────
  ┌─ left (300 px) ──────────┐  ┌─ right (stretch) ────────────────────────┐
  │ [Refresh]  [Clear All]    │  │  Frame Log (QTableWidget)                │
  │ Connection list           │  │  ─── splitter ───────────────────────────│
  │  Host │ Path │ # │ Status │  │  Payload Viewer (_CodeEdit read-only)    │
  │                           │  │  ─── splitter ───────────────────────────│
  │                           │  │  Sender                                  │
  │                           │  │    URL input  [Connect] [Disconnect]     │
  │                           │  │    _CodeEdit (editable)                  │
  │                           │  │    [▶ Send Text]  [▶ Send Binary]        │
  └───────────────────────────┘  └──────────────────────────────────────────┘
"""
from __future__ import annotations

import asyncio
import json
import logging
import queue

import aiohttp
from PySide6.QtCore import Qt, QThread, QTimer, Signal
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QFrame, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QSplitter, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from gui.repeater import _CodeEdit
from proxy._ws_store import WSStore

log = logging.getLogger(__name__)


# ── Styling constants ─────────────────────────────────────────────────────────

_MONO   = QFont("Cascadia Code", 9)
_DARK   = "#1E1E2E"
_DARKER = "#11111B"
_PANEL  = "#181825"
_BORDER = "#313244"
_DIM    = "#6C7086"
_TEXT   = "#CDD6F4"

_BTN_SS = (
    "QPushButton{background:#313244;color:#CDD6F4;border:1px solid #45475A;"
    "border-radius:4px;padding:0 10px;min-height:24px;font-size:9px;}"
    "QPushButton:hover{background:#45475A;}"
    "QPushButton:disabled{background:#181825;color:#45475A;border-color:#313244;}"
)
_BTN_GREEN = (
    "QPushButton{background:#1E3A2F;color:#A6E3A1;border:1px solid #A6E3A1;"
    "border-radius:4px;padding:0 10px;min-height:24px;font-size:9px;font-weight:bold;}"
    "QPushButton:hover{background:#2A4A3F;}"
    "QPushButton:disabled{background:#181825;color:#45475A;border-color:#313244;}"
)
_BTN_RED = (
    "QPushButton{background:#3A1E1E;color:#F38BA8;border:1px solid #F38BA8;"
    "border-radius:4px;padding:0 10px;min-height:24px;font-size:9px;}"
    "QPushButton:hover{background:#4A2A2A;}"
    "QPushButton:disabled{background:#181825;color:#45475A;border-color:#313244;}"
)

# Frame row colours by opcode (used for text/preview columns)
_OPCODE_COLORS: dict[int, str] = {
    0x1: "#CDD6F4",   # text        → normal text
    0x2: "#89B4FA",   # binary      → blue
    0x8: "#F38BA8",   # close       → red
    0x9: "#6C7086",   # ping        → dim
    0xA: "#6C7086",   # pong        → dim
    0x0: "#585B70",   # continuation → muted
}

# Direction colours and row background tints
_DIR_UP_FG   = "#89B4FA"   # ↑ client→server arrow colour (blue)
_DIR_DOWN_FG = "#A6E3A1"   # ↓ server→client arrow colour (green)
_DIR_UP_BG   = "#16213e"   # subtle blue-tinted row background
_DIR_DOWN_BG = "#11111B"   # default dark (no tint for incoming)

_TABLE_SS = (
    "QTableWidget{background:#11111B;color:#CDD6F4;border:none;"
    "gridline-color:#313244;font-family:'Cascadia Code';font-size:9px;}"
    "QTableWidget::item:selected{background:#313244;color:#CDD6F4;}"
    "QHeaderView::section{background:#181825;color:#6C7086;border:none;"
    "border-bottom:1px solid #313244;font-size:9px;padding:2px 6px;}"
)


def _hline() -> QFrame:
    f = QFrame()
    f.setFrameShape(QFrame.HLine)
    f.setFixedHeight(1)
    f.setStyleSheet("background:#313244;border:none;")
    return f


# ── Live WebSocket client worker ──────────────────────────────────────────────

class _WSClientWorker(QThread):
    """
    Maintains a live WebSocket connection from the GUI.
    Routes through the AWE proxy so frames are also captured.
    """

    frame_received    = Signal(str, str)   # (direction "↑"/"↓", payload_text)
    connection_status = Signal(str)        # "connected" | "disconnected" | "error: ..."

    def __init__(self, url: str, proxy_port: int, parent=None):
        super().__init__(parent)
        self._url        = url
        self._proxy_port = proxy_port
        self._loop: asyncio.AbstractEventLoop | None = None
        self._send_q: asyncio.Queue | None = None
        self._stop = False

    def send(self, text: str) -> None:
        """Thread-safe: enqueue a text frame to be sent."""
        if self._loop and self._send_q:
            self._loop.call_soon_threadsafe(self._send_q.put_nowait, text)

    def stop(self) -> None:
        self._stop = True
        if self._loop and self._send_q:
            self._loop.call_soon_threadsafe(self._send_q.put_nowait, None)  # wake sender

    def run(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._main())
        finally:
            self._loop.close()

    async def _main(self) -> None:
        self._send_q = asyncio.Queue()
        proxy = f"http://127.0.0.1:{self._proxy_port}"
        try:
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.ws_connect(
                    self._url, proxy=proxy, ssl=False,
                ) as ws:
                    self.connection_status.emit("connected")

                    async def _sender():
                        while not self._stop:
                            try:
                                msg = await asyncio.wait_for(
                                    self._send_q.get(), timeout=0.5
                                )
                                if msg is None:
                                    break
                                await ws.send_str(msg)
                                self.frame_received.emit("↑", msg)
                            except asyncio.TimeoutError:
                                pass

                    async def _receiver():
                        async for msg in ws:
                            if self._stop:
                                break
                            if msg.type == aiohttp.WSMsgType.TEXT:
                                self.frame_received.emit("↓", msg.data)
                            elif msg.type == aiohttp.WSMsgType.BINARY:
                                self.frame_received.emit("↓", msg.data.hex())
                            elif msg.type in (aiohttp.WSMsgType.CLOSE,
                                              aiohttp.WSMsgType.ERROR):
                                break

                    await asyncio.gather(_sender(), _receiver(), return_exceptions=True)
        except Exception as exc:
            self.connection_status.emit(f"error: {exc}")
        finally:
            self.connection_status.emit("disconnected")


# ── Main page ─────────────────────────────────────────────────────────────────

class WebSocketPage(QWidget):
    def __init__(self, proxy_port: int = 8080, parent=None):
        super().__init__(parent)
        self._proxy_port  = proxy_port
        self._ws_store    = WSStore()         # read-only instance for the GUI
        self._conn_rows:  list[dict] = []     # current connection list
        self._frame_rows: list[dict] = []     # frames for selected connection
        self._current_conn_id: str  = ""
        self._worker: _WSClientWorker | None  = None
        self._live_conn_id: str = ""

        self._build_ui()

        self._timer = QTimer(self)
        self._timer.setInterval(3000)
        self._timer.timeout.connect(self._refresh_connections)
        self._timer.start()

    # ── UI construction ───────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        self.setStyleSheet(f"background:{_DARK};color:{_TEXT};")
        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(self._build_left())
        div = QFrame()
        div.setFixedWidth(1)
        div.setStyleSheet(f"background:{_BORDER};")
        root.addWidget(div)
        root.addWidget(self._build_right(), stretch=1)

    def _build_left(self) -> QWidget:
        w  = QWidget()
        w.setFixedWidth(300)
        w.setStyleSheet(f"background:{_PANEL};")
        vb = QVBoxLayout(w)
        vb.setContentsMargins(0, 0, 0, 0)
        vb.setSpacing(0)

        # toolbar
        tb = QHBoxLayout()
        tb.setContentsMargins(8, 6, 8, 6)
        tb.setSpacing(6)
        lbl = QLabel("WebSockets")
        lbl.setStyleSheet(f"color:{_TEXT};font-size:10px;font-weight:bold;background:transparent;")
        tb.addWidget(lbl)
        tb.addStretch()
        self._refresh_btn = QPushButton("Refresh")
        self._refresh_btn.setStyleSheet(_BTN_SS)
        self._refresh_btn.clicked.connect(self._refresh_connections)
        tb.addWidget(self._refresh_btn)
        self._clear_btn = QPushButton("Clear All")
        self._clear_btn.setStyleSheet(_BTN_SS)
        self._clear_btn.clicked.connect(self._clear_all)
        tb.addWidget(self._clear_btn)
        vb.addLayout(tb)
        vb.addWidget(_hline())

        # connection table
        self._conn_table = QTableWidget(0, 4)
        self._conn_table.setHorizontalHeaderLabels(["Host", "Path", "#", "Status"])
        self._conn_table.setFont(_MONO)
        self._conn_table.setStyleSheet(_TABLE_SS)
        self._conn_table.verticalHeader().setVisible(False)
        self._conn_table.setSelectionBehavior(QTableWidget.SelectRows)
        self._conn_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._conn_table.horizontalHeader().setStretchLastSection(True)
        self._conn_table.setColumnWidth(0, 110)
        self._conn_table.setColumnWidth(1, 90)
        self._conn_table.setColumnWidth(2, 35)
        self._conn_table.itemSelectionChanged.connect(self._on_connection_selected)
        vb.addWidget(self._conn_table, stretch=1)
        return w

    def _build_right(self) -> QWidget:
        w  = QWidget()
        vb = QVBoxLayout(w)
        vb.setContentsMargins(0, 0, 0, 0)
        vb.setSpacing(0)

        splitter = QSplitter(Qt.Vertical)
        splitter.setChildrenCollapsible(False)
        splitter.setStyleSheet(
            f"QSplitter::handle{{background:{_BORDER};height:3px;}}"
        )

        splitter.addWidget(self._build_frame_log())
        splitter.addWidget(self._build_payload_viewer())
        splitter.addWidget(self._build_sender())
        splitter.setSizes([280, 200, 220])

        vb.addWidget(splitter, stretch=1)
        return w

    def _build_frame_log(self) -> QWidget:
        w  = QWidget()
        vb = QVBoxLayout(w)
        vb.setContentsMargins(0, 0, 0, 0)
        vb.setSpacing(0)

        hdr = QLabel("  Frame Log")
        hdr.setFixedHeight(24)
        hdr.setStyleSheet(
            f"background:{_PANEL};color:{_DIM};font-size:9px;"
            f"border-bottom:1px solid {_BORDER};"
        )
        vb.addWidget(hdr)

        self._frame_table = QTableWidget(0, 5)
        self._frame_table.setHorizontalHeaderLabels(
            ["Dir", "Opcode", "Length", "Preview", "Time"]
        )
        self._frame_table.setFont(_MONO)
        self._frame_table.setStyleSheet(_TABLE_SS)
        self._frame_table.verticalHeader().setVisible(False)
        self._frame_table.setSelectionBehavior(QTableWidget.SelectRows)
        self._frame_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._frame_table.horizontalHeader().setStretchLastSection(True)
        self._frame_table.setColumnWidth(0, 32)
        self._frame_table.setColumnWidth(1, 90)
        self._frame_table.setColumnWidth(2, 60)
        self._frame_table.setColumnWidth(4, 80)
        self._frame_table.itemSelectionChanged.connect(self._on_frame_selected)
        vb.addWidget(self._frame_table, stretch=1)
        return w

    def _build_payload_viewer(self) -> QWidget:
        w  = QWidget()
        vb = QVBoxLayout(w)
        vb.setContentsMargins(0, 0, 0, 0)
        vb.setSpacing(0)

        hdr = QLabel("  Payload")
        hdr.setFixedHeight(24)
        hdr.setStyleSheet(
            f"background:{_PANEL};color:{_DIM};font-size:9px;"
            f"border-bottom:1px solid {_BORDER};"
        )
        vb.addWidget(hdr)

        self._payload_view = _CodeEdit(read_only=True)
        vb.addWidget(self._payload_view, stretch=1)
        return w

    def _build_sender(self) -> QWidget:
        w  = QWidget()
        w.setStyleSheet(f"background:{_PANEL};")
        vb = QVBoxLayout(w)
        vb.setContentsMargins(0, 0, 0, 0)
        vb.setSpacing(0)

        # header bar
        hdr = QLabel("  Sender")
        hdr.setFixedHeight(24)
        hdr.setStyleSheet(
            f"background:{_PANEL};color:{_DIM};font-size:9px;"
            f"border-bottom:1px solid {_BORDER};"
        )
        vb.addWidget(hdr)

        # URL row
        url_row = QHBoxLayout()
        url_row.setContentsMargins(8, 6, 8, 4)
        url_row.setSpacing(6)
        self._url_edit = QLineEdit()
        self._url_edit.setPlaceholderText("wss://host/path")
        self._url_edit.setObjectName("urlText")
        self._url_edit.setFont(_MONO)
        url_row.addWidget(self._url_edit, stretch=1)

        self._connect_btn = QPushButton("Connect")
        self._connect_btn.setStyleSheet(_BTN_GREEN)
        self._connect_btn.clicked.connect(self._on_connect)
        url_row.addWidget(self._connect_btn)

        self._disconnect_btn = QPushButton("Disconnect")
        self._disconnect_btn.setStyleSheet(_BTN_RED)
        self._disconnect_btn.setEnabled(False)
        self._disconnect_btn.clicked.connect(self._on_disconnect)
        url_row.addWidget(self._disconnect_btn)

        self._status_lbl = QLabel("Disconnected")
        self._status_lbl.setStyleSheet(
            f"color:{_DIM};font-size:9px;background:transparent;"
        )
        url_row.addWidget(self._status_lbl)
        vb.addLayout(url_row)

        # editor
        self._sender_edit = _CodeEdit(read_only=False)
        self._sender_edit.setMaximumHeight(80)
        vb.addWidget(self._sender_edit)

        # send buttons
        send_row = QHBoxLayout()
        send_row.setContentsMargins(8, 4, 8, 6)
        send_row.setSpacing(6)
        send_row.addStretch()

        self._send_text_btn = QPushButton("▶  Send Text")
        self._send_text_btn.setStyleSheet(_BTN_GREEN)
        self._send_text_btn.setEnabled(False)
        self._send_text_btn.clicked.connect(self._on_send_text)
        send_row.addWidget(self._send_text_btn)

        self._send_bin_btn = QPushButton("▶  Send Binary (hex)")
        self._send_bin_btn.setStyleSheet(_BTN_SS)
        self._send_bin_btn.setEnabled(False)
        self._send_bin_btn.clicked.connect(self._on_send_binary)
        send_row.addWidget(self._send_bin_btn)

        vb.addLayout(send_row)
        return w

    # ── Connection list ───────────────────────────────────────────────────────

    def _refresh_connections(self) -> None:
        conns = self._ws_store.list_connections()
        self._conn_rows = conns

        prev_id = self._current_conn_id
        self._conn_table.setRowCount(len(conns))
        new_frame_count = 0
        for r, c in enumerate(conns):
            status = "Open" if c.get("closed_at") is None else "Closed"
            color  = "#A6E3A1" if status == "Open" else _DIM
            cells  = [c.get("host",""), c.get("path","/"),
                      str(c.get("frame_count", 0)), status]
            for col, text in enumerate(cells):
                item = QTableWidgetItem(text)
                item.setForeground(QColor(color if col == 3 else _TEXT))
                self._conn_table.setItem(r, col, item)

            if c.get("id") == prev_id:
                self._conn_table.selectRow(r)
                new_frame_count = c.get("frame_count", 0)

        # Auto-update frame log when new frames arrive for the selected connection
        if prev_id and new_frame_count != len(self._frame_rows):
            self._load_frames(prev_id)

    def _on_connection_selected(self) -> None:
        rows = self._conn_table.selectedItems()
        if not rows:
            return
        row_idx = self._conn_table.currentRow()
        if row_idx < 0 or row_idx >= len(self._conn_rows):
            return
        conn = self._conn_rows[row_idx]
        conn_id = conn.get("id", "")
        if conn_id == self._current_conn_id:
            return
        self._current_conn_id = conn_id
        host = conn.get("host", "")
        path = conn.get("path", "/")
        self._url_edit.setText(f"wss://{host}{path}")
        self._load_frames(conn_id)

    def _load_frames(self, conn_id: str) -> None:
        frames = self._ws_store.get_frames(conn_id)
        self._frame_rows = frames
        self._frame_table.setRowCount(len(frames))
        for r, f in enumerate(frames):
            self._set_frame_row(r, f)
        if frames:
            self._frame_table.scrollToBottom()

    def _set_frame_row(self, r: int, f: dict) -> None:
        direction  = f.get("direction", "?")
        opcode     = f.get("opcode", 0)
        is_up      = direction == "↑"
        dir_fg     = QColor(_DIR_UP_FG   if is_up else _DIR_DOWN_FG)
        row_bg     = QColor(_DIR_UP_BG   if is_up else _DIR_DOWN_BG)
        text_color = QColor(_OPCODE_COLORS.get(opcode, _TEXT))
        ts         = f.get("timestamp", "")[-8:-1]
        preview    = f.get("payload_text", "")[:80].replace("\n", " ")
        cells = [
            (direction,                    dir_fg,     row_bg),
            (f.get("opcode_name", ""),     text_color, row_bg),
            (str(f.get("payload_len", 0)), text_color, row_bg),
            (preview,                      text_color, row_bg),
            (ts,                           QColor(_DIM), row_bg),
        ]
        for col, (text, fg, bg) in enumerate(cells):
            item = QTableWidgetItem(text)
            item.setForeground(fg)
            item.setBackground(bg)
            self._frame_table.setItem(r, col, item)

    def _on_frame_selected(self) -> None:
        rows = self._frame_table.selectedItems()
        if not rows:
            return
        row_idx = self._frame_table.currentRow()
        if row_idx < 0 or row_idx >= len(self._frame_rows):
            return
        frame = self._frame_rows[row_idx]
        text  = frame.get("payload_text", "")
        # Pretty-print JSON if possible
        try:
            parsed = json.loads(text)
            text   = json.dumps(parsed, indent=2, ensure_ascii=False)
        except Exception:
            pass
        self._payload_view.setPlainText(text)

    # ── Public API ────────────────────────────────────────────────────────────

    def load_connection(self, host: str, path: str) -> None:
        """Called from History 'View WebSocket' — select matching connection."""
        self._refresh_connections()
        for r, c in enumerate(self._conn_rows):
            if c.get("host") == host and c.get("path") == path:
                self._conn_table.selectRow(r)
                return
        # Connection not yet visible — pre-fill URL for sender
        self._url_edit.setText(f"wss://{host}{path}")

    # ── Sender ────────────────────────────────────────────────────────────────

    def _on_connect(self) -> None:
        url = self._url_edit.text().strip()
        if not url:
            return
        if self._worker and self._worker.isRunning():
            return
        self._worker = _WSClientWorker(url, self._proxy_port, parent=self)
        self._worker.frame_received.connect(self._on_live_frame)
        self._worker.connection_status.connect(self._on_connection_status)
        self._worker.start()

    def _on_disconnect(self) -> None:
        if self._worker:
            self._worker.stop()

    def _on_send_text(self) -> None:
        if self._worker:
            self._worker.send(self._sender_edit.toPlainText())

    def _on_send_binary(self) -> None:
        if not self._worker:
            return
        hex_text = self._sender_edit.toPlainText().replace(" ", "").replace("\n", "")
        try:
            payload = bytes.fromhex(hex_text)
            self._worker.send(payload.decode("latin-1"))  # send raw bytes as text frame for now
        except ValueError:
            self._status_lbl.setText("Invalid hex")

    def _on_live_frame(self, direction: str, payload: str) -> None:
        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).isoformat()[-8:-1]
        frame = {
            "direction":    direction,
            "opcode":       0x1,
            "opcode_name":  "text",
            "payload_text": payload,
            "payload_len":  len(payload),
            "timestamp":    ts,
        }
        row = self._frame_table.rowCount()
        self._frame_table.insertRow(row)
        self._set_frame_row(row, frame)
        self._frame_table.scrollToBottom()
        self._frame_rows.append(frame)

    def _on_connection_status(self, status: str) -> None:
        connected = status == "connected"
        self._connect_btn.setEnabled(not connected)
        self._disconnect_btn.setEnabled(connected)
        self._send_text_btn.setEnabled(connected)
        self._send_bin_btn.setEnabled(connected)
        color = "#A6E3A1" if connected else ("#F38BA8" if "error" in status else _DIM)
        self._status_lbl.setStyleSheet(
            f"color:{color};font-size:9px;background:transparent;"
        )
        self._status_lbl.setText(status.capitalize())

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _clear_all(self) -> None:
        self._ws_store.clear_all()
        self._conn_rows.clear()
        self._frame_rows.clear()
        self._current_conn_id = ""
        self._conn_table.setRowCount(0)
        self._frame_table.setRowCount(0)
        self._payload_view.setPlainText("")
