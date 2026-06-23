"""
HttpHistoryPage — chronological log of every proxied request.

Shows ALL requests (no deduplication) in a table sorted oldest-first.
Clicking a row loads the full request/response in the pane below.
Filter by scope is ON by default.
Data comes from MongoDB (awe_proxy_traffic.traffic).

Columns:  #  |  Method  |  Host  |  Path  |  Status  |  Length
"""
from __future__ import annotations

import logging

from bson import ObjectId
from PySide6.QtCore import Qt, QTimer, QPoint, Signal, QEvent
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QFrame,
    QPushButton, QLabel, QTableWidget, QTableWidgetItem,
    QTabWidget, QTextEdit, QHeaderView, QAbstractItemView, QMenu, QToolTip, QDialog,
    QApplication,
)

from database.scope import ScopeConfig
from gui.guiUtilities import (
    SyntaxHighlighter, format_http_body, SearchBar,
    decode_text, DecodeDialog,
    parse_http_headers, set_header_clipboard, HeaderSelectorDialog,
)

log = logging.getLogger(__name__)

_COLS = ["#", "Method", "Host", "Path", "Status", "Length"]


def _status_color(code) -> str:
    try:
        c = int(code)
    except (TypeError, ValueError):
        return "#6C7086"
    if 200 <= c < 300: return "#A6E3A1"
    if 300 <= c < 400: return "#89B4FA"
    if 400 <= c < 500: return "#F9E2AF"
    if 500 <= c < 600: return "#F38BA8"
    return "#6C7086"


class HttpHistoryPage(QWidget):
    send_to_repeater   = Signal(str)
    send_to_intruder   = Signal(str)
    send_to_websocket  = Signal(str, str)   # (host, path)
    traffic_changed    = Signal()

    def __init__(self, proxy_col, repository=None, parent=None):
        super().__init__(parent)
        self._col          = proxy_col   # pymongo Collection or None
        self._repo         = repository
        self._scope        = ScopeConfig()
        self._filter_scope = True
        self._last_count   = -1
        # (timestamp_str, doc_id_str) per visible row
        self._rows: list[tuple[str, str]] = []

        self._build_ui()
        self._scope_btn.setChecked(True)
        self._load_scope()
        self._refresh_table()
        self._start_poll_timer()

    # ── public ────────────────────────────────────────────────────────────────

    def on_scope_changed(self, config: ScopeConfig) -> None:
        self._scope = config
        if self._filter_scope:
            self._refresh_table()

    def refresh(self) -> None:
        self._load_scope()
        self._refresh_table()

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # toolbar
        tb = QHBoxLayout()
        tb.setContentsMargins(8, 6, 8, 6)
        tb.setSpacing(10)
        title = QLabel("HTTP History")
        title.setStyleSheet("color:#CDD6F4; font-weight:bold; font-size:11px;")
        tb.addWidget(title)
        tb.addStretch()

        self._count_lbl = QLabel("0 requests")
        self._count_lbl.setStyleSheet("color:#6C7086; font-size:9px;")
        tb.addWidget(self._count_lbl)

        self._scope_btn = QPushButton("Filter by Scope: ON")
        self._scope_btn.setCheckable(True)
        self._scope_btn.setFixedHeight(24)
        self._scope_btn.setStyleSheet(_TOGGLE_SS_ON)
        self._scope_btn.toggled.connect(self._on_scope_toggle)
        tb.addWidget(self._scope_btn)

        ref_btn = QPushButton("Refresh")
        ref_btn.setFixedHeight(24)
        ref_btn.setStyleSheet(_BTN_SS)
        ref_btn.clicked.connect(self.refresh)
        tb.addWidget(ref_btn)
        root.addLayout(tb)

        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setFixedHeight(1)
        sep.setStyleSheet("background:#313244; border:none;")
        root.addWidget(sep)

        splitter = QSplitter(Qt.Vertical)
        splitter.setChildrenCollapsible(False)
        splitter.setStyleSheet("QSplitter::handle{background:#313244;height:3px;}")

        # table
        self._table = QTableWidget(0, len(_COLS))
        self._table.setHorizontalHeaderLabels(_COLS)
        self._table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SingleSelection)
        self._table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        self._table.horizontalHeader().setStretchLastSection(False)
        self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self._table.setShowGrid(False)
        self._table.setStyleSheet(
            "QTableWidget{background:#1E1E2E; alternate-background-color:#181825;"
            " color:#CDD6F4; border:none; gridline-color:#313244;}"
            "QTableWidget::item:selected{background:#313244; color:#CDD6F4;}"
            "QHeaderView::section{background:#181825; color:#6C7086;"
            " border:none; border-bottom:1px solid #313244; padding:4px 8px;"
            " font-size:9px;}"
        )
        for col, w in [(0, 45), (1, 65), (2, 200), (4, 55), (5, 70)]:
            self._table.setColumnWidth(col, w)
        self._table.currentCellChanged.connect(self._on_row_changed)
        self._table.setContextMenuPolicy(Qt.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._on_table_context_menu)
        splitter.addWidget(self._table)

        # req/resp pane
        rr = QWidget()
        rr_vb = QVBoxLayout(rr)
        rr_vb.setContentsMargins(0, 0, 0, 0)
        self._tabs = QTabWidget()
        self._tabs.setStyleSheet(
            "QTabBar::tab{background:#181825;color:#6C7086;padding:4px 12px;border:none;}"
            "QTabBar::tab:selected{background:#313244;color:#CDD6F4;}"
        )
        self._req_view  = _CodeView()
        self._resp_view = _CodeView()
        self._tabs.addTab(self._req_view,  "Request")
        self._tabs.addTab(self._resp_view, "Response")
        self._req_view.send_to_repeater.connect(self.send_to_repeater)
        self._req_view.send_to_intruder.connect(self.send_to_intruder)
        self._resp_view.send_to_repeater.connect(
            lambda _: self.send_to_repeater.emit(self._req_view.toPlainText()))
        self._resp_view.send_to_intruder.connect(
            lambda _: self.send_to_intruder.emit(self._req_view.toPlainText()))
        rr_vb.addWidget(self._tabs)

        self._search_bar = SearchBar(rr)
        self._search_bar.set_editor(self._req_view)
        rr_vb.addWidget(self._search_bar)

        self._tabs.currentChanged.connect(
            lambda _: self._search_bar.set_editor(self._tabs.currentWidget()))
        self._req_view.installEventFilter(self)
        self._resp_view.installEventFilter(self)

        splitter.addWidget(rr)

        splitter.setSizes([350, 300])
        root.addWidget(splitter, stretch=1)

    # ── table population ──────────────────────────────────────────────────────

    def _refresh_table(self) -> None:
        self._table.setRowCount(0)
        self._rows.clear()
        self._req_view.clear()
        self._resp_view.clear()

        if self._col is None:
            self._count_lbl.setText("database unavailable")
            return

        try:
            all_hosts = self._col.distinct("host")
        except Exception as exc:
            log.warning("History DB query failed: %s", exc)
            self._count_lbl.setText("DB error")
            return

        in_scope = [
            h for h in all_hosts
            if not self._filter_scope or self._scope.matches(h)
        ]
        if not in_scope:
            self._count_lbl.setText("0 requests")
            return

        try:
            cursor = self._col.find(
                {"host": {"$in": in_scope}},
                {"host": 1, "path": 1, "method": 1,
                 "status_code": 1, "timestamp": 1,
                 "response.body": 1},
                sort=[("timestamp", 1)],
            )
            docs = list(cursor)
        except Exception as exc:
            log.warning("History find failed: %s", exc)
            return

        self._table.setUpdatesEnabled(False)
        for seq, doc in enumerate(docs, start=1):
            ts     = doc.get("timestamp", "")
            host   = doc.get("host", "")
            path   = doc.get("path", "/")
            method = doc.get("method", "?")
            status = str(doc.get("status_code", "?"))
            body   = (doc.get("response") or {}).get("body", "")
            length = str(len(body.encode("utf-8", errors="replace"))) if body else "0"
            doc_id = str(doc["_id"])

            color = QColor(_status_color(status))
            row   = self._table.rowCount()
            self._table.insertRow(row)
            self._rows.append((ts, doc_id))

            for col, text in enumerate([str(seq), method, host, path, status, length]):
                cell = QTableWidgetItem(text)
                cell.setForeground(color if col == 4 else QColor("#CDD6F4"))
                if col == 1:
                    cell.setForeground(QColor("#89B4FA"))
                self._table.setItem(row, col, cell)
            self._table.setRowHeight(row, 22)

        self._table.setUpdatesEnabled(True)
        count = self._table.rowCount()
        self._count_lbl.setText(f"{count} request{'s' if count != 1 else ''}")

    # ── interactions ──────────────────────────────────────────────────────────

    def _load_doc(self, doc_id: str) -> dict | None:
        if not doc_id or self._col is None:
            return None
        try:
            return self._col.find_one({"_id": ObjectId(doc_id)})
        except Exception as exc:
            log.warning("Failed to load doc %s: %s", doc_id, exc)
            return None

    def _on_row_changed(self, row: int, *_) -> None:
        if row < 0 or row >= len(self._rows):
            return
        _, doc_id = self._rows[row]
        doc = self._load_doc(doc_id)
        if doc:
            self._req_view.setText(_fmt_request(doc.get("request", {})))
            self._resp_view.setText(_fmt_response(doc.get("response", {})))
            self._tabs.setCurrentIndex(0)

    def _on_table_context_menu(self, pos: QPoint) -> None:
        row = self._table.rowAt(pos.y())
        if row < 0 or row >= len(self._rows):
            return

        _, doc_id = self._rows[row]
        status_item = self._table.item(row, 4)
        is_ws = status_item is not None and status_item.text() == "101"

        menu       = QMenu(self)
        action     = menu.addAction("Send to Repeater")
        int_action = menu.addAction("Send to Intruder")
        ws_action  = None
        if is_ws:
            menu.addSeparator()
            ws_action = menu.addAction("View WebSocket")

        chosen = menu.exec(self._table.mapToGlobal(pos))
        doc = self._load_doc(doc_id)
        if not doc:
            return
        if chosen is action:
            self.send_to_repeater.emit(_fmt_request(doc.get("request", {})))
        elif chosen is int_action:
            self.send_to_intruder.emit(_fmt_request(doc.get("request", {})))
        elif ws_action and chosen is ws_action:
            req  = doc.get("request", {})
            host = req.get("host", doc.get("host", ""))
            path = req.get("path", "/")
            self.send_to_websocket.emit(host, path)

    def eventFilter(self, obj, event) -> bool:
        if (event.type() == QEvent.Type.KeyPress
                and event.modifiers() == Qt.ControlModifier
                and event.key() == Qt.Key_F):
            self._search_bar.set_editor(obj)
            self._search_bar.activate()
            return True
        return super().eventFilter(obj, event)

    def _on_scope_toggle(self, checked: bool) -> None:
        self._filter_scope = checked
        self._scope_btn.setText(f"Filter by Scope: {'ON' if checked else 'OFF'}")
        self._scope_btn.setStyleSheet(_TOGGLE_SS_ON if checked else _TOGGLE_SS_OFF)
        self._refresh_table()

    def _load_scope(self) -> None:
        if self._repo:
            try:
                self._scope = self._repo.get_scope()
            except Exception:
                pass

    # ── poll timer ────────────────────────────────────────────────────────────

    def _start_poll_timer(self) -> None:
        self._poll_timer = QTimer(self)
        self._poll_timer.setInterval(2000)
        self._poll_timer.timeout.connect(self._check_new_traffic)
        self._poll_timer.start()

    def _check_new_traffic(self) -> None:
        if self._col is None:
            return
        try:
            count = self._col.estimated_document_count()
        except Exception:
            return
        if count != self._last_count:
            self._last_count = count
            self._refresh_table()
            self.traffic_changed.emit()


# ── formatting ────────────────────────────────────────────────────────────────

def _fmt_body(doc: dict) -> str:
    body = doc.get("body", "")
    if not body:
        return ""
    if doc.get("body_encoding") == "base64":
        import base64 as _b64
        try:
            raw  = _b64.b64decode(body)
            size = len(raw)
        except Exception:
            size = len(body) * 3 // 4
        return f"[Binary content — {size:,} bytes, base64]\n{body}"
    return body


def _fmt_request(req: dict) -> str:
    lines = [f"{req.get('method','')} {req.get('url','')}"]
    for k, v in (req.get("headers", {}).items()):
        for val in ([v] if isinstance(v, str) else v):
            lines.append(f"{k}: {val}")
    body = _fmt_body(req)
    if body:
        lines += ["", body]
    return "\n".join(lines)


def _fmt_response(resp: dict) -> str:
    lines = [f"{resp.get('http_version','HTTP/1.1')} {resp.get('status_code','')} {resp.get('reason','')}"]
    for k, v in (resp.get("headers", {}).items()):
        for val in ([v] if isinstance(v, str) else v):
            lines.append(f"{k}: {val}")
    body = _fmt_body(resp)
    if body:
        lines += ["", body]
    return "\n".join(lines)


# ── shared styles ─────────────────────────────────────────────────────────────

_TOGGLE_SS_ON = (
    "QPushButton{background:#1E3A2F;color:#A6E3A1;border:1px solid #A6E3A1;"
    "border-radius:4px;padding:0 10px;font-size:9px;}"
    "QPushButton:hover{background:#2A4A3F;}"
)
_TOGGLE_SS_OFF = (
    "QPushButton{background:#313244;color:#6C7086;border:1px solid #45475A;"
    "border-radius:4px;padding:0 10px;font-size:9px;}"
    "QPushButton:hover{background:#45475A;color:#CDD6F4;}"
)
_BTN_SS = (
    "QPushButton{background:#313244;color:#6C7086;border:1px solid #45475A;"
    "border-radius:4px;padding:0 10px;font-size:9px;}"
    "QPushButton:hover{background:#45475A;color:#CDD6F4;}"
)


class _CodeView(QTextEdit):
    send_to_repeater = Signal(str)
    send_to_intruder = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setFont(QFont("Cascadia Code", 9))
        self.setStyleSheet(
            "QTextEdit{background:#11111B; color:#CDD6F4; border:none; padding:8px;}"
        )
        self._hl = SyntaxHighlighter(self.document())

    def contextMenuEvent(self, event):
        menu      = self.createStandardContextMenu()
        txt       = self.toPlainText()
        selected  = self.textCursor().selectedText().strip()
        has_text  = bool(txt.strip())
        has_body  = has_text and '\n\n' in txt and bool(txt.split('\n\n', 1)[-1].strip())
        has_sel   = bool(selected)

        menu.addSeparator()
        rep_act = menu.addAction("Send to Repeater")
        rep_act.setEnabled(has_text)
        int_act = menu.addAction("Send to Intruder")
        int_act.setEnabled(has_text)

        menu.addSeparator()
        fmt_menu = menu.addMenu("Format Body")
        fmt_menu.setEnabled(has_body)
        json_act = fmt_menu.addAction("JSON")
        xml_act  = fmt_menu.addAction("XML")
        html_act = fmt_menu.addAction("HTML")
        js_act   = fmt_menu.addAction("JavaScript")

        menu.addSeparator()
        dec_menu = menu.addMenu("Decode Selection")
        dec_menu.setEnabled(has_sel)
        dec_auto = dec_menu.addAction("Auto-detect")
        dec_menu.addSeparator()
        dec_b64  = dec_menu.addAction("Base64")
        dec_url  = dec_menu.addAction("URL")
        dec_html = dec_menu.addAction("HTML Entities")
        dec_hex  = dec_menu.addAction("Hex")
        dec_jwt  = dec_menu.addAction("JWT")
        dec_uni  = dec_menu.addAction("Unicode Escape")

        menu.addSeparator()
        copy_hdrs_menu = menu.addMenu("Copy Headers")
        copy_hdrs_menu.setEnabled(has_text)
        copy_all_act = copy_hdrs_menu.addAction("All Headers")
        copy_sel_act = copy_hdrs_menu.addAction("Select Headers…")
        copy_body_act = menu.addAction("Copy Body")
        copy_body_act.setEnabled(has_body)

        chosen = menu.exec(event.globalPos())
        fmt_map = {json_act: 'json', xml_act: 'xml', html_act: 'html', js_act: 'javascript'}
        dec_map = {dec_auto: 'auto', dec_b64: 'base64', dec_url: 'url',
                   dec_html: 'html', dec_hex: 'hex', dec_jwt: 'jwt', dec_uni: 'unicode'}

        if chosen is rep_act:
            self.send_to_repeater.emit(txt)
        elif chosen is int_act:
            self.send_to_intruder.emit(txt)
        elif chosen in fmt_map:
            result = format_http_body(txt, fmt_map[chosen])
            if result is not None:
                self.setPlainText(result)
        elif chosen in dec_map and has_sel:
            result, used = decode_text(selected, dec_map[chosen])
            if result is None:
                QToolTip.showText(event.globalPos(), f"Cannot decode as {used}")
            else:
                DecodeDialog(result, used, parent=self.window()).show()
        elif chosen is copy_all_act:
            hdrs = parse_http_headers(txt)
            set_header_clipboard(hdrs)
            QToolTip.showText(event.globalPos(),
                              f"Copied {len(hdrs)} header{'s' if len(hdrs) != 1 else ''}")
        elif chosen is copy_sel_act:
            hdrs = parse_http_headers(txt)
            if not hdrs:
                QToolTip.showText(event.globalPos(), "No headers found")
            else:
                dlg = HeaderSelectorDialog(hdrs, parent=self.window())
                if dlg.exec() == QDialog.DialogCode.Accepted:
                    sel = dlg.selected_headers()
                    if sel:
                        set_header_clipboard(sel)
                        QToolTip.showText(event.globalPos(),
                                          f"Copied {len(sel)} header{'s' if len(sel) != 1 else ''}")
        elif chosen is copy_body_act:
            body = txt.split('\n\n', 1)[-1]
            QApplication.clipboard().setText(body)
            QToolTip.showText(event.globalPos(), "Body copied")
