"""
HttpHistoryPage — chronological log of every proxied request.

Shows ALL requests (no deduplication) in a table sorted oldest-first.
Clicking a row loads the full request/response in the pane below.
Filter by scope is ON by default.
Data comes from MongoDB (awe_proxy_traffic.traffic).

Columns:  #  |  Type  |  Method  |  Host  |  Path  |  Status  |  Length
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
from gui.appearance import load_ui_settings, save_ui_settings
from gui.filterPanel import (
    FilterPanel, _status_cat, _status_color, _file_type, _looks_like_rsc,
    _RSC_LINE_RE,
)
from gui.guiUtilities import (
    SyntaxHighlighter, format_http_body, SearchBar,
    decode_text, DecodeDialog,
    parse_http_headers, set_header_clipboard, HeaderSelectorDialog,
    ResponseRenderView,
)

log = logging.getLogger(__name__)

_COLS = ["#", "Type", "Method", "Host", "Path", "Status", "Length"]
_COL_SEQ    = 0
_COL_TYPE   = 1
_COL_METHOD = 2
_COL_HOST   = 3
_COL_PATH   = 4
_COL_STATUS = 5
_COL_LEN    = 6

_SSE_FG  = "#CBA6F7"
_SSE_ROW = "#1E1A2E"
_RSC_FG  = "#89DCEB"
_RSC_ROW = "#0F1F22"


# ── Main page ─────────────────────────────────────────────────────────────────

class HttpHistoryPage(QWidget):
    send_to_repeater        = Signal(str)
    send_to_intruder        = Signal(str)
    send_to_websocket       = Signal(str, str)
    send_to_decoder         = Signal(str)
    send_to_comparer_left   = Signal(str)
    send_to_comparer_right  = Signal(str)
    send_to_jwt             = Signal(str)
    traffic_changed         = Signal()

    def __init__(self, proxy_col, repository=None, parent=None):
        super().__init__(parent)
        self._col          = proxy_col
        self._repo         = repository
        self._scope        = ScopeConfig()
        self._filter_scope = True
        self._last_count   = -1
        self._rows: list[tuple[str, str]] = []

        self._build_ui()
        self._scope_btn.setChecked(True)
        self._load_scope()
        self._restore_saved_filters()
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

        # ── Toolbar ───────────────────────────────────────────────────────────
        tb = QHBoxLayout()
        tb.setContentsMargins(8, 6, 8, 6)
        tb.setSpacing(8)

        title = QLabel("HTTP History")
        title.setStyleSheet("color:#CDD6F4; font-weight:bold; font-size:11px;")
        tb.addWidget(title)
        tb.addStretch()

        self._count_lbl = QLabel("0 requests")
        self._count_lbl.setStyleSheet("color:#6C7086; font-size:9px;")
        tb.addWidget(self._count_lbl)

        self._filter_active_lbl = QLabel("")
        self._filter_active_lbl.setStyleSheet(
            "color:#F9E2AF; font-size:9px; background:#2A2A1A;"
            " border:1px solid #45475A; border-radius:3px; padding:0 6px;"
        )
        self._filter_active_lbl.setVisible(False)
        tb.addWidget(self._filter_active_lbl)

        self._scope_btn = QPushButton("Scope: ON")
        self._scope_btn.setCheckable(True)
        self._scope_btn.setFixedHeight(24)
        self._scope_btn.setStyleSheet(_TOGGLE_SS_ON)
        self._scope_btn.toggled.connect(self._on_scope_toggle)
        tb.addWidget(self._scope_btn)

        self._filter_btn = QPushButton("Filters ▾")
        self._filter_btn.setCheckable(True)
        self._filter_btn.setFixedHeight(24)
        self._filter_btn.setStyleSheet(_BTN_SS)
        self._filter_btn.toggled.connect(self._on_filter_toggle)
        tb.addWidget(self._filter_btn)

        self._reset_btn = QPushButton("Reset")
        self._reset_btn.setFixedHeight(24)
        self._reset_btn.setStyleSheet(_BTN_SS)
        self._reset_btn.clicked.connect(self._on_filter_reset)
        self._reset_btn.setVisible(False)
        tb.addWidget(self._reset_btn)

        ref_btn = QPushButton("Refresh")
        ref_btn.setFixedHeight(24)
        ref_btn.setStyleSheet(_BTN_SS)
        ref_btn.clicked.connect(self.refresh)
        tb.addWidget(ref_btn)

        root.addLayout(tb)

        # ── Separator ─────────────────────────────────────────────────────────
        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setFixedHeight(1)
        sep.setStyleSheet("background:#313244; border:none;")
        root.addWidget(sep)

        # ── Filter panel (hidden by default) ──────────────────────────────────
        self._filter_panel = FilterPanel(sections=FilterPanel.ALL_SECTIONS)
        self._filter_panel.setVisible(False)
        self._filter_panel.changed.connect(self._on_filter_changed)
        root.addWidget(self._filter_panel)

        sep2 = QFrame()
        sep2.setFrameShape(QFrame.HLine)
        sep2.setFixedHeight(1)
        sep2.setStyleSheet("background:#313244; border:none;")
        sep2.setObjectName("filter_sep")
        sep2.setVisible(False)
        self._filter_sep = sep2
        root.addWidget(sep2)

        # ── Table + request/response pane ─────────────────────────────────────
        splitter = QSplitter(Qt.Vertical)
        splitter.setChildrenCollapsible(False)
        splitter.setStyleSheet("QSplitter::handle{background:#313244;height:3px;}")

        self._table = QTableWidget(0, len(_COLS))
        self._table.setHorizontalHeaderLabels(_COLS)
        self._table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SingleSelection)
        self._table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        self._table.horizontalHeader().setStretchLastSection(False)
        self._table.horizontalHeader().setSectionResizeMode(_COL_PATH, QHeaderView.Stretch)
        self._table.setShowGrid(False)
        self._table.setStyleSheet(
            "QTableWidget{background:#1E1E2E; alternate-background-color:#181825;"
            " color:#CDD6F4; border:none; gridline-color:#313244;}"
            "QTableWidget::item:selected{background:#313244; color:#CDD6F4;}"
            "QHeaderView::section{background:#181825; color:#6C7086;"
            " border:none; border-bottom:1px solid #313244; padding:4px 8px;"
            " font-size:9px;}"
        )
        for col, w in [(_COL_SEQ, 45), (_COL_TYPE, 42), (_COL_METHOD, 65),
                       (_COL_HOST, 200), (_COL_STATUS, 55), (_COL_LEN, 70)]:
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
        self._render_view = ResponseRenderView()
        self._tabs.addTab(self._req_view,    "Request")
        self._tabs.addTab(self._resp_view,   "Response")
        self._tabs.addTab(self._render_view, "Render")
        self._req_view.send_to_repeater.connect(self.send_to_repeater)
        self._req_view.send_to_intruder.connect(self.send_to_intruder)
        self._req_view.send_to_decoder.connect(self.send_to_decoder)
        self._req_view.send_to_comparer_left.connect(self.send_to_comparer_left)
        self._req_view.send_to_comparer_right.connect(self.send_to_comparer_right)
        self._req_view.send_to_jwt.connect(self.send_to_jwt)
        self._resp_view.send_to_repeater.connect(
            lambda _: self.send_to_repeater.emit(self._req_view.toPlainText()))
        self._resp_view.send_to_intruder.connect(
            lambda _: self.send_to_intruder.emit(self._req_view.toPlainText()))
        self._resp_view.send_to_decoder.connect(self.send_to_decoder)
        self._resp_view.send_to_comparer_left.connect(self.send_to_comparer_left)
        self._resp_view.send_to_comparer_right.connect(self.send_to_comparer_right)
        self._resp_view.send_to_jwt.connect(self.send_to_jwt)
        rr_vb.addWidget(self._tabs)

        self._search_bar = SearchBar(rr)
        self._search_bar.set_editor(self._req_view)
        rr_vb.addWidget(self._search_bar)

        self._current_doc: dict | None = None

        def _on_tab_changed(idx: int) -> None:
            current = self._tabs.widget(idx)
            is_render = current is self._render_view
            self._render_view.on_tab_visibility_changed(is_render)
            self._search_bar.setVisible(not is_render)
            if is_render:
                self._render_current_response()
            else:
                self._search_bar.set_editor(current)

        self._tabs.currentChanged.connect(_on_tab_changed)
        self._req_view.installEventFilter(self)
        self._resp_view.installEventFilter(self)

        splitter.addWidget(rr)
        splitter.setSizes([350, 300])
        root.addWidget(splitter, stretch=1)

    # ── table population ──────────────────────────────────────────────────────

    def _refresh_table(self) -> None:
        # Remember which document was selected so we can restore it silently.
        cur = self._table.currentRow()
        _selected_id = (
            self._rows[cur][1] if 0 <= cur < len(self._rows) else None
        )

        self._table.setUpdatesEnabled(False)
        self._table.blockSignals(True)   # suppress currentCellChanged while rebuilding
        self._table.setRowCount(0)
        self._table.blockSignals(False)
        self._rows.clear()
        # Don't touch req/resp views here — content stays visible during rebuild.

        if self._col is None:
            self._count_lbl.setText("database unavailable")
            self._table.setUpdatesEnabled(True)
            return

        try:
            all_hosts = self._col.distinct("host")
        except Exception as exc:
            log.warning("History DB query failed: %s", exc)
            self._count_lbl.setText("DB error")
            self._table.setUpdatesEnabled(True)
            return

        in_scope = [
            h for h in all_hosts
            if not self._filter_scope or self._scope.matches(h)
        ]
        if not in_scope:
            self._count_lbl.setText("0 requests")
            self._table.setUpdatesEnabled(True)
            return

        try:
            cursor = self._col.find(
                {"host": {"$in": in_scope}},
                {"host": 1, "path": 1, "method": 1, "status_code": 1,
                 "timestamp": 1, "is_sse": 1, "is_rsc": 1,
                 "request.headers": 1, "request.body": 1,
                 "response.body": 1, "response.headers": 1},
                sort=[("timestamp", 1)],
            )
            docs = list(cursor)
        except Exception as exc:
            log.warning("History find failed: %s", exc)
            self._table.setUpdatesEnabled(True)
            return

        fp = self._filter_panel
        seq = 0
        for doc in docs:
            req  = doc.get("request") or {}
            resp = doc.get("response") or {}
            body = resp.get("body", "")

            ct = str((resp.get("headers") or {}).get("content-type", "")).lower()

            # SSE detection (stored flag + legacy fallback)
            is_sse = doc.get("is_sse", False)
            if not is_sse:
                is_sse = body == "[SSE stream]" or "text/event-stream" in ct

            # RSC detection (stored flag + legacy fallback)
            is_rsc = doc.get("is_rsc", False) if not is_sse else False
            if not is_rsc and not is_sse:
                is_rsc = "text/x-component" in ct or _looks_like_rsc(body)

            length = len(body.encode("utf-8", errors="replace")) if body else 0

            if not fp.passes(doc, req, resp, body, is_sse, is_rsc, length):
                continue

            seq   += 1
            ts     = doc.get("timestamp", "")
            host   = doc.get("host", "")
            path   = doc.get("path", "/")
            method = doc.get("method", "?")
            status = str(doc.get("status_code", "?"))
            doc_id = str(doc["_id"])

            status_col = QColor(_status_color(status))
            if is_sse:
                row_bg   = QColor(_SSE_ROW)
                type_lbl = "SSE"
                type_fg  = QColor(_SSE_FG)
            elif is_rsc:
                row_bg   = QColor(_RSC_ROW)
                type_lbl = "RSC"
                type_fg  = QColor(_RSC_FG)
            else:
                row_bg   = None
                type_lbl = ""
                type_fg  = QColor("#313244")

            row = self._table.rowCount()
            self._table.insertRow(row)
            self._rows.append((ts, doc_id))

            cells = [
                (_COL_SEQ,    str(seq),  QColor("#6C7086")),
                (_COL_TYPE,   type_lbl,  type_fg),
                (_COL_METHOD, method,    QColor("#89B4FA")),
                (_COL_HOST,   host,      QColor("#CDD6F4")),
                (_COL_PATH,   path,      QColor("#CDD6F4")),
                (_COL_STATUS, status,    status_col),
                (_COL_LEN,    str(length), QColor("#CDD6F4")),
            ]
            for col, text, fg in cells:
                cell = QTableWidgetItem(text)
                cell.setForeground(fg)
                if row_bg:
                    cell.setBackground(row_bg)
                if col == _COL_TYPE and type_lbl:
                    cell.setTextAlignment(Qt.AlignCenter)
                self._table.setItem(row, col, cell)
            self._table.setRowHeight(row, 22)

        # Restore the previously selected row without triggering a DB reload.
        if _selected_id:
            for i, (_, did) in enumerate(self._rows):
                if did == _selected_id:
                    self._table.blockSignals(True)
                    self._table.setCurrentCell(i, 0)
                    self._table.blockSignals(False)
                    break
            else:
                # Row filtered out or deleted — clear the detail panes.
                self._req_view.clear()
                self._resp_view.clear()
                self._current_doc = None
                self._render_view.clear()

        self._table.setUpdatesEnabled(True)
        count = self._table.rowCount()
        self._count_lbl.setText(f"{count} request{'s' if count != 1 else ''}")
        self._update_filter_indicator()

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
            self._current_doc = doc
            self._req_view.setText(_fmt_request(doc.get("request", {})))
            self._resp_view.setText(_fmt_response(doc.get("response", {})))
            if self._tabs.currentWidget() is self._render_view:
                self._render_current_response()
            else:
                self._tabs.setCurrentIndex(0)

    def _render_current_response(self) -> None:
        doc = self._current_doc
        if not doc:
            self._render_view.clear()
            return
        resp = doc.get("response") or {}
        body_str = resp.get("body", "") or ""
        body_bytes = body_str.encode("utf-8", errors="replace")
        # Extract content-type from response headers
        hdrs = resp.get("headers") or {}
        ct_val = hdrs.get("content-type") or hdrs.get("Content-Type") or ""
        if isinstance(ct_val, list):
            ct_val = ct_val[0] if ct_val else ""
        content_type = str(ct_val).split(";")[0].strip()
        # Build base URL from original request URL
        req = doc.get("request") or {}
        base_url = req.get("url") or ""
        self._render_view.render_response(body_bytes, content_type, base_url)

    def _on_table_context_menu(self, pos: QPoint) -> None:
        row = self._table.rowAt(pos.y())
        if row < 0 or row >= len(self._rows):
            return

        _, doc_id = self._rows[row]
        status_item = self._table.item(row, _COL_STATUS)
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
        self._scope_btn.setText(f"Scope: {'ON' if checked else 'OFF'}")
        self._scope_btn.setStyleSheet(_TOGGLE_SS_ON if checked else _TOGGLE_SS_OFF)
        self._refresh_table()

    def _on_filter_toggle(self, checked: bool) -> None:
        self._filter_panel.setVisible(checked)
        self._filter_sep.setVisible(checked)
        self._filter_btn.setText("Filters ▴" if checked else "Filters ▾")

    def _on_filter_changed(self) -> None:
        self._refresh_table()
        active = self._filter_panel.is_active()
        self._reset_btn.setVisible(active)
        self._save_filters()

    def _on_filter_reset(self) -> None:
        self._filter_panel.reset()
        self._reset_btn.setVisible(False)
        self._refresh_table()
        self._save_filters()

    def _save_filters(self) -> None:
        try:
            data = load_ui_settings()
            data["http_history_filters"] = self._filter_panel.to_dict()
            save_ui_settings(data)
        except Exception:
            pass

    def _restore_saved_filters(self) -> None:
        try:
            data = load_ui_settings()
            saved = data.get("http_history_filters")
            if not saved:
                return
            self._filter_panel.from_dict(saved)
            if self._filter_panel.is_active():
                self._filter_btn.setChecked(True)
                self._reset_btn.setVisible(True)
        except Exception:
            pass

    def _update_filter_indicator(self) -> None:
        if self._filter_panel.is_active():
            try:
                total = self._col.estimated_document_count() if self._col else 0
            except Exception:
                total = 0
            shown = self._table.rowCount()
            self._filter_active_lbl.setText(f"Filtered: {shown}/{total}")
            self._filter_active_lbl.setVisible(True)
        else:
            self._filter_active_lbl.setVisible(False)

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


# ── Code view ─────────────────────────────────────────────────────────────────

class _CodeView(QTextEdit):
    send_to_repeater       = Signal(str)
    send_to_intruder       = Signal(str)
    send_to_decoder        = Signal(str)
    send_to_comparer_left  = Signal(str)
    send_to_comparer_right = Signal(str)
    send_to_jwt            = Signal(str)

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

        dec_page_act = menu.addAction("Send to Decoder")
        dec_page_act.setEnabled(has_text)

        cmp_menu  = menu.addMenu("Send to Comparer")
        cmp_left  = cmp_menu.addAction("Left Pane")
        cmp_right = cmp_menu.addAction("Right Pane")
        cmp_left.setEnabled(has_text)
        cmp_right.setEnabled(has_text)

        jwt_act = menu.addAction("Analyze JWT")
        jwt_act.setEnabled(has_sel and selected.count('.') == 2)

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
        elif chosen is dec_page_act:
            self.send_to_decoder.emit(selected if has_sel else txt)
        elif chosen is cmp_left:
            self.send_to_comparer_left.emit(selected if has_sel else txt)
        elif chosen is cmp_right:
            self.send_to_comparer_right.emit(selected if has_sel else txt)
        elif chosen is jwt_act and has_sel:
            self.send_to_jwt.emit(selected)
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
