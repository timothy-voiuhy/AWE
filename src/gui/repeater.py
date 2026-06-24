"""
RepeaterPage — per-target HTTP repeater, embedded in the Target nav bar.

Each tab holds one editable request pane and a read-only response pane.
Clicking Send dispatches the request via httpx through the AWE proxy
(port configured per-target) so the traffic is logged in the proxy store.

Public API used by callers:
    page.add_tab(request_text, title="")   # pre-populate from Sitemap / History
"""
from __future__ import annotations

import logging

import httpx
from PySide6.QtCore import Qt, QThread, Signal, QEvent, QTimer
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QTabWidget,
    QPushButton, QLabel, QTextEdit, QFrame, QMenu, QToolTip, QDialog, QApplication,
    QComboBox,
)

from gui.guiUtilities import (
    SyntaxHighlighter, format_http_body, SearchBar,
    decode_text, DecodeDialog,
    parse_http_headers, set_header_clipboard, HeaderSelectorDialog,
    paste_headers, has_copied_headers,
    ResponseRenderView,
)
from gui.utilities.session_utils import apply_session_to_request

log = logging.getLogger(__name__)


# ── request parsing ───────────────────────────────────────────────────────────

def _parse_raw_request(text: str) -> tuple[str, str, dict[str, str], bytes]:
    """Parse a formatted HTTP request block into (method, url, headers, body)."""
    lines = text.replace('\r\n', '\n').split('\n')
    if not lines or not lines[0].strip():
        return 'GET', '/', {}, b''

    # First line: METHOD URL [HTTP/version]
    parts = lines[0].strip().split(' ', 2)
    method = parts[0].upper()             if len(parts) >= 1 else 'GET'
    url    = parts[1]                     if len(parts) >= 2 else '/'

    # Headers — stop at first blank line
    headers: dict[str, str] = {}
    i = 1
    while i < len(lines) and lines[i].strip():
        if ':' in lines[i]:
            k, _, v = lines[i].partition(':')
            headers[k.strip()] = v.strip()
        i += 1

    # Body — everything after the blank separator
    i += 1
    body_text = '\n'.join(lines[i:]).strip()
    body      = body_text.encode('utf-8') if body_text else b''

    # Resolve relative URL using Host header
    if not url.startswith('http'):
        host = headers.get('Host', headers.get('host', 'localhost'))
        port_str = host.split(':')[-1] if ':' in host else ''
        scheme   = 'https' if port_str == '443' else 'https'
        url = f"{scheme}://{host}{url}"

    return method, url, headers, body


def _parse_resp_for_render(text: str) -> tuple[bytes, str]:
    """Parse formatted raw HTTP response text → (body_bytes, content_type)."""
    if "\n\n" in text:
        hdr_block, body = text.split("\n\n", 1)
    else:
        return b"", ""
    ct = ""
    for line in hdr_block.split("\n")[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            if k.strip().lower() == "content-type":
                ct = v.strip().split(";")[0].strip()
                break
    return body.encode("utf-8", errors="replace"), ct


# ── background send worker ────────────────────────────────────────────────────

class _SendWorker(QThread):
    done = Signal(str, str)   # (response_text, error_message)

    _SKIP_HEADERS = frozenset({
        "content-length", "transfer-encoding", "connection",
        "proxy-connection", "keep-alive", "te", "trailers",
    })

    def __init__(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes,
        proxy_port: int,
    ) -> None:
        super().__init__()
        self._method     = method
        self._url        = url
        self._body       = body
        self._proxy_port = proxy_port
        self._headers    = {
            k: v for k, v in headers.items()
            if k.lower() not in self._SKIP_HEADERS
        }

    def run(self) -> None:
        try:
            with httpx.Client(
                proxy=f"http://127.0.0.1:{self._proxy_port}",
                verify=False,
                follow_redirects=False,
                timeout=30.0,
            ) as client:
                r = client.request(
                    self._method, self._url,
                    headers=self._headers,
                    content=self._body,
                )

            version = r.http_version or "HTTP/1.1"
            lines   = [f"{version} {r.status_code} {r.reason_phrase}"]
            for k, v in r.headers.multi_items():
                lines.append(f"{k}: {v}")
            lines.append("")
            lines.append(r.content.decode("utf-8", errors="replace"))
            self.done.emit("\n".join(lines), "")

        except Exception as exc:
            self.done.emit("", str(exc))


# ── single tab content ────────────────────────────────────────────────────────

class _TabPane(QWidget):
    """Content of one repeater tab: request editor + response viewer."""

    send_to_intruder_requested    = Signal(str)
    send_to_decoder_requested     = Signal(str)
    send_to_comparer_left_req     = Signal(str)
    send_to_comparer_right_req    = Signal(str)
    send_to_jwt_requested         = Signal(str)

    def __init__(
        self,
        request_text: str = "",
        proxy_port: int   = 8080,
        repository        = None,
        parent            = None,
    ) -> None:
        super().__init__(parent)
        self._proxy_port = proxy_port
        self._repo       = repository
        self._worker: _SendWorker | None = None
        self._build_ui(request_text)

    def get_state(self) -> dict:
        """Return serialisable snapshot of this tab's content."""
        return {"request": self._req_edit.toPlainText()}

    def set_state(self, state: dict) -> None:
        """Restore content from a previously saved snapshot."""
        if state.get("request"):
            self._req_edit.setPlainText(state["request"])

    def _build_ui(self, request_text: str) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── toolbar ───────────────────────────────────────────────────────────
        tb = QHBoxLayout()
        tb.setContentsMargins(8, 6, 8, 6)
        tb.setSpacing(8)

        self._send_btn = QPushButton("▶  Send")
        self._send_btn.setFixedHeight(26)
        self._send_btn.setStyleSheet(
            "QPushButton{background:#1E3A2F;color:#A6E3A1;border:1px solid #A6E3A1;"
            "border-radius:4px;padding:0 14px;font-size:10px;font-weight:bold;}"
            "QPushButton:hover{background:#2A4A3F;}"
            "QPushButton:disabled{background:#181825;color:#45475A;border-color:#313244;}"
        )
        self._send_btn.clicked.connect(self._on_send)
        tb.addWidget(self._send_btn)

        self._intruder_btn = QPushButton("⊛  Intruder")
        self._intruder_btn.setFixedHeight(26)
        self._intruder_btn.setStyleSheet(
            "QPushButton{background:#2A1A2E;color:#EE99A0;border:1px solid #EE99A0;"
            "border-radius:4px;padding:0 12px;font-size:10px;}"
            "QPushButton:hover{background:#3A2A3E;}"
        )
        self._intruder_btn.clicked.connect(
            lambda: self.send_to_intruder_requested.emit(
                self._req_edit.toPlainText().strip()
            )
        )
        tb.addWidget(self._intruder_btn)

        self._status_lbl = QLabel("")
        self._status_lbl.setStyleSheet("color:#6C7086; font-size:9px;")
        tb.addWidget(self._status_lbl)
        tb.addStretch()

        # Session selector
        sess_lbl = QLabel("Session:")
        sess_lbl.setStyleSheet("color:#6C7086; font-size:9px;")
        tb.addWidget(sess_lbl)
        self._session_combo = QComboBox()
        self._session_combo.setFixedHeight(26)
        self._session_combo.setMinimumWidth(120)
        self._session_combo.setStyleSheet(
            "QComboBox{background:#11111B;color:#CDD6F4;border:1px solid #45475A;"
            "border-radius:4px;padding:0 6px;font-size:9px;}"
            "QComboBox::drop-down{border:none;}"
            "QComboBox QAbstractItemView{background:#1E1E2E;color:#CDD6F4;"
            "selection-background-color:#313244;border:1px solid #45475A;}"
        )
        self._session_combo.currentIndexChanged.connect(self._apply_session)
        tb.addWidget(self._session_combo)
        self._load_sessions()

        root.addLayout(tb)

        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setFixedHeight(1)
        sep.setStyleSheet("background:#313244; border:none;")
        root.addWidget(sep)

        # ── splitter: request (top) / response (bottom) ───────────────────────
        splitter = QSplitter(Qt.Vertical)
        splitter.setChildrenCollapsible(False)
        splitter.setStyleSheet("QSplitter::handle{background:#313244;height:4px;}")

        req_wrap = _PaneWrapper("Request", "#89B4FA")
        self._req_edit = _CodeEdit(read_only=False)
        if request_text:
            self._req_edit.setPlainText(request_text)
        req_wrap.body_layout().addWidget(self._req_edit)
        splitter.addWidget(req_wrap)

        resp_wrap = _PaneWrapper("Response", "#6C7086")
        # Inner tab: Raw text | Render
        self._resp_inner = QTabWidget()
        self._resp_inner.setStyleSheet(
            "QTabBar::tab{background:#181825;color:#6C7086;"
            "padding:2px 10px;border:none;font-size:9px;}"
            "QTabBar::tab:selected{background:#252540;color:#CDD6F4;}"
            "QTabWidget::pane{border:none;}"
        )
        self._resp_edit   = _CodeEdit(read_only=True)
        self._resp_render = ResponseRenderView()
        self._resp_inner.addTab(self._resp_edit,   "Raw")
        self._resp_inner.addTab(self._resp_render, "Render")
        self._resp_inner.currentChanged.connect(self._on_resp_inner_tab_changed)
        resp_wrap.body_layout().addWidget(self._resp_inner)
        splitter.addWidget(resp_wrap)

        splitter.setSizes([350, 300])
        root.addWidget(splitter, stretch=1)

        self._search_bar = SearchBar(self)
        self._search_bar.set_editor(self._req_edit)
        root.addWidget(self._search_bar)

        self._last_resp_text: str = ""

        self._req_edit.send_to_decoder.connect(self.send_to_decoder_requested)
        self._req_edit.send_to_comparer_left.connect(self.send_to_comparer_left_req)
        self._req_edit.send_to_comparer_right.connect(self.send_to_comparer_right_req)
        self._req_edit.send_to_jwt.connect(self.send_to_jwt_requested)
        self._resp_edit.send_to_decoder.connect(self.send_to_decoder_requested)
        self._resp_edit.send_to_comparer_left.connect(self.send_to_comparer_left_req)
        self._resp_edit.send_to_comparer_right.connect(self.send_to_comparer_right_req)
        self._resp_edit.send_to_jwt.connect(self.send_to_jwt_requested)

        self._req_edit.installEventFilter(self)
        self._resp_edit.installEventFilter(self)

    # ── event filter (Ctrl+F → search bar) ───────────────────────────────────

    def eventFilter(self, obj, event) -> bool:
        if (event.type() == QEvent.Type.KeyPress
                and event.modifiers() == Qt.ControlModifier
                and event.key() == Qt.Key_F):
            self._search_bar.set_editor(obj)
            self._search_bar.activate()
            return True
        return super().eventFilter(obj, event)

    # ── send / receive ────────────────────────────────────────────────────────

    def _on_resp_inner_tab_changed(self, idx: int) -> None:
        w = self._resp_inner.widget(idx)
        is_render = w is self._resp_render
        self._resp_render.on_tab_visibility_changed(is_render)
        self._search_bar.setVisible(not is_render)
        if is_render:
            self._do_render()

    def _do_render(self) -> None:
        if not self._last_resp_text:
            self._resp_render.clear()
            return
        body_bytes, ct = _parse_resp_for_render(self._last_resp_text)
        _, url, _, _ = _parse_raw_request(self._req_edit.toPlainText().strip() or "GET / HTTP/1.1\r\n\r\n")
        self._resp_render.render_response(body_bytes, ct, url)

    def _on_send(self) -> None:
        raw = self._req_edit.toPlainText().strip()
        if not raw:
            return
        method, url, headers, body = _parse_raw_request(raw)

        self._send_btn.setEnabled(False)
        self._status_lbl.setText("Sending…")
        self._resp_edit.clear()
        self._last_resp_text = ""
        self._resp_render.clear()

        self._worker = _SendWorker(method, url, headers, body, self._proxy_port)
        self._worker.done.connect(self._on_done)
        self._worker.start()

    def _on_done(self, response: str, error: str) -> None:
        self._send_btn.setEnabled(True)
        if error:
            self._status_lbl.setStyleSheet("color:#F38BA8; font-size:9px;")
            self._status_lbl.setText(f"Error — {error[:100]}")
            self._resp_edit.setPlainText(f"Error:\n{error}")
            self._last_resp_text = ""
            self._resp_render.clear()
        else:
            first = response.split('\n', 1)[0]
            # colour status label by response class
            code_str = first.split(' ')[1] if len(first.split(' ')) > 1 else ''
            color = "#A6E3A1"
            try:
                c = int(code_str)
                if   c < 300: color = "#A6E3A1"
                elif c < 400: color = "#89B4FA"
                elif c < 500: color = "#F9E2AF"
                else:         color = "#F38BA8"
            except ValueError:
                pass
            self._status_lbl.setStyleSheet(f"color:{color}; font-size:9px; font-weight:bold;")
            self._status_lbl.setText(first)
            self._resp_edit.setPlainText(response)
            self._last_resp_text = response
            if self._resp_inner.currentWidget() is self._resp_render:
                self._do_render()

    # ── session helpers ───────────────────────────────────────────────────────

    def _load_sessions(self) -> None:
        self._session_combo.blockSignals(True)
        self._session_combo.clear()
        self._session_combo.addItem("No Session", None)
        if self._repo:
            try:
                for sess in self._repo.list_auth_sessions():
                    self._session_combo.addItem(sess.get("name", ""), sess.get("id"))
            except Exception:
                pass
        self._session_combo.blockSignals(False)

    def refresh_sessions(self) -> None:
        self._load_sessions()

    def _apply_session(self, index: int) -> None:
        if index <= 0 or not self._repo:
            return
        session_id = self._session_combo.itemData(index)
        if not session_id:
            return
        try:
            sess = self._repo.get_auth_session(session_id)
        except Exception:
            return
        if not sess:
            return
        current = self._req_edit.toPlainText()
        modified = apply_session_to_request(current, sess)
        if modified != current:
            self._req_edit.setPlainText(modified)


# ── repeater page (embeddable) ────────────────────────────────────────────────

class RepeaterPage(QWidget):
    """Per-target HTTP repeater.  Add to a QStackedWidget via targetWindow."""

    send_to_intruder       = Signal(str)
    send_to_decoder        = Signal(str)
    send_to_comparer_left  = Signal(str)
    send_to_comparer_right = Signal(str)
    send_to_jwt            = Signal(str)

    def __init__(self, proxy_port: int = 8080, repository=None, parent=None) -> None:
        super().__init__(parent)
        self._proxy_port  = proxy_port
        self._repo        = repository
        self._tab_counter = 0
        self._save_timer  = QTimer(self)
        self._save_timer.setSingleShot(True)
        self._save_timer.setInterval(2000)
        self._save_timer.timeout.connect(self._save_state)
        self._build_ui()
        self._restore_state()

    # ── public API ────────────────────────────────────────────────────────────

    def add_tab(self, request_text: str = "", title: str = "") -> None:
        """Open a new tab pre-populated with *request_text* and switch to it."""
        self._tab_counter += 1
        if not title:
            title = _auto_title(request_text, self._tab_counter)
        pane = _TabPane(
            request_text=request_text,
            proxy_port=self._proxy_port,
            repository=self._repo,
            parent=self,
        )
        pane.send_to_intruder_requested.connect(self.send_to_intruder)
        pane.send_to_decoder_requested.connect(self.send_to_decoder)
        pane.send_to_comparer_left_req.connect(self.send_to_comparer_left)
        pane.send_to_comparer_right_req.connect(self.send_to_comparer_right)
        pane.send_to_jwt_requested.connect(self.send_to_jwt)
        # schedule a save whenever the request text changes
        pane._req_edit.textChanged.connect(self._save_timer.start)
        idx = self._tabs.addTab(pane, title[:32])
        self._tabs.setCurrentIndex(idx)
        self._save_timer.start()

    # ── persistence ───────────────────────────────────────────────────────────

    def _save_state(self) -> None:
        if not self._repo:
            return
        tabs = []
        for i in range(self._tabs.count()):
            pane = self._tabs.widget(i)
            if isinstance(pane, _TabPane):
                tabs.append({
                    "title":   self._tabs.tabText(i),
                    "content": pane.get_state(),
                })
        try:
            self._repo.save_page_state("repeater", {
                "tabs":        tabs,
                "active_tab":  self._tabs.currentIndex(),
            })
        except Exception:
            pass

    def _restore_state(self) -> None:
        if not self._repo:
            return
        try:
            state = self._repo.load_page_state("repeater")
        except Exception:
            return
        if not state or not state.get("tabs"):
            return
        # Remove the default blank tab added by _build_ui
        while self._tabs.count() > 0:
            w = self._tabs.widget(0)
            self._tabs.removeTab(0)
            if w:
                w.deleteLater()
        self._tab_counter = 0
        for tab in state["tabs"]:
            content = tab.get("content", {})
            self.add_tab(
                request_text=content.get("request", ""),
                title=tab.get("title", ""),
            )
        active = state.get("active_tab", 0)
        if 0 <= active < self._tabs.count():
            self._tabs.setCurrentIndex(active)

    def refresh_sessions(self) -> None:
        """Reload session combos in all open tabs."""
        for i in range(self._tabs.count()):
            pane = self._tabs.widget(i)
            if isinstance(pane, _TabPane):
                pane.refresh_sessions()

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        self._tabs = QTabWidget()
        self._tabs.setTabsClosable(True)
        self._tabs.tabCloseRequested.connect(self._close_tab)
        self._tabs.setMovable(True)
        self._tabs.setStyleSheet(
            "QTabBar::tab{background:#181825;color:#6C7086;padding:5px 14px;"
            "border:none;border-radius:4px 4px 0 0;min-width:90px;}"
            "QTabBar::tab:selected{background:#1E1E2E;color:#CDD6F4;"
            "border-bottom:2px solid #F5C2E7;}"
            "QTabBar::tab:hover{background:#313244;color:#CDD6F4;}"
            "QTabWidget::pane{border:none;border-top:1px solid #313244;}"
        )

        # "+" corner button for a blank tab
        new_btn = QPushButton("+")
        new_btn.setFixedSize(28, 28)
        new_btn.setToolTip("New tab")
        new_btn.setStyleSheet(
            "QPushButton{background:transparent;color:#6C7086;border:none;font-size:18px;}"
            "QPushButton:hover{color:#CDD6F4;}"
        )
        new_btn.clicked.connect(lambda: self.add_tab())
        self._tabs.setCornerWidget(new_btn, Qt.TopRightCorner)

        root.addWidget(self._tabs, stretch=1)

        # Start with one blank tab
        self.add_tab(title="New Request")

    def _close_tab(self, index: int) -> None:
        if self._tabs.count() <= 1:
            return   # always keep at least one tab
        widget = self._tabs.widget(index)
        self._tabs.removeTab(index)
        if widget:
            widget.deleteLater()
        self._save_timer.start()


# ── small helpers ─────────────────────────────────────────────────────────────

def _auto_title(request_text: str, counter: int) -> str:
    """Derive a short tab title from the first line of a raw request."""
    first = request_text.strip().split('\n', 1)[0].strip()
    parts = first.split(' ', 2)
    if len(parts) >= 2:
        from urllib.parse import urlsplit
        path = urlsplit(parts[1]).path or '/'
        # Keep path concise — last two segments
        segs = [s for s in path.split('/') if s]
        short_path = '/' + '/'.join(segs[-2:]) if segs else '/'
        return f"{parts[0]} {short_path}"
    return f"Request {counter}"


class _PaneWrapper(QWidget):
    """Thin header + body container for request/response panes."""

    def __init__(self, label: str, color: str, parent=None) -> None:
        super().__init__(parent)
        vb = QVBoxLayout(self)
        vb.setContentsMargins(0, 0, 0, 0)
        vb.setSpacing(0)
        hdr = QLabel(f"  {label}")
        hdr.setFixedHeight(22)
        hdr.setStyleSheet(
            f"color:{color}; font-size:9px; background:#181825;"
            "border-bottom:1px solid #313244;"
        )
        vb.addWidget(hdr)
        self._body_vb = vb

    def body_layout(self) -> QVBoxLayout:
        return self._body_vb


class _CodeEdit(QTextEdit):
    """Monospace editor / viewer with HTTP syntax highlighting."""

    send_to_decoder        = Signal(str)
    send_to_comparer_left  = Signal(str)
    send_to_comparer_right = Signal(str)
    send_to_jwt            = Signal(str)

    def __init__(self, read_only: bool = False, parent=None) -> None:
        super().__init__(parent)
        self.setReadOnly(read_only)
        self.setFont(QFont("Cascadia Code", 9))
        self.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        self.setStyleSheet(
            "QTextEdit{background:#11111B; color:#CDD6F4; border:none; padding:8px;}"
        )
        self._hl = SyntaxHighlighter(self.document())

    def contextMenuEvent(self, event) -> None:
        menu     = self.createStandardContextMenu()
        txt      = self.toPlainText()
        selected = self.textCursor().selectedText().strip()
        has_text = bool(txt.strip())
        has_body = '\n\n' in txt and bool(txt.split('\n\n', 1)[-1].strip())
        has_sel  = bool(selected)
        editable = not self.isReadOnly()

        menu.addSeparator()
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
        fmt_menu.setEnabled(has_body and editable)
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

        paste_rep_act = paste_add_act = None
        if editable:
            paste_menu = menu.addMenu("Paste Headers")
            paste_menu.setEnabled(has_copied_headers())
            paste_rep_act = paste_menu.addAction("Replace Existing")
            paste_add_act = paste_menu.addAction("Add to Existing")

        menu.addSeparator()
        wrap_act = menu.addAction("Word Wrap")
        wrap_act.setCheckable(True)
        wrap_act.setChecked(self.lineWrapMode() != QTextEdit.LineWrapMode.NoWrap)

        chosen = menu.exec(event.globalPos())

        fmt_map = {json_act: 'json', xml_act: 'xml', html_act: 'html', js_act: 'javascript'}
        dec_map = {dec_auto: 'auto', dec_b64: 'base64', dec_url: 'url',
                   dec_html: 'html', dec_hex: 'hex', dec_jwt: 'jwt', dec_uni: 'unicode'}

        if chosen is dec_page_act:
            self.send_to_decoder.emit(selected if has_sel else txt)
        elif chosen is cmp_left:
            self.send_to_comparer_left.emit(selected if has_sel else txt)
        elif chosen is cmp_right:
            self.send_to_comparer_right.emit(selected if has_sel else txt)
        elif chosen is jwt_act and has_sel:
            self.send_to_jwt.emit(selected)
        elif chosen in fmt_map and editable:
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
        elif chosen is paste_rep_act:
            result = paste_headers(txt, 'replace')
            if result is not None:
                self.setPlainText(result)
        elif chosen is paste_add_act:
            result = paste_headers(txt, 'add')
            if result is not None:
                self.setPlainText(result)
        elif chosen is wrap_act:
            mode = (QTextEdit.LineWrapMode.WidgetWidth if wrap_act.isChecked()
                    else QTextEdit.LineWrapMode.NoWrap)
            self.setLineWrapMode(mode)
