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
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QTabWidget,
    QPushButton, QLabel, QTextEdit, QFrame,
)

from gui.guiUtilities import SyntaxHighlighter

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

    def __init__(
        self,
        request_text: str = "",
        proxy_port: int   = 8080,
        parent            = None,
    ) -> None:
        super().__init__(parent)
        self._proxy_port = proxy_port
        self._worker: _SendWorker | None = None
        self._build_ui(request_text)

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

        self._status_lbl = QLabel("")
        self._status_lbl.setStyleSheet("color:#6C7086; font-size:9px;")
        tb.addWidget(self._status_lbl)
        tb.addStretch()
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
        self._resp_edit = _CodeEdit(read_only=True)
        resp_wrap.body_layout().addWidget(self._resp_edit)
        splitter.addWidget(resp_wrap)

        splitter.setSizes([350, 300])
        root.addWidget(splitter, stretch=1)

    # ── send / receive ────────────────────────────────────────────────────────

    def _on_send(self) -> None:
        raw = self._req_edit.toPlainText().strip()
        if not raw:
            return
        method, url, headers, body = _parse_raw_request(raw)

        self._send_btn.setEnabled(False)
        self._status_lbl.setText("Sending…")
        self._resp_edit.clear()

        self._worker = _SendWorker(method, url, headers, body, self._proxy_port)
        self._worker.done.connect(self._on_done)
        self._worker.start()

    def _on_done(self, response: str, error: str) -> None:
        self._send_btn.setEnabled(True)
        if error:
            self._status_lbl.setStyleSheet("color:#F38BA8; font-size:9px;")
            self._status_lbl.setText(f"Error — {error[:100]}")
            self._resp_edit.setPlainText(f"Error:\n{error}")
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


# ── repeater page (embeddable) ────────────────────────────────────────────────

class RepeaterPage(QWidget):
    """Per-target HTTP repeater.  Add to a QStackedWidget via targetWindow."""

    def __init__(self, proxy_port: int = 8080, parent=None) -> None:
        super().__init__(parent)
        self._proxy_port  = proxy_port
        self._tab_counter = 0
        self._build_ui()

    # ── public API ────────────────────────────────────────────────────────────

    def add_tab(self, request_text: str = "", title: str = "") -> None:
        """Open a new tab pre-populated with *request_text* and switch to it."""
        self._tab_counter += 1
        if not title:
            title = _auto_title(request_text, self._tab_counter)
        pane = _TabPane(
            request_text=request_text,
            proxy_port=self._proxy_port,
            parent=self,
        )
        idx = self._tabs.addTab(pane, title[:32])
        self._tabs.setCurrentIndex(idx)

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

    def __init__(self, read_only: bool = False, parent=None) -> None:
        super().__init__(parent)
        self.setReadOnly(read_only)
        self.setFont(QFont("Cascadia Code", 9))
        self.setLineWrapMode(QTextEdit.NoWrap)
        self.setStyleSheet(
            "QTextEdit{background:#11111B; color:#CDD6F4; border:none; padding:8px;}"
        )
        self._hl = SyntaxHighlighter(self.document())
