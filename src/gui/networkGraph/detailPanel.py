import logging

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QScrollArea,
    QPushButton, QFrame, QApplication, QSplitter, QStackedWidget,
)

from ._models import GraphNode
from ._constants import _NS, _KIND_ICON
from ._helpers import _ReqRespPane, _ReqRespCodeView, _fmt_req, _fmt_resp

logger = logging.getLogger(__name__)


# ── Detail panel ──────────────────────────────────────────────────────────────

class DetailPanel(QWidget):
    openInBrowser  = Signal(str)
    sendToRepeater = Signal(str)   # emits raw request text for endpoint nodes

    _BTN = """
        QPushButton {
            background:#252540; color:#CDD6F4;
            border:1px solid #313244; border-radius:5px;
            font-size:10px; text-align:left; padding:0 10px;
            min-height:28px;
        }
        QPushButton:hover { background:#313244; border-color:%s; color:%s; }
    """

    # Widths for the two modes
    _W_DEFAULT  = 260
    _W_ENDPOINT = 520

    def __init__(self, proxy_col=None, parent=None):
        super().__init__(parent)
        self._proxy_col = proxy_col   # pymongo Collection or None
        self.setFixedWidth(self._W_DEFAULT)
        self.setStyleSheet("background:#1E1E2E;")

        root_vb = QVBoxLayout(self)
        root_vb.setContentsMargins(0, 0, 0, 0)
        root_vb.setSpacing(0)

        # ── stacked area: default (key/val) vs endpoint (req/resp) ───────────
        self._pages = QStackedWidget()
        root_vb.addWidget(self._pages)

        # ── Page 0: default node info ─────────────────────────────────────────
        default_page = QWidget()
        default_page.setStyleSheet("background:#1E1E2E;")
        vb = QVBoxLayout(default_page)
        vb.setContentsMargins(10, 12, 10, 12)
        vb.setSpacing(8)

        self._icon_lbl = QLabel("○")
        self._icon_lbl.setStyleSheet("font-size:30px; color:#6C7086; background:transparent;")
        self._icon_lbl.setAlignment(Qt.AlignCenter)
        vb.addWidget(self._icon_lbl)

        self._title = QLabel("Select a node")
        self._title.setStyleSheet(
            "color:#CDD6F4; font-size:11px; font-weight:bold; background:transparent;")
        self._title.setAlignment(Qt.AlignCenter)
        self._title.setWordWrap(True)
        vb.addWidget(self._title)

        div = QFrame(); div.setFrameShape(QFrame.HLine)
        div.setStyleSheet("background:#313244; border:none;"); div.setFixedHeight(1)
        vb.addWidget(div)

        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setFrameShape(QFrame.NoFrame)
        self._scroll.setStyleSheet("background:#1E1E2E; border:none;")
        self._body = QWidget(); self._body.setStyleSheet("background:#1E1E2E;")
        self._body_vb = QVBoxLayout(self._body)
        self._body_vb.setContentsMargins(0, 0, 0, 0)
        self._body_vb.setSpacing(4)
        self._body_vb.addStretch()
        self._scroll.setWidget(self._body)
        vb.addWidget(self._scroll, stretch=1)

        self._act_vb = QVBoxLayout()
        self._act_vb.setSpacing(5)
        vb.addLayout(self._act_vb)

        self._empty_label = QLabel("Click any node to\nsee its details here.")
        self._empty_label.setStyleSheet(
            "color:#45475A; font-size:10px; background:transparent;")
        self._empty_label.setAlignment(Qt.AlignCenter)
        self._body_vb.insertWidget(0, self._empty_label)

        self._pages.addWidget(default_page)

        # ── Page 1: endpoint req/resp view ────────────────────────────────────
        ep_page = QWidget()
        ep_page.setStyleSheet("background:#1E1E2E;")
        ep_vb = QVBoxLayout(ep_page)
        ep_vb.setContentsMargins(0, 0, 0, 0)
        ep_vb.setSpacing(0)

        # header bar
        ep_hdr = QWidget()
        ep_hdr.setFixedHeight(36)
        ep_hdr.setStyleSheet("background:#181825; border-bottom:1px solid #313244;")
        hdr_hl = QHBoxLayout(ep_hdr)
        hdr_hl.setContentsMargins(10, 0, 10, 0)
        hdr_hl.setSpacing(6)
        self._ep_icon = QLabel(_KIND_ICON.get("endpoint", "○"))
        self._ep_icon.setStyleSheet("color:#A6E3A1; font-size:14px; background:transparent;")
        hdr_hl.addWidget(self._ep_icon)
        self._ep_title = QLabel("")
        self._ep_title.setStyleSheet(
            "color:#CDD6F4; font-size:10px; font-weight:bold; background:transparent;")
        self._ep_title.setWordWrap(False)
        hdr_hl.addWidget(self._ep_title, stretch=1)
        ep_back_btn = QPushButton("✕")
        ep_back_btn.setFixedSize(22, 22)
        ep_back_btn.setToolTip("Back to node info")
        ep_back_btn.setStyleSheet(
            "QPushButton{background:#313244;color:#6C7086;border:none;border-radius:4px;}"
            "QPushButton:hover{background:#45475A;color:#CDD6F4;}")
        ep_back_btn.clicked.connect(self._show_default_page)
        hdr_hl.addWidget(ep_back_btn)
        ep_vb.addWidget(ep_hdr)

        # meta row: method badge + status + content-type
        self._ep_meta = QLabel("")
        self._ep_meta.setStyleSheet(
            "color:#6C7086; font-size:9px; padding:4px 10px; background:#11111B;")
        ep_vb.addWidget(self._ep_meta)

        # req / resp splitter
        rr_splitter = QSplitter(Qt.Vertical)
        rr_splitter.setChildrenCollapsible(False)
        rr_splitter.setStyleSheet(
            "QSplitter::handle{background:#313244;height:3px;}")

        req_wrap = _ReqRespPane("Request", "#89B4FA")
        self._ep_req_view = _ReqRespCodeView()
        req_wrap.body_layout().addWidget(self._ep_req_view)
        rr_splitter.addWidget(req_wrap)

        resp_wrap = _ReqRespPane("Response", "#6C7086")
        self._ep_resp_view = _ReqRespCodeView()
        resp_wrap.body_layout().addWidget(self._ep_resp_view)
        rr_splitter.addWidget(resp_wrap)

        rr_splitter.setSizes([260, 260])
        ep_vb.addWidget(rr_splitter, stretch=1)

        # action row at bottom
        ep_act = QWidget()
        ep_act.setStyleSheet("background:#181825; border-top:1px solid #313244;")
        ep_act_hl = QHBoxLayout(ep_act)
        ep_act_hl.setContentsMargins(8, 6, 8, 6)
        ep_act_hl.setSpacing(6)
        self._ep_browser_btn = QPushButton("◉  Open in Browser")
        self._ep_browser_btn.setFixedHeight(26)
        self._ep_browser_btn.setStyleSheet(
            "QPushButton{background:#1A2740;color:#89B4FA;border:1px solid #89B4FA;"
            "border-radius:4px;font-size:10px;padding:0 10px;}"
            "QPushButton:hover{background:#243550;}")
        self._ep_browser_btn.setVisible(False)
        ep_act_hl.addWidget(self._ep_browser_btn)
        self._ep_repeater_btn = QPushButton("↻  Send to Repeater")
        self._ep_repeater_btn.setFixedHeight(26)
        self._ep_repeater_btn.setStyleSheet(
            "QPushButton{background:#2A1F3D;color:#CBA6F7;border:1px solid #CBA6F7;"
            "border-radius:4px;font-size:10px;padding:0 10px;}"
            "QPushButton:hover{background:#3A2F4D;}")
        self._ep_repeater_btn.setVisible(False)
        ep_act_hl.addWidget(self._ep_repeater_btn)
        ep_act_hl.addStretch()
        ep_vb.addWidget(ep_act)

        self._pages.addWidget(ep_page)

        self._pages.setCurrentIndex(0)
        self._current_node: GraphNode | None = None

    # ── Public ────────────────────────────────────────────────────────────────

    def show_node(self, node: GraphNode):
        self._current_node = node
        s = _NS[node.kind]

        if node.kind == "endpoint":
            self._show_endpoint(node, s)
        else:
            self._show_default(node, s)

    # ── Default page ──────────────────────────────────────────────────────────

    def _show_default(self, node: GraphNode, s: dict):
        self._icon_lbl.setText(_KIND_ICON.get(node.kind, "○"))
        self._icon_lbl.setStyleSheet(
            f"font-size:30px; color:{s['fill']}; background:transparent;")
        self._title.setText(node.label)

        self._clear_body()
        self._clear_actions()

        self._add_row("Type", node.kind.upper(), s["fill"])
        for key, value in node.data.items():
            if isinstance(value, list):
                value = ", ".join(str(v) for v in value) or "—"
            if value:
                self._add_row(key.replace("_", " ").title(), str(value))

        url = node.data.get("url") or node.data.get("domain")
        if url:
            href = url if url.startswith("http") else f"https://{url}"
            self._add_action("◉  Open in Browser", "#89B4FA",
                             lambda u=href: self.openInBrowser.emit(u))

        copy_val = (node.data.get("ip") or node.data.get("domain") or
                    node.data.get("value") or node.label)
        if copy_val:
            lbl = copy_val[:22] + ("…" if len(copy_val) > 22 else "")
            self._add_action(f"⎘  Copy: {lbl}", "#6C7086",
                             lambda v=copy_val: QApplication.clipboard().setText(v))

        self.setFixedWidth(self._W_DEFAULT)
        self._pages.setCurrentIndex(0)

    def _show_default_page(self):
        """Back button on endpoint view — return to the default page."""
        self.setFixedWidth(self._W_DEFAULT)
        self._pages.setCurrentIndex(0)

    # ── Endpoint page ─────────────────────────────────────────────────────────

    def _show_endpoint(self, node: GraphNode, s: dict):
        url    = node.data.get("url", "")
        method = node.data.get("method", "GET")
        status = node.data.get("status_code", "")
        ctype  = node.data.get("content_type", "")

        self._ep_title.setText(f"{method}  {url}")
        meta_parts = []
        if status:
            meta_parts.append(f"Status: {status}")
        if ctype:
            meta_parts.append(f"Content-Type: {ctype}")
        self._ep_meta.setText("   ".join(meta_parts) if meta_parts else "")

        # Clear old content
        self._ep_req_view.clear()
        self._ep_resp_view.clear()
        self._ep_browser_btn.setVisible(False)
        self._ep_repeater_btn.setVisible(False)

        # Wire browser button
        if url:
            href = url if url.startswith("http") else f"https://{url}"
            self._ep_browser_btn.setVisible(True)
            try:
                self._ep_browser_btn.clicked.disconnect()
            except RuntimeError:
                pass
            self._ep_browser_btn.clicked.connect(lambda: self.openInBrowser.emit(href))

        # Fetch traffic doc and populate panes
        doc = self._fetch_traffic_doc(url, method)
        if doc:
            self._ep_req_view.setPlainText(_fmt_req(doc.get("request", {})))
            self._ep_resp_view.setPlainText(_fmt_resp(doc.get("response", {})))
            raw_req = _fmt_req(doc.get("request", {}))
            if raw_req:
                self._ep_repeater_btn.setVisible(True)
                try:
                    self._ep_repeater_btn.clicked.disconnect()
                except RuntimeError:
                    pass
                self._ep_repeater_btn.setProperty("raw_req", raw_req)
                self._ep_repeater_btn.clicked.connect(self._on_send_repeater)
        else:
            self._ep_req_view.setPlainText(
                f"# No traffic captured for this endpoint yet.\n"
                f"# Proxy the request through AWE to see it here.\n\n"
                f"{method} {url}"
            )

        self.setFixedWidth(self._W_ENDPOINT)
        self._pages.setCurrentIndex(1)

    def _on_send_repeater(self):
        raw = self._ep_repeater_btn.property("raw_req") or ""
        if raw:
            self.sendToRepeater.emit(raw)

    def _fetch_traffic_doc(self, url: str, method: str) -> dict | None:
        if not url or self._proxy_col is None:
            return None
        try:
            from urllib.parse import urlsplit
            p = urlsplit(url)
            host = p.netloc
            path = p.path or "/"
            # Find the most recent matching traffic doc
            doc = self._proxy_col.find_one(
                {"host": host, "path": path, "method": method.upper()},
                sort=[("timestamp", -1)],
            )
            if doc is None:
                # Fallback: match by host+path without method
                doc = self._proxy_col.find_one(
                    {"host": host, "path": path},
                    sort=[("timestamp", -1)],
                )
            return doc
        except Exception:
            logger.exception("DetailPanel: traffic lookup failed for %s", url)
            return None

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _clear_body(self):
        while self._body_vb.count() > 1:
            it = self._body_vb.takeAt(0)
            if it.widget():
                it.widget().deleteLater()

    def _clear_actions(self):
        while self._act_vb.count():
            it = self._act_vb.takeAt(0)
            if it.widget():
                it.widget().deleteLater()

    def _add_row(self, key: str, value: str, accent: str = "#45475A"):
        row = QWidget()
        row.setStyleSheet(
            "QWidget{background:#252540;border-radius:4px;}"
            "QLabel{background:transparent;border:none;}")
        hl = QHBoxLayout(row)
        hl.setContentsMargins(8, 5, 8, 5)
        hl.setSpacing(8)
        kl = QLabel(key)
        kl.setStyleSheet("color:#6C7086;font-size:9px;")
        kl.setFixedWidth(76)
        hl.addWidget(kl)
        vl = QLabel(value)
        vl.setStyleSheet("color:#CDD6F4;font-size:9px;")
        vl.setWordWrap(True)
        hl.addWidget(vl, stretch=1)
        idx = max(self._body_vb.count() - 1, 0)
        self._body_vb.insertWidget(idx, row)

    def _add_action(self, label: str, color: str, fn):
        btn = QPushButton(label)
        btn.setStyleSheet(self._BTN % (color, color))
        btn.clicked.connect(fn)
        self._act_vb.addWidget(btn)

