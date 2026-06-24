import html as _html_mod
import json
import re

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel


def _json_to_html(raw: bytes) -> bytes:
    """Pretty-print JSON and return a self-contained dark-themed HTML page."""
    try:
        obj    = json.loads(raw.decode("utf-8", errors="replace"))
        pretty = json.dumps(obj, indent=2, ensure_ascii=False)
    except Exception:
        pretty = raw.decode("utf-8", errors="replace")

    _TOKEN = re.compile(
        r'(?P<key>"(?:[^"\\]|\\.)*"(?=\s*:))'
        r'|(?P<str>"(?:[^"\\]|\\.)*")'
        r'|(?P<lit>true|false|null)'
        r'|(?P<num>-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)'
    )
    _CSS = {"key": "jk", "str": "js", "lit": "jb", "num": "ji"}

    def _repl(m: re.Match) -> str:
        kind = m.lastgroup
        tok  = _html_mod.escape(m.group(0))
        if kind == "lit" and m.group(0) == "null":
            return f'<span class="jn">{tok}</span>'
        return f'<span class="{_CSS[kind]}">{tok}</span>'

    def _safe_sub(text: str) -> str:
        result, pos = [], 0
        for m in _TOKEN.finditer(text):
            if m.start() > pos:
                result.append(_html_mod.escape(text[pos:m.start()]))
            result.append(_repl(m))
            pos = m.end()
        if pos < len(text):
            result.append(_html_mod.escape(text[pos:]))
        return "".join(result)

    highlighted = _safe_sub(pretty)

    page = (
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        "<style>"
        "*{box-sizing:border-box;margin:0;padding:0}"
        "body{background:#11111B;color:#CDD6F4;"
        "font-family:'Cascadia Code','Fira Code',monospace;"
        "font-size:12px;padding:10px;line-height:1.5}"
        "pre{white-space:pre-wrap;word-break:break-all}"
        ".jk{color:#89B4FA}.js{color:#A6E3A1}"
        ".ji{color:#FAB387}.jb{color:#CBA6F7}.jn{color:#F38BA8}"
        "</style></head>"
        f"<body><pre>{highlighted}</pre></body></html>"
    )
    return page.encode("utf-8")


# One profile shared by every ResponseRenderView in the process.
_RENDER_PROFILE = None


def _get_render_profile():
    global _RENDER_PROFILE
    if _RENDER_PROFILE is None:
        from PySide6.QtWebEngineCore import QWebEngineProfile, QWebEngineSettings
        _RENDER_PROFILE = QWebEngineProfile("awe_render")
        s = _RENDER_PROFILE.settings()
        s.setAttribute(QWebEngineSettings.WebAttribute.JavascriptEnabled, True)
        s.setAttribute(QWebEngineSettings.WebAttribute.WebGLEnabled, False)
        s.setAttribute(QWebEngineSettings.WebAttribute.Accelerated2dCanvasEnabled, False)
    return _RENDER_PROFILE


class ResponseRenderView(QWidget):
    """
    Embeds a QWebEngineView for rendering captured HTTP responses in-place.

    All instances share one QWebEngineProfile (_RENDER_PROFILE), so exactly
    one extra QtWebEngineProcess exists while any render view is active.

    The QWebEngineView + QWebEnginePage are created lazily on first render and
    destroyed entirely after the user has been away from the tab for 45 s,
    freeing the renderer resources.  They are transparently recreated on the
    next render_response() call.
    """

    _IDLE_MS = 45_000

    def __init__(self, parent=None):
        super().__init__(parent)
        self._vb = QVBoxLayout(self)
        self._vb.setContentsMargins(0, 0, 0, 0)
        self._vb.setSpacing(0)

        self._placeholder = QLabel("Select a response to render it here.")
        self._placeholder.setAlignment(Qt.AlignCenter)
        self._placeholder.setStyleSheet(
            "color:#45475A; font-size:10px; background:#11111B;"
        )
        self._unsupported = QLabel("")
        self._unsupported.setAlignment(Qt.AlignCenter)
        self._unsupported.setStyleSheet(
            "color:#6C7086; font-size:10px; background:#11111B;"
        )
        self._unsupported.setVisible(False)

        self._vb.addWidget(self._placeholder)
        self._vb.addWidget(self._unsupported)

        self._web:  object | None = None
        self._page: object | None = None

        self._idle_timer = QTimer(self)
        self._idle_timer.setSingleShot(True)
        self._idle_timer.setInterval(self._IDLE_MS)
        self._idle_timer.timeout.connect(self._destroy_web)

    # ── public API ────────────────────────────────────────────────────────────

    def render_response(self, body: bytes, content_type: str = "", base_url: str = "") -> None:
        try:
            _get_render_profile()
        except Exception:
            return

        from PySide6.QtCore import QUrl

        ct = (content_type or "").lower().split(";")[0].strip()

        is_json = (
            ct in ("application/json", "application/ld+json")
            or ct.endswith("+json")
        )
        is_html = ct in (
            "text/html", "application/xhtml+xml",
            "text/xml", "application/xml", "image/svg+xml", "text/plain",
        ) or ct.startswith("image/")

        if not (is_json or is_html):
            self._placeholder.setVisible(False)
            self._unsupported.setText(f"Cannot render  ·  {ct or 'unknown content-type'}")
            self._unsupported.setVisible(True)
            if self._web:
                self._web.setVisible(False)
            return

        if is_json:
            render_body = _json_to_html(body)
            render_ct   = "text/html"
        else:
            render_body = body
            render_ct   = ct or "text/html"

        self._ensure_web()
        self._placeholder.setVisible(False)
        self._unsupported.setVisible(False)
        self._web.setVisible(True)
        q_url = QUrl(base_url) if base_url else QUrl("about:blank")
        self._web.setContent(render_body, render_ct, q_url)

    def on_tab_visibility_changed(self, visible: bool) -> None:
        """Call when this widget becomes the active tab (True) or is hidden (False)."""
        if visible:
            self._idle_timer.stop()
        else:
            self._idle_timer.start()

    def clear(self) -> None:
        self._idle_timer.stop()
        self._destroy_web()

    # ── internal ──────────────────────────────────────────────────────────────

    def _ensure_web(self) -> None:
        """Create QWebEngineView + page against the shared profile if not alive."""
        if self._web is not None:
            return
        from PySide6.QtWebEngineWidgets import QWebEngineView
        from PySide6.QtWebEngineCore import QWebEnginePage

        profile = _get_render_profile()
        self._page = QWebEnginePage(profile, self)
        self._page.certificateError.connect(self._on_cert_error)
        self._web = QWebEngineView(profile, self)
        self._web.setPage(self._page)
        self._web.setStyleSheet("background:#11111B;")
        self._web.setVisible(False)
        self._vb.addWidget(self._web)

    def _destroy_web(self) -> None:
        """Tear down the QWebEngineView and page to release the renderer."""
        self._unsupported.setVisible(False)
        self._placeholder.setVisible(True)
        if self._web is None:
            return
        self._web.setVisible(False)
        self._vb.removeWidget(self._web)
        self._web.deleteLater()
        self._web = None
        if self._page is not None:
            self._page.deleteLater()
            self._page = None

    def _on_cert_error(self, error) -> None:
        try:
            error.acceptCertificate()
        except Exception:
            pass
