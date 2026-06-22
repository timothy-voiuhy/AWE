from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QTextEdit, QLineEdit
from gui.guiUtilities import SyntaxHighlighter
from ._constants import _NS, _KIND_ICON


# ── Req/resp pane helpers ─────────────────────────────────────────────────────

class _ReqRespPane(QWidget):
    """Labelled header + body container, styled like the repeater panes."""

    def __init__(self, label: str, color: str, parent=None):
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


class _ReqRespCodeView(QTextEdit):
    """Read-only monospace viewer with HTTP syntax highlighting."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setFont(QFont("Cascadia Code", 9))
        self.setLineWrapMode(QTextEdit.NoWrap)
        self.setStyleSheet(
            "QTextEdit{background:#11111B; color:#CDD6F4; border:none; padding:8px;}"
        )
        self._hl = SyntaxHighlighter(self.document())


# ── Traffic formatting helpers ────────────────────────────────────────────────

def _fmt_req(req: dict) -> str:
    lines = [f"{req.get('method', '')} {req.get('url', '')}"]
    for k, v in (req.get("headers") or {}).items():
        for val in ([v] if isinstance(v, str) else v):
            lines.append(f"{k}: {val}")
    body = req.get("body", "")
    if body:
        lines += ["", body]
    return "\n".join(lines)


def _fmt_resp(resp: dict) -> str:
    lines = [
        f"{resp.get('http_version', 'HTTP/1.1')} "
        f"{resp.get('status_code', '')} "
        f"{resp.get('reason', '')}"
    ]
    for k, v in (resp.get("headers") or {}).items():
        for val in ([v] if isinstance(v, str) else v):
            lines.append(f"{k}: {val}")
    body = resp.get("body", "")
    if body:
        lines += ["", body]
    return "\n".join(lines)


# ── Search bar widget ─────────────────────────────────────────────────────────

class _SearchEdit(QLineEdit):
    """QLineEdit that clears itself on Escape."""
    def keyPressEvent(self, ev):
        if ev.key() == Qt.Key_Escape:
            self.clear()
        else:
            super().keyPressEvent(ev)


# ── Legend chip ───────────────────────────────────────────────────────────────

def _legend_chip(kind: str) -> QLabel:
    s = _NS[kind]
    icon = _KIND_ICON.get(kind, "○")
    chip = QLabel(f" {icon} {kind} ")
    chip.setStyleSheet(f"""
        QLabel {{
            background:{s['fill']}; color:#1E1E2E;
            border-radius:8px; font-size:8px;
            padding:2px 6px; font-weight:bold;
        }}
    """)
    return chip
