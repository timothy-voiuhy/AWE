import re

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit, QPushButton, QApplication,
)

from gui.utilities.syntax_highlighter import SyntaxHighlighter


def decode_text(text: str, method: str) -> tuple[str | None, str]:
    """
    Decode *text* using the given method.
    method: 'auto' | 'base64' | 'url' | 'html' | 'hex' | 'jwt' | 'unicode'
    Returns (decoded_str, method_label) or (None, method_label) on failure.
    """
    text = text.strip()
    if not text:
        return None, method

    if method == 'auto':
        # URL — only when explicit %XX sequences are present
        if re.search(r'%[0-9a-fA-F]{2}', text):
            r, m = decode_text(text, 'url')
            if r is not None:
                return r, m
        # HTML entities
        if '&' in text and ';' in text:
            r, m = decode_text(text, 'html')
            if r is not None:
                return r, m
        # JWT — exactly 2 dots, each part looks like base64
        if text.count('.') == 2:
            r, m = decode_text(text, 'jwt')
            if r is not None:
                return r, m
        # Base64 — only when text matches base64 alphabet
        if re.fullmatch(r'[A-Za-z0-9+/\-_=]+', text) and len(text) >= 4:
            r, m = decode_text(text, 'base64')
            if r is not None and r != text:
                return r, m
        # Unicode escapes
        if r'\\u' in text or r'\\x' in text or '\\u' in text or '\\x' in text:
            r, m = decode_text(text, 'unicode')
            if r is not None:
                return r, m
        # Hex
        _clean = re.sub(r'[\s\-:]+', '', text)
        if re.fullmatch(r'[0-9a-fA-F]+', _clean) and len(_clean) % 2 == 0 and len(_clean) >= 4:
            r, m = decode_text(text, 'hex')
            if r is not None:
                return r, m
        return None, 'Auto'

    if method == 'url':
        from urllib.parse import unquote_plus
        decoded = unquote_plus(text)
        return (decoded, 'URL') if decoded != text else (None, 'URL')

    if method == 'base64':
        import base64 as _b64
        for fn in (_b64.b64decode, _b64.urlsafe_b64decode):
            try:
                padded = text + '=' * ((4 - len(text) % 4) % 4)
                raw    = fn(padded)
                try:
                    return raw.decode('utf-8'), 'Base64'
                except UnicodeDecodeError:
                    return raw.hex(' '), 'Base64 → Hex'
            except Exception:
                continue
        return None, 'Base64'

    if method == 'html':
        import html as _html
        decoded = _html.unescape(text)
        return (decoded, 'HTML Entities') if decoded != text else (None, 'HTML Entities')

    if method == 'hex':
        clean = re.sub(r'[\s\-:]+', '', text)
        clean = re.sub(r'(?i)^0x|\\x', '', clean)
        if re.fullmatch(r'[0-9a-fA-F]+', clean) and len(clean) % 2 == 0:
            try:
                raw = bytes.fromhex(clean)
                try:
                    return raw.decode('utf-8'), 'Hex'
                except UnicodeDecodeError:
                    return raw.decode('latin-1'), 'Hex → Latin-1'
            except Exception:
                pass
        return None, 'Hex'

    if method == 'jwt':
        parts = text.split('.')
        if len(parts) == 3:
            try:
                import base64 as _b64, json as _json
                def _b64d(s):
                    s += '=' * ((4 - len(s) % 4) % 4)
                    return _json.loads(_b64.urlsafe_b64decode(s))
                result = _json.dumps(
                    {'header': _b64d(parts[0]), 'payload': _b64d(parts[1]),
                     'signature': parts[2]},
                    indent=2, ensure_ascii=False,
                )
                return result, 'JWT'
            except Exception:
                pass
        return None, 'JWT'

    if method == 'unicode':
        try:
            decoded = text.encode('raw_unicode_escape').decode('unicode_escape')
            return (decoded, 'Unicode Escape') if decoded != text else (None, 'Unicode Escape')
        except Exception:
            pass
        return None, 'Unicode Escape'

    return None, method


class DecodeDialog(QDialog):
    """Non-modal popup that shows a decoded string with syntax highlighting."""

    def __init__(self, decoded: str, method: str, parent=None):
        super().__init__(parent)
        self.setAttribute(Qt.WA_DeleteOnClose)
        self.setWindowTitle(f"Decoded — {method}")
        self.resize(580, 340)
        self._decoded = decoded
        self._build_ui(decoded, method)

    def _build_ui(self, decoded: str, method: str) -> None:
        self.setStyleSheet(
            "QDialog{background:#1E1E2E;}"
            "QLabel{color:#6C7086;font-size:9px;background:transparent;}"
            "QPushButton{background:#313244;color:#CDD6F4;"
            "border:1px solid #45475A;border-radius:4px;"
            "padding:0 16px;min-height:26px;font-size:9px;}"
            "QPushButton:hover{background:#45475A;}"
        )
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 10, 12, 10)
        root.setSpacing(6)

        hdr = QLabel(f"Method: {method}")
        hdr.setStyleSheet("color:#A6E3A1;font-size:9px;background:transparent;")
        root.addWidget(hdr)

        view = QTextEdit()
        view.setReadOnly(True)
        view.setPlainText(decoded)
        view.setFont(QFont("Cascadia Code", 9))
        view.setStyleSheet(
            "QTextEdit{background:#11111B;color:#CDD6F4;"
            "border:1px solid #313244;border-radius:4px;padding:8px;}"
        )
        SyntaxHighlighter(view.document())
        root.addWidget(view, stretch=1)

        btn_row = QHBoxLayout()
        btn_row.setContentsMargins(0, 4, 0, 0)
        btn_row.addStretch()

        copy_btn = QPushButton("Copy")
        copy_btn.clicked.connect(
            lambda: QApplication.clipboard().setText(self._decoded))
        btn_row.addWidget(copy_btn)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.close)
        btn_row.addWidget(close_btn)

        root.addLayout(btn_row)

    def keyPressEvent(self, event) -> None:
        if event.key() == Qt.Key_Escape:
            self.close()
        else:
            super().keyPressEvent(event)
