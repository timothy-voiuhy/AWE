import logging
import os
import re
import socket

from PySide6.QtCore import Qt, QThread, QRegularExpression, QObject, Signal
from PySide6.QtGui import QColor, QEnterEvent, QKeyEvent, QSyntaxHighlighter, QTextCharFormat, QAction, QFont, QTextCursor
from PySide6.QtWidgets import (
    QPushButton, QToolTip, QTextEdit, QMessageBox, QCheckBox,
    QWidget, QHBoxLayout, QVBoxLayout, QLineEdit, QLabel,
    QDialog, QApplication, QScrollArea,
)

from config.config import RUNDIR


class CustomCheckBox(QCheckBox):
    def __init__(self, tootip_text, parent=None):
        super().__init__(parent)
        self.setToolTip(tootip_text)

    def enterEvent(self, event: QEnterEvent) -> None:
        QToolTip().showText(self.mapToGlobal(self.rect().bottomRight()), self.toolTip())


class GuiProxyClient(QThread):
    def __init__(self, request: str, is_command=False, proxy_port=None):
        super().__init__()
        self.setObjectName("GuiProxyClient")
        self.is_command = is_command
        self.responseDir = RUNDIR + "tmp/"
        self.respose_file = os.path.join(self.responseDir, "response.txt")
        self.request = self.makeRequestPacket(request)
        self.proxy_port = proxy_port
        self.proxyAddress = ("127.0.0.1", self.proxy_port)
        try:
            self.socket = socket.create_connection(self.proxyAddress, timeout=10)
        except ConnectionRefusedError or ConnectionAbortedError or ConnectionResetError as e:
            logging.error(f"Connection error: {e}")
            self.exit()

    def makeRequestPacket(self, request: str):
        request_lines = request.split("\n")
        new_request = ""
        for rl in request_lines:
            if request_lines.index(rl) == 0:
                new_request = rl
            else:
                new_request = new_request + "\r\n" + rl
        return new_request

    def send(self):
        try:
            self.socket.sendall(self.request.encode("utf-8"))
            # self.socket.close()
            if not self.is_command:
                response = self.socket.recv(496000)
                with open(self.respose_file, 'wb') as file:
                    file.write(response)
                self.exit()
        except Exception as e:
            logging.error(f"Encountered error: {e}")
            self.exit()

    def run(self):
        self.send()


class TextEditor(QTextEdit):
    def __init__(self, parent=None):
        super(TextEditor, self).__init__(parent)
        self.setTabChangesFocus(True)
        self.setTabStopDistance(40)
        self.setAutoIndent(True)
        self.setFontWeight(50)

    def keyPressEvent(self, event: QKeyEvent) -> None:
        if self.autoIndent and event.key() == Qt.Key.Key_Return:
            cursor = self.textCursor()
            block = cursor.block()
            text = block.text()
            cursor_position = cursor.positionInBlock()
            leading_spaces = len(text) - len(text.strip())

            if cursor_position > 0 and text.endswith((":", "{")):
                indent = leading_spaces + self.tabStopDistance() // self.fontMetrics().averageCharWidth()
                QTextEdit.keyPressEvent(self, event)
                cursor.insertText(" " * int(indent))
                return
        elif self.autoIndent and event.key() == Qt.Key.Key_Tab:
            cursor = self.textCursor()
            block = cursor.block()
            text = block.text()
            cursor_position = cursor.positionInBlock()
            leading_spaces = len(text) - len(text.strip())

            if cursor_position > 0:
                indent = leading_spaces + self.tabStopDistance() // self.fontMetrics().averageCharWidth()
                # QTextEdit.keyPressEvent(self, event)
                cursor.insertText(" " * int(indent))
                return

        QTextEdit.keyPressEvent(self, event)

    def setAutoIndent(self, enabled: bool):
        self.autoIndent = enabled


class ReqResTextEditor(TextEditor, QObject):
    sendToRepeaterSignal = Signal(str)
    sendToDecoderSignal = Signal(str)

    def __init__(self):
        super().__init__()

    def contextMenuEvent(self, event):
        menu = self.createStandardContextMenu()

        sendToRepeaterAction = QAction("send to repeater", self)
        sendToRepeaterAction.triggered.connect(self.sendRequestToRepeater)
        menu.addAction(sendToRepeaterAction)

        sendToDecoderAction = QAction("send to decoder", self)
        sendToDecoderAction.triggered.connect(self.sendHighlightedToDecoder)
        menu.addAction(sendToDecoderAction)

        menu.exec()

    def sendHighlightedToDecoder(self):
        # self.sendToDecoderSignal.emit(self.)
        pass

    def sendRequestToRepeater(self):
        # print(red("send to repeater signal has been emitted"))
        self.sendToRepeaterSignal.emit(self.toPlainText())


class HoverButton(QPushButton):
    def __init__(self, text, tooltip_text, parent=None):
        super().__init__(text, parent)
        self.setToolTip(tooltip_text)
        # self.setFlat(True)

    def enterEvent(self, event: QEnterEvent) -> None:
        QToolTip.showText(self.mapToGlobal(self.rect().bottomLeft()), self.toolTip())


class SyntaxHighlighter(QSyntaxHighlighter):
    """
    Dual-purpose highlighter: colours HTTP request/response messages AND
    generic JSON / code snippets.

    Rule tuples: (QRegularExpression, QTextCharFormat, group_index)
      group_index 0  → colour the full match
      group_index N  → colour only capture group N (lets you split one pattern
                        across multiple formats, e.g. header name vs value)
    """

    def __init__(self, parent=None):
        super().__init__(parent)

        def _fmt(color, *, bold=False, italic=False) -> QTextCharFormat:
            f = QTextCharFormat()
            f.setForeground(QColor(color))
            if bold:   f.setFontWeight(QFont.Weight.Bold)
            if italic: f.setFontItalic(True)
            return f

        def _re(pattern) -> QRegularExpression:
            return QRegularExpression(pattern)

        R = []   # (QRegularExpression, QTextCharFormat, group_index)

        # ── JSON / code body rules (applied first; HTTP rules override) ────────

        # Quoted strings — Green
        R += [
            (_re(r'"[^"\\]*(?:\\.[^"\\]*)*"'), _fmt("#A6E3A1"), 0),
            (_re(r"'[^'\\]*(?:\\.[^'\\]*)*'"), _fmt("#A6E3A1"), 0),
        ]

        # JSON true / false / null — Peach
        R += [(_re(r"\b(?:true|false|null)\b"), _fmt("#FAB387"), 0)]

        # Numbers — Lavender
        R += [(_re(r"\b\d+(?:\.\d+)?\b"), _fmt("#B4BEFE"), 0)]

        # Brackets / braces — Blue
        bracket_fmt = _fmt("#89B4FA")
        for ch in [r"\{", r"\}", r"\[", r"\]"]:
            R.append((_re(ch), bracket_fmt, 0))

        # Absolute URLs — Peach underlined
        url_fmt = _fmt("#FAB387")
        url_fmt.setFontUnderline(True)
        url_fmt.setUnderlineColor(QColor("#FAB387"))
        R.append((_re(r"https?://[^\s\"\'<>]+"), url_fmt, 0))

        # ── HTTP request / status line ─────────────────────────────────────────

        # Method — bold Blue
        _methods = "GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE"
        R.append((_re(rf"^({_methods})\b"), _fmt("#89B4FA", bold=True), 0))

        # Relative path on request line (e.g. GET /api/v1 HTTP/1.1)
        R.append((_re(rf"^(?:{_methods})\s+(/[^\s]*)"), _fmt("#FAB387"), 1))

        # HTTP version (start of status line) — dim
        R.append((_re(r"^HTTP/\S+"), _fmt("#585B70"), 0))

        # Status code by class (group 1 = the 3-digit code)
        R += [
            (_re(r"^HTTP/\S+\s+(2\d{2})\b"), _fmt("#A6E3A1", bold=True), 1),  # 2xx green
            (_re(r"^HTTP/\S+\s+(3\d{2})\b"), _fmt("#89B4FA", bold=True), 1),  # 3xx blue
            (_re(r"^HTTP/\S+\s+(4\d{2})\b"), _fmt("#F9E2AF", bold=True), 1),  # 4xx yellow
            (_re(r"^HTTP/\S+\s+(5\d{2})\b"), _fmt("#F38BA8", bold=True), 1),  # 5xx red
        ]

        # Reason phrase after status code — dim
        R.append((_re(r"^HTTP/\S+\s+\d{3}\s+(.+)$"), _fmt("#6C7086"), 1))

        # ── HTTP header lines ──────────────────────────────────────────────────
        # Pattern anchored at line start; only fires on "Name: value" lines.
        # [A-Za-z][A-Za-z0-9\-]+ then literal colon keeps false-positives minimal.

        _hdr = r"^[A-Za-z][A-Za-z0-9\-]+"

        # Header name — bold Mauve
        R.append((_re(rf"{_hdr}(?=:)"), _fmt("#CBA6F7", bold=True), 0))

        # Colon + optional space — dim (group 1)
        R.append((_re(rf"{_hdr}(:\s?)"), _fmt("#585B70"), 1))

        # Header value (everything after the colon) — Teal (group 1)
        R.append((_re(rf"{_hdr}:\s?(.+)$"), _fmt("#89DCEB"), 1))

        # cookie-specific formats (applied after base rules in highlightBlock)
        self._cookie_key_fmt = _fmt("#A6E3A1")           # green  — cookie/attr name
        self._cookie_val_fmt = _fmt("#FAB387")           # peach  — cookie/attr value
        self._cookie_sep_fmt = _fmt("#6C7086", italic=True)  # dim — = ; separators

        self._rules = R   # renamed from highlightRules to avoid external mutation

    # Pattern to detect a Cookie/Set-Cookie header line
    _COOKIE_HDR_RE = re.compile(r'^(?:Set-)?Cookie\s*:\s*', re.IGNORECASE)

    def highlightBlock(self, text: str) -> None:
        for pattern, fmt, group in self._rules:
            it = pattern.globalMatch(text)
            while it.hasNext():
                m = it.next()
                start = m.capturedStart(group)
                length = m.capturedLength(group)
                if start >= 0 and length > 0:
                    self.setFormat(start, length, fmt)

        # Cookie / Set-Cookie line — override the generic header-value teal
        # with per-token colours: key=green  =;=dim  value=peach
        hdr_m = self._COOKIE_HDR_RE.match(text)
        if hdr_m:
            self._apply_cookie_fmt(text, hdr_m.end())

    def _apply_cookie_fmt(self, text: str, value_start: int) -> None:
        """Colour each name=value pair and separator in a Cookie/Set-Cookie value."""
        parts  = text[value_start:].split(';')
        offset = value_start
        for i, part in enumerate(parts):
            if '=' in part:
                eq_idx   = part.index('=')
                key_raw  = part[:eq_idx]
                val_raw  = part[eq_idx + 1:]

                # key (strip leading whitespace, keep inner)
                leading  = len(key_raw) - len(key_raw.lstrip())
                key_body = key_raw.strip()
                if key_body:
                    self.setFormat(offset + leading, len(key_body),
                                   self._cookie_key_fmt)

                # = sign
                self.setFormat(offset + eq_idx, 1, self._cookie_sep_fmt)

                # value
                val_lead = len(val_raw) - len(val_raw.lstrip())
                val_body = val_raw.strip()
                if val_body:
                    self.setFormat(offset + eq_idx + 1 + val_lead,
                                   len(val_body), self._cookie_val_fmt)
            else:
                # bare attribute (HttpOnly, Secure, …)
                attr_raw = part
                leading  = len(attr_raw) - len(attr_raw.lstrip())
                attr     = attr_raw.strip()
                if attr:
                    self.setFormat(offset + leading, len(attr),
                                   self._cookie_key_fmt)

            offset += len(part)
            if i < len(parts) - 1:          # ; separator
                self.setFormat(offset, 1, self._cookie_sep_fmt)
                offset += 1


class SearchBar(QWidget):
    """
    Inline find-bar that attaches to a QTextEdit.
    Place it in a layout directly below the editor (or tab widget).
    Toggle visibility with activate(); hide with Escape or the ✕ button.

    Usage:
        bar = SearchBar(parent)
        layout.addWidget(bar)
        bar.set_editor(some_qtext_edit)   # call again when active editor changes
        bar.activate()                    # show + focus (Ctrl+F handler)
    """

    _MATCH_BG  = "#F9E2AF"  # all matches — yellow
    _CUR_BG    = "#FAB387"  # current match — peach
    _MATCH_FG  = "#1E1E2E"

    def __init__(self, parent=None):
        super().__init__(parent)
        self._editor  = None
        self._matches: list[QTextCursor] = []
        self._idx     = -1
        self._build_ui()
        self.hide()

    # ── public ────────────────────────────────────────────────────────────────

    def set_editor(self, editor: QTextEdit) -> None:
        """Switch the target editor (e.g. when the user changes tab)."""
        if self._editor is editor:
            return
        if self._editor is not None:
            self._editor.setExtraSelections([])
        self._editor = editor
        if self.isVisible() and self._input.text():
            self._do_search(self._input.text())

    def activate(self) -> None:
        """Show the bar and put focus in the search field."""
        self.show()
        self._input.setFocus()
        self._input.selectAll()

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        self.setFixedHeight(30)
        self.setAutoFillBackground(True)
        from PySide6.QtGui import QPalette
        pal = self.palette()
        pal.setColor(QPalette.ColorRole.Window, QColor("#181825"))
        self.setPalette(pal)

        lay = QHBoxLayout(self)
        lay.setContentsMargins(8, 3, 8, 3)
        lay.setSpacing(4)

        _inp_ss = (
            "QLineEdit{background:#1E1E2E;color:#CDD6F4;"
            "border:1px solid #45475A;border-radius:3px;padding:0 6px;}"
            "QLineEdit:focus{border-color:#89B4FA;}"
        )
        _btn_ss = (
            "QPushButton{background:transparent;color:#6C7086;border:none;"
            "padding:0 5px;font-size:11px;min-width:22px;min-height:22px;}"
            "QPushButton:hover{color:#CDD6F4;background:#313244;border-radius:3px;}"
            "QPushButton:disabled{color:#45475A;}"
        )
        _lbl_ss = "QLabel{color:#6C7086;font-size:9px;min-width:52px;}"

        self._input = QLineEdit()
        self._input.setPlaceholderText("Find…")
        self._input.setFixedHeight(22)
        self._input.setStyleSheet(_inp_ss)
        self._input.textChanged.connect(self._do_search)
        self._input.returnPressed.connect(self._next)
        lay.addWidget(self._input, stretch=1)

        self._count_lbl = QLabel("")
        self._count_lbl.setStyleSheet(_lbl_ss)
        lay.addWidget(self._count_lbl)

        prev_btn = QPushButton("▲")
        prev_btn.setToolTip("Previous (Shift+Enter)")
        prev_btn.setFixedSize(22, 22)
        prev_btn.setStyleSheet(_btn_ss)
        prev_btn.clicked.connect(self._prev)
        lay.addWidget(prev_btn)
        self._prev_btn = prev_btn

        next_btn = QPushButton("▼")
        next_btn.setToolTip("Next (Enter)")
        next_btn.setFixedSize(22, 22)
        next_btn.setStyleSheet(_btn_ss)
        next_btn.clicked.connect(self._next)
        lay.addWidget(next_btn)
        self._next_btn = next_btn

        close_btn = QPushButton("✕")
        close_btn.setToolTip("Close (Esc)")
        close_btn.setFixedSize(22, 22)
        close_btn.setStyleSheet(_btn_ss)
        close_btn.clicked.connect(self._close)
        lay.addWidget(close_btn)

    # ── search logic ──────────────────────────────────────────────────────────

    def _do_search(self, text: str) -> None:
        if self._editor is None:
            return
        self._matches.clear()
        self._idx = -1

        if not text:
            self._editor.setExtraSelections([])
            self._update_count()
            return

        doc    = self._editor.document()
        cursor = QTextCursor(doc)
        while True:
            cursor = doc.find(text, cursor)
            if cursor.isNull():
                break
            self._matches.append(QTextCursor(cursor))

        if self._matches:
            self._idx = 0

        self._rebuild_selections()
        self._update_count()

    def _rebuild_selections(self) -> None:
        """Repaint all highlights; current match gets the peach colour."""
        if self._editor is None:
            return

        match_fmt = QTextCharFormat()
        match_fmt.setBackground(QColor(self._MATCH_BG))
        match_fmt.setForeground(QColor(self._MATCH_FG))

        cur_fmt = QTextCharFormat()
        cur_fmt.setBackground(QColor(self._CUR_BG))
        cur_fmt.setForeground(QColor(self._MATCH_FG))

        sels = []
        for i, c in enumerate(self._matches):
            sel        = QTextEdit.ExtraSelection()
            sel.cursor = c
            sel.format = cur_fmt if i == self._idx else match_fmt
            sels.append(sel)

        self._editor.setExtraSelections(sels)

        if 0 <= self._idx < len(self._matches):
            self._editor.setTextCursor(self._matches[self._idx])
            self._editor.ensureCursorVisible()

    def _next(self) -> None:
        if not self._matches:
            return
        self._idx = (self._idx + 1) % len(self._matches)
        self._rebuild_selections()
        self._update_count()

    def _prev(self) -> None:
        if not self._matches:
            return
        self._idx = (self._idx - 1) % len(self._matches)
        self._rebuild_selections()
        self._update_count()

    def _update_count(self) -> None:
        n = len(self._matches)
        if not self._input.text():
            self._count_lbl.setText("")
        elif n == 0:
            self._count_lbl.setStyleSheet("QLabel{color:#F38BA8;font-size:9px;min-width:52px;}")
            self._count_lbl.setText("no results")
        else:
            self._count_lbl.setStyleSheet("QLabel{color:#6C7086;font-size:9px;min-width:52px;}")
            self._count_lbl.setText(f"{self._idx + 1} / {n}")
        nav_ok = bool(self._matches)
        self._prev_btn.setEnabled(nav_ok)
        self._next_btn.setEnabled(nav_ok)

    def _close(self) -> None:
        if self._editor is not None:
            self._editor.setExtraSelections([])
        self._matches.clear()
        self._idx = -1
        self._input.clear()
        self.hide()
        if self._editor is not None:
            self._editor.setFocus()

    def keyPressEvent(self, event) -> None:
        if event.key() == Qt.Key_Escape:
            self._close()
        elif event.key() in (Qt.Key_Return, Qt.Key_Enter):
            if event.modifiers() & Qt.ShiftModifier:
                self._prev()
            else:
                self._next()
        else:
            super().keyPressEvent(event)


# ── Header clipboard (app-level, not system clipboard) ────────────────────────

_HEADER_CLIPBOARD: list[tuple[str, str]] = []


def parse_http_headers(text: str) -> list[tuple[str, str]]:
    """Return all headers from an HTTP message as [(name, value), …]."""
    lines = text.split('\n')
    hdrs: list[tuple[str, str]] = []
    for line in lines[1:]:          # skip request/status line
        if not line.strip():
            break
        if ':' in line:
            name, _, value = line.partition(':')
            hdrs.append((name.strip(), value.strip()))
    return hdrs


def set_header_clipboard(headers: list[tuple[str, str]]) -> None:
    global _HEADER_CLIPBOARD
    _HEADER_CLIPBOARD = headers


def copy_headers_from_text(text: str) -> int:
    """Copy ALL headers from *text* into the header clipboard. Returns count."""
    hdrs = parse_http_headers(text)
    set_header_clipboard(hdrs)
    return len(hdrs)


class HeaderSelectorDialog(QDialog):
    """Checkbox list that lets the user pick which headers to copy."""

    def __init__(self, headers: list[tuple[str, str]], parent=None):
        super().__init__(parent)
        self.setWindowTitle("Select Headers to Copy")
        self.setMinimumSize(520, 380)
        self._checks: list[tuple[QCheckBox, tuple[str, str]]] = []
        self._build_ui(headers)

    # ── public ────────────────────────────────────────────────────────────────

    def selected_headers(self) -> list[tuple[str, str]]:
        return [hdr for cb, hdr in self._checks if cb.isChecked()]

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build_ui(self, headers: list[tuple[str, str]]) -> None:
        self.setStyleSheet(
            "QDialog{background:#1E1E2E;}"
            "QLabel{color:#6C7086;font-size:9px;background:transparent;}"
            "QCheckBox{color:#CDD6F4;font-family:'Cascadia Code';font-size:9px;spacing:6px;}"
            "QCheckBox::indicator{width:13px;height:13px;"
            "border:1px solid #45475A;border-radius:2px;background:#181825;}"
            "QCheckBox::indicator:checked{background:#89B4FA;border-color:#89B4FA;}"
            "QScrollArea{border:1px solid #313244;border-radius:4px;}"
            "QPushButton{background:#313244;color:#CDD6F4;border:1px solid #45475A;"
            "border-radius:4px;padding:0 12px;min-height:24px;font-size:9px;}"
            "QPushButton:hover{background:#45475A;}"
        )
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 10, 12, 10)
        root.setSpacing(8)

        root.addWidget(QLabel(
            f"{len(headers)} header{'s' if len(headers) != 1 else ''} found"
            " — uncheck any you don't want to copy:"
        ))

        scroll  = QScrollArea()
        scroll.setWidgetResizable(True)
        inner   = QWidget()
        inner.setStyleSheet("QWidget{background:#11111B;}")
        inner_vb = QVBoxLayout(inner)
        inner_vb.setContentsMargins(8, 8, 8, 8)
        inner_vb.setSpacing(3)

        for name, value in headers:
            label = f"{name}: {value[:120]}{'…' if len(value) > 120 else ''}"
            cb    = QCheckBox(label)
            cb.setChecked(True)
            cb.setToolTip(f"{name}: {value}")
            inner_vb.addWidget(cb)
            self._checks.append((cb, (name, value)))

        inner_vb.addStretch()
        scroll.setWidget(inner)
        root.addWidget(scroll, stretch=1)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(6)

        sel_btn = QPushButton("Select All")
        sel_btn.clicked.connect(lambda: [cb.setChecked(True)  for cb, _ in self._checks])
        btn_row.addWidget(sel_btn)

        desel_btn = QPushButton("Deselect All")
        desel_btn.clicked.connect(lambda: [cb.setChecked(False) for cb, _ in self._checks])
        btn_row.addWidget(desel_btn)

        btn_row.addStretch()

        ok_btn = QPushButton("Copy Selected")
        ok_btn.setStyleSheet(
            "QPushButton{background:#1E3A2F;color:#A6E3A1;border:1px solid #A6E3A1;"
            "border-radius:4px;padding:0 14px;min-height:24px;font-size:9px;}"
            "QPushButton:hover{background:#2A4A3F;}"
        )
        ok_btn.clicked.connect(self.accept)
        btn_row.addWidget(ok_btn)

        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        btn_row.addWidget(cancel_btn)

        root.addLayout(btn_row)

    def keyPressEvent(self, event) -> None:
        if event.key() == Qt.Key_Escape:
            self.reject()
        else:
            super().keyPressEvent(event)


def paste_headers(text: str, mode: str) -> str | None:
    """
    Apply the header clipboard to *text*.
    mode='replace' → discard existing headers, insert copied ones.
    mode='add'     → keep existing headers, append any that aren't already
                     present (matched case-insensitively by name).
    Returns the modified HTTP message, or None when the clipboard is empty.
    """
    if not _HEADER_CLIPBOARD:
        return None

    lines   = text.split('\n')
    if not lines:
        return None

    req_line = lines[0]
    existing: list[str] = []
    body_idx = len(lines)

    for i, line in enumerate(lines[1:], 1):
        if not line.strip():
            body_idx = i
            break
        existing.append(line)

    body = '\n'.join(lines[body_idx:])

    if mode == 'replace':
        new_hdrs = [f"{n}: {v}" for n, v in _HEADER_CLIPBOARD]
    else:  # 'add'
        existing_names = {ln.partition(':')[0].strip().lower() for ln in existing}
        new_hdrs = list(existing)
        for n, v in _HEADER_CLIPBOARD:
            if n.lower() not in existing_names:
                new_hdrs.append(f"{n}: {v}")

    parts = [req_line] + new_hdrs + ['']
    if body.strip():
        parts.append(body)
    return '\n'.join(parts)


def has_copied_headers() -> bool:
    return bool(_HEADER_CLIPBOARD)


# ── Decode utilities ──────────────────────────────────────────────────────────

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


def format_http_body(text: str, fmt: str) -> str | None:
    """
    Format the body section of an HTTP message (headers + blank line + body).
    *fmt* is one of 'json' | 'xml' | 'html' | 'javascript'.
    Returns the reassembled message with the formatted body, or None on failure.
    """
    idx = text.find('\n\n')
    if idx == -1:
        return None
    headers = text[:idx]
    body    = text[idx + 2:].strip()
    if not body:
        return None

    formatted = None

    if fmt == 'json':
        try:
            import json
            formatted = json.dumps(json.loads(body), indent=2, ensure_ascii=False)
        except Exception:
            pass

    elif fmt == 'xml':
        try:
            import xml.dom.minidom
            pretty = xml.dom.minidom.parseString(body.encode('utf-8')).toprettyxml(indent='  ')
            # Strip auto-added declaration if the original didn't have one
            if not body.lstrip().startswith('<?xml'):
                lines  = pretty.splitlines()
                pretty = '\n'.join(ln for ln in lines[1:] if ln.strip())
            formatted = pretty
        except Exception:
            pass

    elif fmt == 'html':
        try:
            from bs4 import BeautifulSoup
            formatted = BeautifulSoup(body, 'html.parser').prettify()
        except Exception:
            pass

    elif fmt == 'javascript':
        try:
            import jsbeautifier
            formatted = jsbeautifier.beautify(body)
        except Exception:
            pass

    if formatted is None:
        return None
    return headers + '\n\n' + formatted


class MessageBox(QMessageBox):
    """Wrapper class for a QMessageBox
    icon: can be either of [Information, Warning, Critical, Question]
    buttons: can be one or more of :
    ButtonMask, NoButton ,Default ,Escape ,FlagMask, FirstButton, Ok,
    Save, SaveAll, Open, Yes, YesAll, YesToAll, No, NoAll, NoToAll, Abort
    Retry ,Ignore, Close, Cancel, Discard, Help, Apply, Reset, LastButton
    RestoreDefaults"""

    def __init__(self, windowTitle: str = None, text: str = None, icon: str = None, button=None, buttons: list = None):
        super().__init__()
        self.windowTitle_ = windowTitle
        self.button = button
        self.text = text
        self.icon = icon
        self.buttons = buttons
        self.setWindowTitle(self.windowTitle_)
        self.setText(self.text)
        _icon_map = {
            "Information": QMessageBox.Icon.Information,
            "Warning":     QMessageBox.Icon.Warning,
            "Critical":    QMessageBox.Icon.Critical,
            "Question":    QMessageBox.Icon.Question,
        }
        if self.icon in _icon_map:
            self.setIcon(_icon_map[self.icon])
        _btn_map = {
            "Ok":     QMessageBox.StandardButton.Ok,
            "Cancel": QMessageBox.StandardButton.Cancel,
            "Yes":    QMessageBox.StandardButton.Yes,
            "No":     QMessageBox.StandardButton.No,
        }
        if self.button in _btn_map:
            self.setStandardButtons(_btn_map[self.button])
        if self.buttons is not None:
            mapped = [_btn_map[b] for b in self.buttons if b in _btn_map]
            if mapped:
                combined = mapped[0]
                for b in mapped[1:]:
                    combined = combined | b
                self.setStandardButtons(combined)


