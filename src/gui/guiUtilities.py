import logging
import os
import socket

from PySide6.QtCore import Qt, QThread, QRegularExpression, QObject, Signal
from PySide6.QtGui import QColor, QEnterEvent, QKeyEvent, QSyntaxHighlighter, QTextCharFormat, QAction, QFont
from PySide6.QtWidgets import QPushButton, QToolTip, QTextEdit, QMessageBox, QCheckBox

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

        self._rules = R   # renamed from highlightRules to avoid external mutation

    def highlightBlock(self, text: str) -> None:
        for pattern, fmt, group in self._rules:
            it = pattern.globalMatch(text)
            while it.hasNext():
                m = it.next()
                start = m.capturedStart(group)
                length = m.capturedLength(group)
                if start >= 0 and length > 0:
                    self.setFormat(start, length, fmt)


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


