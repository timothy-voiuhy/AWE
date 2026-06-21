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
    def __init__(self, parent=None):
        super(SyntaxHighlighter, self).__init__(parent)

        # Keywords — Mauve #CBA6F7
        keyword_fmt = QTextCharFormat()
        keyword_fmt.setForeground(QColor("#CBA6F7"))
        keywords = [
            "class", "def", "if", "else", "elif", "for", "while", "try",
            "except", "finally", "import", "from", "as", "return", "raise",
        ]
        self.highlightRules = [
            (QRegularExpression("\\b" + kw + "\\b"), keyword_fmt) for kw in keywords
        ]

        # Brackets — Blue #89B4FA
        bracket_fmt = QTextCharFormat()
        bracket_fmt.setForeground(QColor("#89B4FA"))
        self.highlightRules.extend(
            (QRegularExpression(ch), bracket_fmt)
            for ch in [r"\(", r"\)", r"\{", r"\}", r"\[", r"\]"]
        )

        # Comments — Overlay1 #7F849C
        comment_fmt = QTextCharFormat()
        comment_fmt.setForeground(QColor("#7F849C"))
        comment_fmt.setFontItalic(True)
        self.highlightRules.append((QRegularExpression("#.*"), comment_fmt))

        # self — Sapphire #74C7EC
        self_fmt = QTextCharFormat()
        self_fmt.setForeground(QColor("#74C7EC"))
        self.highlightRules.append((QRegularExpression(r"self(?=\.)"), self_fmt))

        # Function names after def — Blue #89B4FA bold
        func_fmt = QTextCharFormat()
        func_fmt.setForeground(QColor("#89B4FA"))
        func_fmt.setFontWeight(QFont.Weight.Bold)
        self.highlightRules.append((QRegularExpression(r"(?<=def\s)\w+(?=\()"), func_fmt))

        # Strings — Green #A6E3A1
        string_fmt = QTextCharFormat()
        string_fmt.setForeground(QColor("#A6E3A1"))
        self.highlightRules.append((QRegularExpression(r'"[^"]*"'), string_fmt))
        self.highlightRules.append((QRegularExpression(r"'[^']*'"), string_fmt))

        # URLs — Peach #FAB387 underlined
        url_fmt = QTextCharFormat()
        url_fmt.setForeground(QColor("#FAB387"))
        url_fmt.setFontUnderline(True)
        url_fmt.setUnderlineColor(QColor("#FAB387"))
        self.highlightRules.append(
            (QRegularExpression(r"https?://[^\s\"\'>]+"), url_fmt)
        )

    def highlightBlock(self, text: str) -> None:
        for pattern, format in self.highlightRules:
            expression = QRegularExpression(pattern)
            match_iter = expression.globalMatch(text)
            while match_iter.hasNext():
                match = match_iter.next()
                index = match.capturedStart()
                length = match.capturedLength()
                self.setFormat(index, length, format)


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


