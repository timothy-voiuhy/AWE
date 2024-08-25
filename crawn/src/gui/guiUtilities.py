import logging
import os
import socket

from PySide6.QtCore import Qt, QThread, QRegularExpression, QObject, Signal
from PySide6.QtGui import QEnterEvent, QKeyEvent, QSyntaxHighlighter, QTextCharFormat, QAction, QFont
from PySide6.QtWidgets import QPushButton, QToolTip, QTextEdit, QMessageBox, QCheckBox

from config.config import RUNDIR
from gui.threadrunners import AtomRunner, LInkFinderRunner, getAllUrlsRunner


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
        QToolTip().showText(self.mapToGlobal(self.rect().bottomLeft()), self.toolTip())


class SyntaxHighlighter(QSyntaxHighlighter):
    def __init__(self, parent=None):
        super(SyntaxHighlighter, self).__init__(parent)

        # the formats for the keywords
        keyword_fmt = QTextCharFormat()
        keyword_fmt.setForeground(Qt.yellow)
        # keyword_fmt.setFontWeight(QFont.Bold)

        keywords = [
            "class", "def", "if", "else", "elif", "for", "while", "try",
            "except", "finally", "import", "from", "as", "return", "raise"
                                                                   "\."
        ]

        # note the format of a highlight rule: [regularexpression, keywordFormat]
        self.highlightRules = [(QRegularExpression("\\b" + keyword + "\\b"), keyword_fmt) for keyword in
                               keywords]

        parentheses_words = ["\(", "\)", "\{", "\}", "\[", "\]"]

        parentheses_fmt = QTextCharFormat()
        parentheses_fmt.setForeground(Qt.yellow)
        # parentheses_fmt.setFontWeight(QFont.Bold)
        self.highlightRules.extend(
            [(QRegularExpression(keyword), parentheses_fmt) for keyword in parentheses_words]
        )

        # comments 
        comment_fmt = QTextCharFormat()
        comment_fmt.setForeground(Qt.magenta)
        # comment_fmt.setFontWeight(QFont.Bold)
        self.highlightRules.extend(
            [(QRegularExpression("#.*"), comment_fmt)]
        )

        # python classes self
        self_fmt = QTextCharFormat()
        self_fmt.setForeground(Qt.red)
        # self_fmt.setFontWeight(QFont.Bold)
        self.highlightRules.extend(
            [(QRegularExpression("self(?=\.)"), self_fmt)]
        )

        # python functions declaration after def
        func_decl_fmt = QTextCharFormat()
        func_decl_fmt.setForeground(Qt.magenta)
        # func_decl_fmt.setFontWeight(QFont.Bold)
        self.highlightRules.extend(
            [(QRegularExpression(r'(?<=def\s)\w+(?=\()'), func_decl_fmt)]
        )

        string_fmt = QTextCharFormat()
        string_fmt.setForeground(Qt.cyan)
        # string_fmt.setFontWeight(QFont.Bold)
        self.highlightRules.extend(
            [(QRegularExpression(r'(?<=\").*(?=\")'), string_fmt)]
        )

        # urls 
        url_fmt = QTextCharFormat()
        url_fmt.setForeground(Qt.green)
        # url_fmt.setFontWeight(QFont.Medium)
        url_fmt.setFontUnderline(True)
        url_fmt.setUnderlineColor(Qt.cyan)
        self.highlightRules.extend(
            [(QRegularExpression("http:\/\/.*\/|https:\/\/.*\/"), url_fmt)]
        )

        # imports_fmt
        imports_fmt = QTextCharFormat()
        imports_fmt.setForeground(Qt.red)
        imports_keywords = ["import", "from"]
        # self.highlightRules.extend(
        #     [(QRegularExpression(f"((?<={keyword_})\s.*\s)"), imports_fmt) for  keyword_ in imports_keywords]
        # )

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
        if self.icon == "Information":
            self.setIcon(QMessageBox.Information)
        elif self.icon == "Warning":
            self.setIcon(QMessageBox.Error)
        elif self.icon == "Critical":
            self.setIcon(QMessageBox.Critical)
        elif self.icon == "Question":
            self.setIcon(QMessageBox.Question)
        if self.button == "Ok":
            self.setStandardButtons(QMessageBox.Ok)
        elif self.button == "Cancel":
            self.setStandardButtons(QMessageBox.Cancel)
        if self.buttons is not None:
            for button_ in self.buttons:
                if button_ == "Ok":
                    self.addButton(QMessageBox.Ok)
                elif button_ == "Cancel":
                    self.addButton(QMessageBox.Cancel)


class ToolsRunner:
    def __init__(self, workingDir,
                 subdomain,
                 tool=None,
                 parent=None,
                 top_parent=None,
                 mainWindow=None):
        self.mainWindow = mainWindow
        self.topParent = top_parent
        self.getAllUrlsRunnerPid = 0
        self.linkFinderRunnerPid = 0
        self.atomRunnerPid = 0
        self.workingDir = workingDir
        self.subdomain = subdomain
        self.tool = tool
        self.parent = parent

    def runUrlToolsOnSd(self):
        if self.tool is not None:
            logging.info(f"Running tool {self.tool}")
        if self.tool == "getAllUrls":
            getAllUrlsRunner_ = getAllUrlsRunner(self.workingDir,
                                                 self.subdomain,
                                                 parent=self,
                                                 top_parent=self.topParent,
                                                 mainWindow=self.mainWindow)
            getAllUrlsRunner_.start()
            while True:
                if self.getAllUrlsRunnerPid == 0:
                    # handle long delays
                    continue
                else:
                    break
            return getAllUrlsRunner_.pid

        elif self.tool == "LinkFinder":

            LInkFinderRunner_ = LInkFinderRunner(self.workingDir, self.subdomain, parent=self,
                                                 top_parent=self.topParent, mainWindow=self.mainWindow)
            self.parent.threads.append(LInkFinderRunner_)
            LInkFinderRunner_.start()
            while True:
                if self.linkFinderRunnerPid == 0:
                    # handle long delays
                    continue
                else:
                    break
            return LInkFinderRunner_.pid

        elif self.tool == "Atom":

            AtomRunner_ = AtomRunner(self.subdomain,
                                     usehttp=False,
                                     useBrowser=False,
                                     parent=self,
                                     projectDirPath=self.workingDir,
                                     top_parent=self.topParent,
                                     objectName="atomRunner",
                                     mainWindow=self.mainWindow
                                     )
            AtomRunner_.start()
            while True:
                if self.atomRunnerPid == 0:
                    # handle long delays
                    continue
                else:
                    break
            return AtomRunner_.pid

        if self.tool is None:
            getAllUrlsRunner_ = getAllUrlsRunner(self.workingDir,
                                                 self.subdomain,
                                                 parent=self, top_parent=self.topParent,
                                                 mainWindow=self.mainWindow)
            getAllUrlsRunner_.start()
            g_pid = getAllUrlsRunner_.getPid()

            LInkFinderRunner_ = LInkFinderRunner(self.workingDir,
                                                 self.subdomain,
                                                 parent=self,
                                                 top_parent=self.topParent,
                                                 mainWindow=self.mainWindow)
            self.parent.append(LInkFinderRunner_)
            LInkFinderRunner_.start()
            l_pid = LInkFinderRunner_.getPid()

            AtomRunner_ = AtomRunner(self.subdomain,
                                     usehttp=False,
                                     useBrowser=False,
                                     parent=self,
                                     top_parent=self.topParent,
                                     objectName="atomRunner",
                                     mainWindow=self.mainWindow)
            AtomRunner_.start()
            a_pid = AtomRunner_.getPid()
            return g_pid, l_pid, a_pid
