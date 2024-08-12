
import codecs
from gui.browserWindow import BrowserWindow
from gui.guiUtilities import HoverButton
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QFormLayout, QComboBox, QTextEdit

class EncodingWidget(QWidget):
    def __init__(self, top_parent):
        super().__init__()
        self.topParent = top_parent
        self.encodingWidgetLayout = QVBoxLayout()
        self.setLayout(self.encodingWidgetLayout)
        self.upperLayout = QHBoxLayout()
        self.encodingWidgetLayout.addLayout(self.upperLayout)
        self.decodeButton = HoverButton("decode", "decode the chosen text using an appropriate decoding method")
        self.decodeButton.clicked.connect(self.decodeText)
        self.encodeButton = HoverButton("encode", "encode the text with the appropriate encoding type")
        self.encodeButton.clicked.connect(self.encodeText)
        self.upperLayout.addWidget(self.decodeButton)
        self.upperLayout.addWidget(self.encodeButton)
        self.dropDownMenu = QComboBox()
        self.addDecodeOptions()
        self.upperLayout.addWidget(self.dropDownMenu, alignment=Qt.AlignLeft)

        self.textsFormLayout = QFormLayout()

        self.textBox = QTextEdit()
        self.textBox.setWindowTitle("encoded text")
        # self.encodingWidgetLayout.addWidget(self.textBox, alignment=Qt.AlignTop)
        self.textsFormLayout.addRow("i:", self.textBox)

        self.resultTextBox = QTextEdit()
        self.resultTextBox.setWindowTitle("decoded text")
        # self.encodingWidgetLayout.addWidget(self.resultTextBox, alignment=Qt.AlignTop)
        self.textsFormLayout.addRow("o:", self.resultTextBox)

        self.encodingWidgetLayout.addLayout(self.textsFormLayout)

        self.decode_option = "base64"

    #     self.determineEncodingLayout = QHBoxLayout()
    #     self.guessButton = HoverButton("Determine Encoding", "use the availabe encoding types to try and determine the encoding type of the text")
    #     self.guessButton.clicked.connect(self.determineEncoding)
    #     self.determineEncodingLayout.addWidget(self.guessButton)

    #     self.guessLabel = QLabel()
    #     self.determineEncodingLayout.addWidget(self.guessLabel)

    #     self.encodingWidgetLayout.addLayout(self.determineEncodingLayout)

    # def determineEncoding(self):
    #     text = self.textBox.toPlainText()
    #     decoder  = codecs.getencoder(text)
    #     self.guessLabel.setText(decoder.__str__())

    def encodeText(self):
        text = self.textBox.toPlainText()
        if self.decode_option == "base64":
            encoded_text = codecs.encode(bytes(text, "utf-8"), "base64")
        #elif self.decode_option == "url":
        #   encoded_text = urlencode(text, encoding="utf-8")
        elif self.decode_option == "utf-8":
            encoded_text = codecs.utf_8_encode(text)
        elif self.decode_option == "utf-32":
            encoded_text = codecs.utf_32_encode(text)
        self.resultTextBox.clear()
        if type(encoded_text) == tuple:
            self.resultTextBox.setText(str(encoded_text[0]))
        else:
            self.resultTextBox.setText(str(encoded_text))

    def addDecodeOptions(self):
        self.dropDownMenu.addItems(["base64", "url", "utf-8", "utf-32"])
        self.dropDownMenu.textActivated.connect(self.setDecodeOption)

    def setDecodeOption(self, item):
        self.decode_option = item

    def UrlDecode(self, text):
        # if isinstance(text, bytes):
        return text.decode("url")

    def decodeUtf8(self, text):
        return text.decode("utf-8")

    def decodeBase64(self, text: bytes):
        return codecs.decode(text, "base64")

    def decodeText(self):
        text = bytes(self.textBox.toPlainText(), "utf-8")
        if self.decode_option == "base64":
            decoded_text = self.decodeBase64(text)
        elif self.decode_option == "utf-8":
            decoded_text = self.decodeUtf8(text)
        elif self.decode_option == "url":
            decoded_text = self.UrlDecode(text)
        self.resultTextBox.clear()
        if type(decoded_text) == bytes:
            self.resultTextBox.setText(str(decoded_text))
        else:
            self.resultTextBox.setText(decoded_text)


class ActionsWidget(QWidget):
    def __init__(self, top_parent, response_editor=None):
        super().__init__()
        self.responseEditor = response_editor
        self.topParent = top_parent
        self.actionWidgetLayout = QVBoxLayout()
        self.setLayout(self.actionWidgetLayout)
        self.renderButton = HoverButton("render", "render the page in a browser")
        self.renderButton.setMaximumWidth(80)
        self.renderButton.clicked.connect(self.renderPage)
        self.actionWidgetLayout.addWidget(self.renderButton)

        self.encodingWidget = EncodingWidget(self.topParent)
        self.actionWidgetLayout.addWidget(self.encodingWidget, alignment=Qt.AlignTop)

    def renderPage(self):
        browser_window = BrowserWindow()
        text = self.responseEditor.toPlainText().split("\n\n")
        # headers = text[0] # note that to get the host the headers of the requestEditor are to be got ::todo
        # headers_dict = {}
        # for header in headers.split("\r\n"):
        #     key, value = header.split(":")
        #     headers_dict[key] = value
        html = ""
        for comp in text[1:]:
            html += comp
            if comp != text[-1]:
                html += "\n\n"
        # browser_window.Page.setContent(bytes(html, "utf-8"), mimeType="html")
        browser_window.Page.setHtml(html)
        self.topParent.tabManager.addTab(browser_window, "render")

