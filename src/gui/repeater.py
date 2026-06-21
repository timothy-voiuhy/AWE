import os
from pathlib import Path
import queue
from PySide6.QtWidgets import QMainWindow, QVBoxLayout, QWidget, QSplitter, QTabWidget, QPushButton, QFrame
import logging
from PySide6.QtCore import QObject

from config.config import RUNDIR
from gui.actionsWidget import ActionsWidget
from gui.guiUtilities import GuiProxyClient, MessageBox, SyntaxHighlighter, TextEditor

class RepeaterReqResTextEditor(TextEditor):
    def __init__(self):
        super().__init__()
        self.setBaseSize(650, 650)
        self.setMaximumWidth(750)

class RepeaterWindow(QMainWindow, QObject):

    # tabChangeSignal  = Signal(int)
    def __init__(self, parent=None):
        super().__init__()
        self.parent = parent
        self.repeaterMainWidget = QWidget()
        self.setCentralWidget(self.repeaterMainWidget)
        self.repeaterMainWidgetLayout = QVBoxLayout()
        self.repeaterMainWidget.setLayout(self.repeaterMainWidgetLayout)

        self.repeaterSplitter = QSplitter()
        self.repeaterMainWidgetLayout.addWidget(self.repeaterSplitter)

        self.repeaterTabManager = QTabWidget()
        self.repeaterTabManager.currentChanged.connect(self.changeTabAttributes)
        self.repeaterSplitter.addWidget(self.repeaterTabManager)
        # self.addReqResInstanceTabManager()
        self.repeaterTabs = []
        self.currentTabManager = None
        self.instanceRepeaterSplitter = None
        self.req_res_tabManager = None
        self.requestsEditorFrame = None
        self.requestsEditorLayout = None
        self.requestsEditor = None
        self.repeaterSendReqButton = None
        self.responseEditor = None
        self.tabIndex = 0
        self.firstTabPresent = False
        self.responseQueue = queue.Queue()
        self.responseDir = RUNDIR + "tmp/"
        if not Path(self.responseDir).is_dir():
            os.makedirs(self.responseDir)
        self.response_file = os.path.join(self.responseDir, "response.txt")
        if not Path(self.response_file).exists():
            with open(self.response_file, "w") as f:
                f.close()
        self.changeTabAttributes()
        self.actionsWidget = ActionsWidget(self.parent, self.responseEditor)
        self.actionsWidget.setMaximumWidth(400)
        self.repeaterSplitter.addWidget(self.actionsWidget)

    def addReqResInstanceTabManager(self, request: str = None):
        instanceRepeaterSplitter = QSplitter()
        self.repeaterTabManager.addTab(instanceRepeaterSplitter, "new")

        req_res_tabManager = QTabWidget()
        instanceRepeaterSplitter.addWidget(req_res_tabManager)

        requestsEditorFrame = QFrame()
        requestsEditorFrame.setBaseSize(650, 650)
        requestsEditorFrame.setMinimumWidth(750)
        requestsEditorLayout = QVBoxLayout()
        requestsEditorFrame.setLayout(requestsEditorLayout)

        requestsEditor = RepeaterReqResTextEditor()
        if request is not None:
            requestsEditor.setText(request)
        highlighter = SyntaxHighlighter(requestsEditor.document())
        requestsEditorLayout.addWidget(requestsEditor)
        req_res_tabManager.addTab(requestsEditorFrame, "request")

        repeaterSendReqButton = QPushButton()
        repeaterSendReqButton.setText("send")
        repeaterSendReqButton.clicked.connect(self.sendRepReqToProxy)
        requestsEditorLayout.addWidget(repeaterSendReqButton)

        responseEditor = RepeaterReqResTextEditor()
        highlighter = SyntaxHighlighter(responseEditor.document())
        req_res_tabManager.addTab(responseEditor, "response")

        tabAttributes = {
            "instanceRepeaterSplitter": instanceRepeaterSplitter,
            "req_res_tabManager": req_res_tabManager,
            "requestsEditorFrame": requestsEditorFrame,
            "requestsEditorLayout": requestsEditorLayout,
            "requestsEditor": requestsEditor,
            "repeaterSendReqButton": repeaterSendReqButton,
            "responseEditor": responseEditor}

        self.repeaterTabs.append(tabAttributes)
        self.repeaterTabManager.setCurrentIndex(self.repeaterTabManager.indexOf(instanceRepeaterSplitter))
        self.firstTabPresent = True
        if self.repeaterTabManager.currentIndex() == 0:
            self.repeaterTabManager.currentChanged.emit(0)

    def changeTabAttributes(self):
        curIndex_ = self.repeaterTabManager.currentIndex()
        if self.firstTabPresent:
            self.instanceRepeaterSplitter = self.repeaterTabs[curIndex_]["instanceRepeaterSplitter"]
            self.req_res_tabManager = self.repeaterTabs[curIndex_]["req_res_tabManager"]
            self.requestsEditorFrame = self.repeaterTabs[curIndex_]["requestsEditorFrame"]
            self.requestsEditorLayout = self.repeaterTabs[curIndex_]["requestsEditorLayout"]
            self.requestsEditor = self.repeaterTabs[curIndex_]["requestsEditor"]
            self.repeaterSendReqButton = self.repeaterTabs[curIndex_]["repeaterSendReqButton"]
            self.responseEditor = self.repeaterTabs[curIndex_]["responseEditor"]

    def sendRepReqToProxy(self):
        try:
            self.guiProxyClient = GuiProxyClient(self.requestsEditor.toPlainText(), proxy_port=self.parent.proxy_port)
            self.guiProxyClient.finished.connect(self.updateResponseEditor)
            self.guiProxyClient.start()
            logging.info("Gui proxy client succesfully reached out to proxy")
        except ConnectionAbortedError or ConnectionResetError:
            logging.error("Proxy Client failed to reach out to proxy")

    def updateResponseEditor(self):
        self.responseEditor.clear()
        with open(self.response_file, 'r') as file:
            response = file.read()
        if response != "":
            self.responseEditor.setText(response)
        else:
            noDataMessageBox = MessageBox("No data",
                                          "No data has been returned from the proxy, it seems either the proxy is off or you have no internet connection",
                                          "Information",
                                          "Ok")
            noDataMessageBox.exec()

