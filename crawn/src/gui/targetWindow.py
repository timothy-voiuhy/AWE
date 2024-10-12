from PySide6 import QtWidgets, QtGui
from PySide6.QtCore import Qt
from PySide6.QtNetwork import QSslCertificate, QSslConfiguration, QNetworkProxyFactory, QNetworkProxy
from PySide6.QtWidgets import QMenuBar

from awe_net.wappy import find_techs
from config.config import RUNDIR
from gui.browserWindow import BrowserWindow
from gui.guiUtilities import HoverButton
from gui.leftDock import LeftDock
from gui.lowerDock import LowerDock
from gui.networkWindow import NetworkWindow
from gui.rightDock import RightDock
from gui.testtargetwindow import TestTargetWindow


class TargetWindow(QtWidgets.QMainWindow):
    def __init__(self, project_dir_path: str, proxy_port, top_parent, index):
        super().__init__()
        self.main_server_name = None
        self.projectIndex = index
        self.topParent = top_parent
        self.rootCACertificate = None
        self.current_tab_index = None
        self.projectDirPath = project_dir_path
        self.getMainSeverName()
        self.threads = []
        self.setObjectName(self.projectDirPath)
        # Docks
        lowerDock = LowerDock(self, self.projectDirPath)
        self.LowerDock = lowerDock.InitializeLowerDock()
        self.LowerDock.setVisible(False)
        rightDock = RightDock(self, self.projectDirPath)
        self.RightDock = rightDock.InitializeDock()
        self.RightDock.setVisible(False)
        leftdock = LeftDock(self, self.projectDirPath, parent=self, top_parent=self.topParent)
        leftdock.openLinkInBrw.connect(self.openNewBrowserTab)
        self.LeftDock = leftdock.InitializeLeftDock()

        # central widget
        centralWidget = QtWidgets.QWidget()
        self.centralWidgetLayout = QtWidgets.QVBoxLayout()

        self.centralWidgetSplitter = QtWidgets.QSplitter(Qt.Vertical)
        self.centralWidgetLayout.addWidget(self.centralWidgetSplitter)
        # self.AddTopMenu()

        self.proxy = QNetworkProxy()

        self.browserMainWindow = QtWidgets.QMainWindow()
        self.centralWidgetSplitter.addWidget(self.browserMainWindow)
        # self.centralWidgetLayout.addWidget(self.browserMainWindow)

        self.browserMainWindowCentralWidget = QtWidgets.QWidget()
        self.browserMainWindow.setCentralWidget(self.browserMainWindowCentralWidget)

        self.browserMainWindowLayout = QtWidgets.QVBoxLayout()
        self.browserMainWindowCentralWidget.setLayout(self.browserMainWindowLayout)

        self.browserTabWidget = QtWidgets.QTabWidget()
        self.browserMainWindowLayout.addWidget(self.browserTabWidget)
        self.openNewBrowserTab()

        centralWidget.setLayout(self.centralWidgetLayout)
        self.setCentralWidget(centralWidget)

        self.targetwindowMenu = self.browserMainWindow.menuBar()

        self.AddTopMenu()

        # network button
        self.NetworkButtonIcon = QtGui.QIcon.fromTheme("network-wired")
        self.NetworkAction = QtGui.QAction()
        self.NetworkAction.setIcon(self.NetworkButtonIcon)
        self.NetworkAction.setIconText("network")
        self.NetworkAction.triggered.connect(self.OpenNetworkWindow)
        self.targetwindowMenu.addAction(self.NetworkAction)

        # add new browser tab
        self.newBrowserTabAction = QtGui.QAction("new")
        self.newBrowserTabAction.triggered.connect(self.openNewBrowserTab)
        self.targetwindowMenu.addAction(self.newBrowserTabAction)

        # close Browser Tab
        self.closeTabAction = QtGui.QAction("close")
        self.closeTabAction.triggered.connect(self.closeBrowserTab)
        self.targetwindowMenu.addAction(self.closeTabAction)

        self.proxy_status = False

        #dev tools button
        self.devToolsAction = QtGui.QAction("dev")
        self.devToolsAction.triggered.connect(self.showdevTools)
        self.targetwindowMenu.addAction(self.devToolsAction)

        # disable proxy tab
        self.handleProxyAction = QtGui.QAction("enableProxy")
        self.handleProxyAction.triggered.connect(self.HandleProxy)
        self.targetwindowMenu.addAction(self.handleProxyAction)

        # test target button
        self.testTargetAction = QtGui.QAction("testTarget")
        self.testTargetAction.triggered.connect(self.OpenTestTargetWindow)
        self.targetwindowMenu.addAction(self.testTargetAction)

        # wappylzer button
        self.wapplyzerAction = QtGui.QAction("wappy")
        self.wapplyzerAction.triggered.connect(self.runWappalzer)
        self.targetwindowMenu.addAction(self.wapplyzerAction)

        self.setWindowTitle("atom")

        self.centralWidgetLayout.addStretch()
        self.proxy_port = proxy_port
        self.topParent.newProjectCreated.emit(self)

    def runWappalzer(self):
        
        # get the url
        url = self.browserTabWidget.currentWidget().browser.url().url()

        self.wappylzerDisplayWidget = QtWidgets.QWidget();
        self.wappylzerDisplayWidget.setMaximumHeight(300)
        self.wappylzerDisplayWidget.setObjectName("wappalzer")
        self.wappylzerDisplayWidgetLayout = QtWidgets.QVBoxLayout()
        self.wappylzerDisplayWidget.setLayout(self.wappylzerDisplayWidgetLayout)

        self.wappylzerTextBrowser = QtWidgets.QTextBrowser()
        self.wappylzerDisplayWidgetLayout.addWidget(self.wappylzerTextBrowser)
        self.wappylzerTextBrowser.clear()
        # run wappylzer
        __return_data = find_techs(url)
        self.wappylzerTextBrowser.setText(__return_data)
        if self.centralWidgetSplitter.widget(1) is not None:
            self.centralWidgetSplitter.widget(1).deleteLater()
        self.centralWidgetSplitter.addWidget(self.wappylzerDisplayWidget)

    def showdevTools(self):
        pass

    def getMainSeverName(self):
        if not self.projectDirPath.endswith("/"):
            self.main_server_name = self.projectDirPath.split("/")[-1]

    def closeEvent(self, event: QtGui.QCloseEvent) -> None:
        self.topParent.projectClosed.emit(self, self.projectIndex)
        return super().closeEvent(event)

    def openNewBrowserTab(self, link=None):
        tab_name = "new"
        try:
            if type(link) is bool:
                BrowserWindow_ = BrowserWindow("google.com")
            elif link is not None:
                BrowserWindow_ = BrowserWindow(link)
                if link.startswith(("https", "http")):
                    tab_name = link.split("//")[1].split(".")[0]
                else:
                    tab_name = link.split(".")[0]
            elif link is None:
                BrowserWindow_ = BrowserWindow("google.com")
        except:
            tab_name = "new"
        self.browserTabWidget.addTab(BrowserWindow_, tab_name)
        self.browserTabWidget.setCurrentIndex(
            self.browserTabWidget.indexOf(BrowserWindow_)
        )

    def closeBrowserTab(self):
        self.current_tab_index = self.browserTabWidget.currentIndex()
        if self.current_tab_index != 0:
            self.browserTabWidget.removeTab(self.current_tab_index)

    def HandleProxy(self):
        if self.proxy_status is False:
            self.enableProxy(use_default=True)
            self.handleProxyAction.setText("DisableProxy")
            self.proxy_status = True
        else:
            self.handleProxyAction.setText("EnableProxy")
            self.proxy_status = False
            QNetworkProxyFactory.setUseSystemConfiguration(True)

    def enableProxy(self, use_default=False):
        if use_default:
            self.proxy_hostname = "127.0.0.1"
            self.proxy_port = self.proxy_port
            
            self.proxy.setType(QNetworkProxy.HttpProxy)
            self.proxy.setHostName(self.proxy_hostname)
            self.proxy.setPort(self.proxy_port)
            QNetworkProxy.setApplicationProxy(self.proxy)
        else:
            self.enableProxyCheckBox.setChecked(True)
            self.proxy_hostname = self.proxyHostNameLineEdit.text()
            if self.proxy_hostname == " ":
                self.proxy_hostname = "127.0.0.1"
            try:
                self.proxy_port = int(self.proxyPortNameLineEdit.text())
                if self.proxy_port == " ":
                    self.proxy_port = self.proxy_port
                self.proxy.setType(QNetworkProxy.HttpProxy)
                self.proxy.setHostName(self.proxy_hostname)
                self.proxy.setPort(self.proxy_port)
                QNetworkProxy.setApplicationProxy(self.proxy)
                self.enableProxyCheckBox.setChecked(True)
                self.LoadCA_Certificate()
            except ValueError:
                self.proxyPortNameLineEdit.setStyleSheet("QLineEdit{border: 2px solid red;}")
                self.enableProxyCheckBox.setChecked(False)

    def OpenTestTargetWindow(self):
        self.testWindow = TestTargetWindow(self.projectDirPath, parent=self, top_parent=self.topParent)
        self.testWindow.Initialize()
        self.testWindow.setFixedHeight(600)
        self.testWindow.setFixedWidth(800)
        self.testWindow.show()

    def OpenNetworkWindow(self):
        self.networkWindow = NetworkWindow()
        self.NetworkWindow_ = self.networkWindow.IniatializeNetworkWindow()
        self.networkWindow.resize(800, 600)
        self.networkWindow.show()

    def AddTopMenu(self):
        # top menu
        self.MenuIcon = QtGui.QIcon(RUNDIR + "resources/icons/settings-icon-gear-3d-render-png.png")
        self.centralWidgetMenu = QtWidgets.QMenu()
        self.centralWidgetMenu.setIcon(self.MenuIcon)
        a_Open = self.centralWidgetMenu.addMenu("open")
        a_openProjects = a_Open.addAction("projects")
        a_openProjects.triggered.connect(self.OpenProject)
        self.centralWidgetMenu.addSeparator()
        a_viewMenu = self.centralWidgetMenu.addMenu("view")
        a_terminal = a_viewMenu.addAction("terminal")
        a_terminal.triggered.connect(self.ViewTerminal)
        target = a_viewMenu.addAction("target")
        target.triggered.connect(self.ViewTarget)
        notePad = a_viewMenu.addAction("notepad")
        notePad.triggered.connect(self.ViewNotepad)
        self.centralWidgetMenu.addSeparator()
        BrowserSettings_action = self.centralWidgetMenu.addAction("Browser settings")
        BrowserSettings_action.triggered.connect(self.openBrowserSettingsWindow)
        self.targetwindowMenu.addMenu(self.centralWidgetMenu)

    def openBrowserSettingsWindow(self):
        self.BrowserSettingsWindow = QtWidgets.QMainWindow()
        self.BrowserSettingsWindowWidget = QtWidgets.QWidget()
        self.BrowserSettingsWindow.setCentralWidget(self.BrowserSettingsWindowWidget)

        self.BrowserSettingsWindowLayout = QtWidgets.QVBoxLayout()
        self.BrowserSettingsWindowWidget.setLayout(self.BrowserSettingsWindowLayout)

        self.ProxyLabel = QtWidgets.QLabel()
        self.ProxyLabel.setText("<b>Proxy Settings</b>")
        self.BrowserSettingsWindowLayout.addWidget(self.ProxyLabel)

        self.enableProxyLayout = QtWidgets.QFormLayout()

        self.enableProxyCheckBox = QtWidgets.QCheckBox()
        self.enableProxyLabel = QtWidgets.QLabel()
        self.enableProxyLabel.setText("enable Proxy")
        self.enableProxyLayout.addRow(self.enableProxyLabel, self.enableProxyCheckBox)

        self.proxyhostNameLabel = QtWidgets.QLabel()
        self.proxyhostNameLabel.setText("HostName:")
        self.proxyHostNameLineEdit = QtWidgets.QLineEdit()
        self.proxyHostNameLineEdit.setPlaceholderText("127.0.0.1")
        self.enableProxyLayout.addRow(self.proxyhostNameLabel, self.proxyHostNameLineEdit)

        self.proxyPortLabel = QtWidgets.QLabel()
        self.proxyPortLabel.setText("HostName:")
        self.proxyPortNameLineEdit = QtWidgets.QLineEdit()
        self.proxyPortNameLineEdit.setPlaceholderText("8081")
        self.enableProxyLayout.addRow(self.proxyPortLabel, self.proxyPortNameLineEdit)

        self.proxyDoneButton = QtWidgets.QPushButton()
        self.proxyDoneButton.setText("Yes")
        self.proxyDoneButton.clicked.connect(self.enableProxy)
        self.enableProxyLayout.addRow("do you want to set the proxy ?:", self.proxyDoneButton)

        self.BrowserSettingsWindowLayout.addLayout(self.enableProxyLayout)
        self.BrowserSettingsWindowLayout.addStretch()

        self.BrowserSettingsWindow.setFixedHeight(600)
        self.BrowserSettingsWindow.setFixedWidth(600)
        self.BrowserSettingsWindow.show()

    def LowerDockClick(self):
        self.LowerDock.activateWindow()

    def ViewTarget(self):
        self.LeftDock.setVisible(True)

    def ViewTerminal(self):
        self.LowerDock.setVisible(True)

    def OpenProject(self):
        file_menu = QtWidgets.QFileDialog()
        filename = file_menu.getOpenFileName(
            self, "Open File", "/", "Text Files (*.txt)"
        )[0]

    def ViewNotepad(self):
        self.RightDock.setVisible(True)

    def LoadProject(self):
        pass
