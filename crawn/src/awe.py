#! /usr/bin/python

import atexit
import logging
import os
import queue
import random
import socket
import sys
import time
from pathlib import Path

from PySide6 import QtCore, QtGui
from PySide6.QtCore import QThread
from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QPushButton, QMainWindow, QWidget, QVBoxLayout, QFormLayout, \
    QCheckBox, QFrame, QLabel, QHBoxLayout, QToolTip, QTabWidget, \
    QLineEdit, QSplitter, QScrollArea, QListView, QApplication

from config.config import DEFAULT_WORKSPACE_DIR, HOME_DIR, RUNDIR
from gui import targetWindow
from gui.actionsWidget import ActionsWidget
from gui.guiUtilities import GuiProxyClient, HoverButton, TextEditor, SyntaxHighlighter, MessageBox
from gui.repeater import RepeaterWindow
from gui.siteMapWindow import SiteMapWindow
from gui.threadrunners import AtomProxy, SessionHandlerRunner
from utiliities import red, cyan

class AmassFailure(Exception):
    pass


class SocketIPC(QThread, QtCore.QObject):
    """
    server: If this is true, a server is going to be created which is supposed to 
    listen for other processes to communicate to it
    The server can send kill signals to the running process in some form
    of controlling them.
    Even when creating a client the server_port is always used since all the 
    clients only commmunicate with the server
    """
    processFinishedExecution = Signal(QWidget, str)  # the string here is the name of the process wrapper class

    def __init__(self, create_server=False,
                 create_client=False,
                 server_port=57788,
                 ):
        super().__init__()
        self.create_server = create_server
        self.create_client = create_client
        self.server_port = server_port
        if self.create_server:
            self.server = socket.create_server(address=("127.0.0.1", self.server_port),
                                               family=socket.AF_INET
                                               )
        if self.create_client:
            self.client = socket.create_connection(address=("127.0.0.1", self.server_port))

    def sendFinishedMessage(self, process_object_name: str):
        if process_object_name == "atomRunner":
            message = "atomRunner"
        elif process_object_name == "getAllUrlsRunner":
            message = "getAllUrlsRunner"
        self.client.send(message)

    def runServer(self):
        logging.info(f"IPCServer listening for connections on  {self.server_port}")
        self.server.listen(100000000)
        while True:
            skt, addr = self.server.accept()
            processObjectName = skt.recv(1000)
            if processObjectName == b'atomRunner':
                self.processFinishedExecution.emit("atomRunner")
            elif processObjectName == b'getAllUrlsRunner':
                self.processFinishedExecution.emit("getAllUrlsRunner")

    def run(self):
        """ This method only runs when the SocketIPC has been opened in server
        mode"""
        self.runServer()


def GetUrls(workingdir):
    hrefLinksFile = os.path.join(workingdir, "href_links")
    # read the index file and return the urls in it
    urls = open(hrefLinksFile, "r").read()
    return urls


class NetworkMap(QWidget):
    def __init__(self) -> None:
        super().__init__()

    def InitializeNetworkMapWidget(self):
        self.NetworkMapWidget = QWidget()


class ProxyInterceptWindow(QMainWindow):
    def __init__(self, projectDirPath):
        super().__init__()
        self.projectDirPath = projectDirPath

        self.MainWidget = QWidget()
        self.setCentralWidget(self.MainWidget)


class ThreadMon(QWidget):
    def __init__(self, thread, top_parent):
        super().__init__()
        self.topParent = top_parent
        self.formLayout = QFormLayout()
        self.thread = thread
        self.nameLabel = QLabel()
        self.nameLabel.setText(thread.objectName())
        self.formLayout.addRow("Thread Name: ", self.nameLabel)
        self.status = self.getStatus()
        self.label = QLabel()
        self.label.setText(self.status)
        self.formLayout.addRow("Status: ", self.label)
        self.threadStopButton = HoverButton("stop thread", "stop the thread from running")
        self.threadStopButton.clicked.connect(self.exitThread)
        self.formLayout.addRow("Stop Thread: ", self.threadStopButton)
        self.process = 0
        self.setLayout(self.formLayout)
        self.topParent.socketIpc.processFinishedExecution.connect(self.closeWidget)

    def closeWidget(self, window_instance, object_name):
        if object_name == self.thread.objectName():
            for thread in window_instance.threads:
                if thread.objectName() == object_name:
                    window_instance.threads.remove(thread)
            self.close()

    def getStatus(self):
        try:
            self.process = self.thread.process
            self.status = "Running"
        except AttributeError:
            self.status = "Not Running"
            if self.thread.isRunning():
                self.status = "Running"
        return self.status

    def exitThread(self):
        try:
            # handle process closure
            self.pid = self.thread.process.pid
            if sys.platform == "win32":
                os.system(f"taskkill /F /PID {int(self.pid)}")
            elif sys.platform == "linux":
                os.system(f"kill {int(self.pid + 1)}")
            if self.thread.process.process_name == "atomProxy":
                self.topParent.isProxyRunning = False
            elif self.thread.process.process_name == "sessionHandler":
                self.topParent.isSessionHandlerRunning = False
            logging.info(f"Terminating subprocess with pid f{self.pid}")
        except AttributeError:
            # handle thread closure
            logging.info(f"Terminating thread {self.thread}")
            self.thread.terminate()
            self.thread.quit()
            # todo : there is a problem when closing a thread
            if self.thread.isRunning():
                logging.error(f"Failed to terminate thread {self.thread}")


class ThreadMonitor(QMainWindow):
    def __init__(self, top_parent=None):
        """ the data should be a dict of the form {"mainWindowInstance":[running_threads]}"""
        super().__init__()
        self.top_parent = top_parent
        self.windowInstances = self.top_parent.openMainWindows
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.threadMonLayout = QVBoxLayout()
        self.central_widget.setLayout(self.threadMonLayout)
        self.tabManager = QTabWidget()
        self.threadMonLayout.addWidget(self.tabManager)
        self.windowInstancesLayouts = []
        self.top_parent.newProjectCreated.connect(self.addTab)
        self.top_parent.projectClosed.connect(self.closeTab)
        self.top_parent.ThreadStarted.connect(self.addThreadMon)

    def closeTab(self, windowInstance, index):
        self.tabManager.removeTab(index)

    def addThreadMon(self, window_instance, threadName):
        for thread in window_instance.threads:
            if thread.objectName() == threadName:
                for layout in self.windowInstancesLayouts:
                    if layout.objectName() == window_instance.objectName():
                        threadMonWidget = ThreadMon(thread, self.top_parent)
                        layout.addWidget(threadMonWidget)

    def addTab(self, window_instance):
        threads = window_instance.threads
        tabname = window_instance.objectName().split("/")[-1]

        newTabWidget = QWidget()
        centralWidgetLayout = QVBoxLayout()
        newTabWidget.setLayout(centralWidgetLayout)

        newTabScrollArea = QScrollArea()
        centralWidgetLayout.addWidget(newTabScrollArea)

        scrollAreaWidget = QWidget()
        newTabLayout = QVBoxLayout()
        newTabLayout.setObjectName(window_instance.objectName())
        scrollAreaWidget.setLayout(newTabLayout)
        newTabScrollArea.setWidget(scrollAreaWidget)
        newTabScrollArea.setWidgetResizable(True)
        newTabWidget.setObjectName(window_instance.objectName())
        for thread in threads:
            threadMonWidget = ThreadMon(thread, top_parent=self.top_parent)
            newTabLayout.addWidget(threadMonWidget)
        self.tabManager.addTab(newTabWidget, tabname)
        self.windowInstancesLayouts.append(newTabLayout)
    # def stopRunningThread()


class MainWin(QMainWindow, QtCore.QObject):
    newProjectCreated = Signal(QMainWindow)
    projectClosed = Signal(QMainWindow, int)
    ThreadStarted = Signal(QWidget, str)

    def __init__(self) -> None:
        super().__init__()

        self.openProjectCount = 0
        # SocketIPC
        self.socketIpc = SocketIPC(create_server=True)
        self.socketIpc.start()
        self.setObjectName("mainWindow")
        self.threads = []
        self.openMainWindows = [self]

        self.program_state_file = RUNDIR + "programState/programState.txt"
        if not Path(self.program_state_file).exists():
            if not Path(os.path.dirname(self.program_state_file)).is_dir():
                os.makedirs(os.path.dirname(self.program_state_file))
        if Path(self.program_state_file).exists():
            with open(self.program_state_file, "rb") as file:
                program_state_bytes = file.read()
            # self.restoreState(program_state_bytes)
        self.isProxyRunning = False
        self.proxy_port = 0
        self.proxy_hostname = 0
        self.isSessionHandlerRunning = False
        self.startSessionHandler()
        time.sleep(3)
        self.startproxy()
        self.setWindowTitle("AWE(Atom Web Enumeration Framework)")
        self.defaultWorkspaceDir = DEFAULT_WORKSPACE_DIR
        try:
            if not Path(self.defaultWorkspaceDir).exists():
                os.makedirs(self.defaultWorkspaceDir)
        except PermissionError as permisssion_error:
            print(f"{red('permission denied')} {cyan('cannot create workspace directory')}")
            print(f"{red('Consider running the program with sudo priviledges')}")
        # central widget
        self.centralWidget = QWidget()
        self.tabManager = QTabWidget()
        # self.centralWidget.setStyleSheet("background-color: #170048;")
        # central widget layout
        self.MainLayout = QVBoxLayout()
        self.centralWidget.setLayout(self.MainLayout)

        # self.AddTargetTab("target one")
        self.upperTabMenuBar = self.menuBar()

        # projects tab
        self.projectsAction = QtGui.QAction("Projects")
        self.projectsAction.triggered.connect(self.addProjectsTab)
        self.upperTabMenuBar.addAction(self.projectsAction)

        # add target
        self.addTabAction = QtGui.QAction("AddTarget")
        self.addTabAction.triggered.connect(self.AddTargetWindow)
        self.upperTabMenuBar.addAction(self.addTabAction)
        self.upperTabMenuBar.addSeparator()

        # start proxy 
        self.startProxyAction = QtGui.QAction("StartProxy")
        self.startProxyAction.triggered.connect(self.startproxy)
        self.upperTabMenuBar.addAction(self.startProxyAction)

        # start proxy button
        self.repeaterAction = QtGui.QAction("repeater")
        self.repeaterAction.triggered.connect(self.openRepeater)
        self.upperTabMenuBar.addAction(self.repeaterAction)

        self.sitemapAction = QtGui.QAction("sitemap")
        self.sitemapAction.triggered.connect(self.addSiteMapTab)
        self.upperTabMenuBar.addAction(self.sitemapAction)

        self.threadmonitorAction = QtGui.QAction("Threads")
        self.threadmonitorAction.triggered.connect(self.addThreadMonitorTab)
        self.upperTabMenuBar.addAction(self.threadmonitorAction)

        # close tab
        self.closeTabAction = QtGui.QAction("CloseTab")
        self.closeTabAction.triggered.connect(self.closeTab)
        self.upperTabMenuBar.addAction(self.closeTabAction)
        self.upperTabMenuBar.addSeparator()

        self.MainLayout.addWidget(self.tabManager)
        self.setCentralWidget(self.centralWidget)
        
        # add repeater tab and sitemap tab
        self.repeaterWindow = RepeaterWindow(parent=self)
        self.siteMapWindow = SiteMapWindow(parent=self)
        self.siteMapWindow.requestsEditor.sendToRepeaterSignal.connect(self.addRepeaterInstanceTab)
        # self.siteMapWindow.responseEditor.sendToRepeaterSignal.connect(self.addRepeaterTab)

        self.threadMonitor = ThreadMonitor(top_parent=self)

        atexit.register(self.saveProgramState)
        self.socketIpc.processFinishedExecution.connect(self.finishedProcess)
        self.newProjectCreated.emit(self)

    def openRepeater(self):
        self.tabManager.addTab(self.repeaterWindow, "Repeater")

    def finishedProcess(self, windowInstance, tool: str):
        logging.info(f"{tool} finished execution")

    def addThreadMonitorTab(self):
        self.tabManager.addTab(self.threadMonitor, "Thread Monitor")

    def addProjectsTab(self):
        # maintab  widget
        self.mainTabWidget = QWidget()
        self.mainTabLayout = QVBoxLayout()
        self.buttonAddTab = QPushButton()
        self.recentProjectsLabel = QLabel()
        self.recentProjectsLabel.setText("<b>Recent Projects</b>")
        self.mainTabLayout.addWidget(self.recentProjectsLabel, alignment=Qt.AlignCenter)

        self.addProjects()

        self.openBarFrame = QFrame()
        self.openBarLayout = QHBoxLayout()
        self.choosenProjectDir = QLineEdit()
        self.choosenProjectDir.setFixedWidth(400)
        self.openBarLayout.addWidget(self.choosenProjectDir)
        self.openProjectButton = QPushButton()
        self.openProjectButton.setText("Open")
        self.openProjectButton.setFixedWidth(50)
        self.openProjectButton.clicked.connect(self.openChoosenProject)
        self.openBarLayout.addWidget(self.openProjectButton)
        self.openBarFrame.setLayout(self.openBarLayout)
        self.mainTabLayout.addWidget(self.openBarFrame, alignment=Qt.AlignCenter)

        self.buttonAddTab.setText("Add Target")
        self.buttonAddTab.setFixedWidth(120)
        self.buttonAddTab.clicked.connect(self.AddTargetWindow)
        self.mainTabLayout.addWidget(self.buttonAddTab)
        self.mainTabLayout.setAlignment(self.buttonAddTab, Qt.AlignCenter)
        self.mainTabWidget.setLayout(self.mainTabLayout)
        self.tabManager.addTab(self.mainTabWidget, "Projects")
        self.mainTabLayout.addStretch()

    def saveProgramState(self):
        byte_array = self.saveState()
        with open(self.program_state_file, "wb") as file:
            file.write(bytes(byte_array))

    def startSessionHandler(self):
        if self.isSessionHandlerRunning is False:
            logging.info("Starting Session Handler")
            self.sessionHandler = SessionHandlerRunner(self)
            self.sessionHandler.start()
            self.isSessionHandlerRunning = True
        else:
            SessionMessageBox = MessageBox("information", "The session handler is Running", "Information", "Ok")
            ret = SessionMessageBox.exec()

    def startproxy(self):
        if self.isProxyRunning is False:
            self.proxy_port = random.randint(8000, 10000)
            self.proxy_hostname = "127.0.0.1"
            logging.info("Starting proxy")
            self.proxy_ = AtomProxy(self.proxy_port, top_parent=self)
            self.proxy_.start()
            self.isProxyRunning = True
        else:
            proxyMessageBox = MessageBox("information", "The proxy is Running", "Information", "Ok")
            ret = proxyMessageBox.exec()

    def addRepeaterInstanceTab(self, request: str = None):
        self.repeaterWindow.addReqResInstanceTabManager(request)

    def addSiteMapTab(self):
        self.tabManager.addTab(self.siteMapWindow, "SitesMap")

    def openChoosenProject(self):
        dir_name = os.path.join(self.defaultWorkspaceDir, self.choosenProjectDir.text())
        if os.path.isdir(dir_name):
            self.AddTargetTab(dir_name)
        else:
            self.choosenProjectDir.setStyleSheet("QLineEdit{border: 2px solid red;}")

    def addProjects(self):
        available_dirs = []
        with os.scandir(self.defaultWorkspaceDir) as entries:
            for entry in entries:
                if entry.is_dir():
                    if not entry.name == "Proxy":
                        available_dirs.append(entry.name)
        self.dirsModel = QtCore.QStringListModel(available_dirs)
        self.dirListView = QListView()
        self.dirListView.setFont((QtGui.QFont("Cascadia Code", 11)))
        self.dirListView.setEditTriggers(QListView.NoEditTriggers)
        self.dirListView.setModel(self.dirsModel)
        self.dirListView.clicked.connect(self.projectDirClicked)
        self.dirListView.doubleClicked.connect(self.openProject)

        self.dirsProjectsScrollArea = QScrollArea()
        self.dirsProjectsScrollArea.setWidget(self.dirListView)
        self.dirsProjectsScrollArea.setWidgetResizable(True)
        self.dirsProjectsScrollArea.setFixedHeight(450)
        self.dirsProjectsScrollArea.setFixedWidth(450)
        self.mainTabLayout.addWidget(self.dirsProjectsScrollArea, alignment=Qt.AlignCenter)

    def openProject(self, index):
        self.projectDirClicked(index)
        self.openChoosenProject()

    def projectDirClicked(self, index):
        clicked_dir = self.dirsModel.data(index, QtCore.Qt.DisplayRole)
        self.choosenProjectDir.setText(clicked_dir)

    def AddTargetWindow(self):
        # new target window
        self.newTargetWindow = QWidget()
        self.newTargetWindow.setFixedHeight(600)
        self.newTargetWindow.setFixedWidth(600)
        self.newTargetWindow.setWindowTitle("Add Target")
        # new target window layout main
        self.newTargetWindowLayoutMain = QVBoxLayout()
        # new target window layout for form
        self.newTargetWindowLayout = QFormLayout()
        self.newTargetTabName = QLineEdit()
        self.newTargetUrlName = QLineEdit()
        self.projectDir = QLineEdit()
        # form layout setup
        self.newTargetWindowLayout.addRow("Project Name:", self.newTargetTabName)
        self.newTargetWindowLayout.addRow("Target Url:", self.newTargetUrlName)
        self.newTargetWindowLayout.addRow("project path: ", self.projectDir)

        self.newTargetWindowLayoutMain.addLayout(self.newTargetWindowLayout)
        # done button
        self.doneButton = QPushButton()
        self.doneButton.setText("Done")
        self.newTargetWindowLayoutMain.addWidget(self.doneButton)
        self.doneButton.clicked.connect(self.m_AddTargetTab)

        self.newTargetWindow.setLayout(self.newTargetWindowLayoutMain)
        self.newTargetWindow.show()

    def m_AddTargetTab(self):
        tab_name = self.newTargetTabName.text()
        if tab_name == "":
            self.newTargetTabName.setStyleSheet("border: 1px solid red;")
        else:
            projectDirectory = os.path.join(self.defaultWorkspaceDir, tab_name)
            if not Path(projectDirectory).exists():
                os.makedirs(projectDirectory)
            self.openProjectCount += 1
            self.mainWindowInstance = targetWindow.TargetWindow(projectDirectory,
                                                                self.proxy_port,
                                                                self,
                                                                index=self.openProjectCount)
            self.openMainWindows.append(self.mainWindowInstance)
            self.tabManager.addTab(self.mainWindowInstance, tab_name)
            self.tabManager.setCurrentIndex(
                self.tabManager.indexOf(self.mainWindowInstance)
            )
            self.newTargetWindow.close()

    def AddTargetTab(self, directory=""):
        self.openProjectCount += 1
        self.mainWindowInstance = targetWindow.TargetWindow(directory, self.proxy_port, self,
                                                            index=self.openProjectCount)
        self.openMainWindows.append(self.mainWindowInstance)
        tab_name = directory.split("/")[-1]
        self.tabManager.addTab(self.mainWindowInstance, tab_name)
        self.tabManager.setCurrentIndex(
            self.tabManager.indexOf(self.mainWindowInstance)
        )

    def closeTab(self):
        self.current_tab_index = self.tabManager.currentIndex()
        self.tabManager.currentWidget().close()
        self.tabManager.removeTab(self.current_tab_index)

    def closeEvent(self, event: QtGui.QCloseEvent) -> None:
        # note that the thread monitor is responsible for closing all opened threads and processes
        # this can be done by closing all present threadMon objects
        if sys.platform == "win32":
            os.system(f"taskkill /F /PID {self.proxy_.process.pid}")
            os.system(f"taskkill /F /PID {self.sessionHandler.process.pid}")
        elif sys.platform == "linux":
            os.system(f"kill {self.proxy_.process.pid + 1}")
            os.system(f"kill {self.sessionHandler.process.pid + 1}")
        return super().closeEvent(event)


def getLogNumber(rundir_):
    logs_dir = rundir_ + "logs/"
    filenumbers = []
    if len(os.listdir(logs_dir)) != 0:
        for file in os.listdir(logs_dir):
            filenumber = int(file.split(".log")[0].split("log")[1])
            filenumbers.append(filenumber)
        return (max(filenumbers) + 1)
    else:
        return 0


if __name__ == "__main__":
    # log_filename = RUNDIR + "logs/log" + str(getLogNumber(RUNDIR)) + ".log"
    # if not Path(log_filename).exists():
    #     if not Path(os.path.dirname(log_filename)).is_dir():
    #         os.makedirs(os.path.dirname(log_filename))
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s')
    # QLoggingCategory.setFilterRules("qt.webengine.*=false")
    os.environ["QTWEBENGINE_REMOTE_DEBUGGING"] ='9090'
    App = QApplication()
    dark_stylesheet = """
    QWidget {
        background-color: #2E2E2E;
        color: #FFFFFF;
    }

    QPushButton {
        background-color: #4A4A4A;
        color: #FFFFFF;
    }

    QMainWindow {
        border: 2px solid #1E1E1E;
    }

    QTabWidget::pane { 
    background-color: #4A4A4A;
    }

    QTabBar::tab {
        background: #4A4A4A;
        color: white;
        border-radius: 20px
        padding: 5px;
    }

    QHeaderView::section {
        background-color: #4A4A4A;
        color: white;
        padding: 5px;
        border: 1px solid gray;
    }

    QTabBar::tab:selected {
        background: darkgray;
    }

    """
    # fonts Cascadia Code, Courier New

    # font  = QtGui.QFont("Cascadia Code", 11)
    # App.setFont(font)
    # App.setStyleSheet(dark_stylesheet)

    main_window = MainWin()
    main_window.showMaximized()
    sys.exit(App.exec())

# TODO:
"""
running all possible tools (for enumeration , recon, testing) possible and showing the results in the application
tools to be added:
    dnsrecon
    dnsmasq

these are to be tested to see how they work before being added

after running a tool, the ip must be changed and user notified.

1.dns server finders
2.controlled speed during enumeration (random speed but controlled increaments and or decreaments )
3.configuring of proxy networks from different providers during enumeration(if speed is good enough then then tor can also be used)
4.api finders
5.tech stack categorizing(webapp frameworks and libraries)
5.location of servers(geographical location, Hosting platform(aws, google, ...))
6.Network mapper [3d visualization]
7.jwt detectors [auth detectors]

7.visualization engine (2d and 3d)
8.auto-categorization of domain names and urls(pages)
9.ai-integration in all aspects of the application(from the gui to the testing)
10.Analysis engine(analyzing all the traffic concerning a specific project that 
has passed through the proxy including all the javascript, css, html, images, http headers, etc)
and the respective presentation gui interface.

"""
