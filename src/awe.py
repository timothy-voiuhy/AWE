#! /usr/bin/python
import atexit
import json
import logging
import os
import queue
import socket
import sys
import time
from pathlib import Path
import shutil
from datetime import datetime

from PySide6 import QtCore, QtGui
from PySide6.QtCore import QThread
from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QPushButton, QMainWindow, QWidget, QVBoxLayout, QFormLayout, \
    QCheckBox, QFrame, QLabel, QHBoxLayout, QToolTip, QTabWidget, \
    QLineEdit, QSplitter, QScrollArea, QListView, QApplication, QMessageBox

from config.config import DEFAULT_WORKSPACE_DIR, HOME_DIR, RUNDIR
from gui import targetWindow
from gui.actionsWidget import ActionsWidget
from gui.guiUtilities import GuiProxyClient, HoverButton, TextEditor, SyntaxHighlighter, MessageBox
from gui.threadrunners import AtomProxy
from utiliities import red, cyan

# Written by proxy.server on startup, deleted on shutdown
_PROXY_CONTROL_FILE = Path(RUNDIR) / "tmp" / "proxy_control.txt"

_PROXY_DEFAULT_PORT  = 8001
_UI_SETTINGS_FILE    = Path(os.path.expanduser("~")) / ".config" / "awe" / "ui_settings.json"


def _read_proxy_port() -> int:
    try:
        return int(json.loads(_UI_SETTINGS_FILE.read_text()).get("proxy_port", _PROXY_DEFAULT_PORT))
    except Exception:
        return _PROXY_DEFAULT_PORT


def _stop_proxy_graceful() -> None:
    """Send a graceful stop to any running proxy via the control socket.

    Reads the port from proxy_control.txt, sends {"action": "stop"}, then
    removes the file.  Silently ignores all errors (proxy may already be dead).
    """
    port = None
    try:
        port = int(_PROXY_CONTROL_FILE.read_text().strip())
    except Exception:
        pass

    if port is not None:
        try:
            from proxy._control import ControlClient
            ControlClient(port).stop()
        except Exception:
            pass

    try:
        _PROXY_CONTROL_FILE.unlink(missing_ok=True)
    except Exception:
        pass


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
        self.client.send(process_object_name.encode())

    def stop(self) -> None:
        """Close the server socket so accept() unblocks and the thread exits."""
        try:
            self.server.close()
        except Exception:
            pass

    def runServer(self):
        logging.info(f"IPCServer listening for connections on  {self.server_port}")
        self.server.listen(100000000)
        while True:
            try:
                skt, addr = self.server.accept()
            except OSError:
                break  # socket was closed via stop()
            processObjectName = skt.recv(1000).decode(errors="replace")
            self.processFinishedExecution.emit(processObjectName)

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
            proc = self.thread.process
            self.pid = proc.pid
            try:
                proc.terminate()
            except Exception:
                pass
            if proc.process_name == "atomProxy":
                self.topParent.isProxyRunning = False
            logging.info(f"Terminating subprocess with pid {self.pid}")
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
        self.isProjectsTabOpen = False
        self.proxy_port = 0
        self.proxy_hostname = 0
        self.isSessionHandlerRunning = False
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

        self.upperTabMenuBar = self.menuBar()

        # ── Workspace ─────────────────────────────────────────────────────────
        workspaceMenu = self.upperTabMenuBar.addMenu("Workspace")

        self.projectsAction = QtGui.QAction("Projects Dashboard", self)
        self.projectsAction.setShortcut("Ctrl+Shift+P")
        self.projectsAction.triggered.connect(self.addProjectsTab)
        workspaceMenu.addAction(self.projectsAction)

        self.addTabAction = QtGui.QAction("New Target…", self)
        self.addTabAction.setShortcut("Ctrl+N")
        self.addTabAction.triggered.connect(self.AddTargetWindow)
        workspaceMenu.addAction(self.addTabAction)

        # ── Views ─────────────────────────────────────────────────────────────
        viewsMenu = self.upperTabMenuBar.addMenu("Views")

        self.threadmonitorAction = QtGui.QAction("Thread Monitor", self)
        self.threadmonitorAction.setShortcut("Ctrl+T")
        self.threadmonitorAction.triggered.connect(self.addThreadMonitorTab)
        viewsMenu.addAction(self.threadmonitorAction)

        # ── Proxy ─────────────────────────────────────────────────────────────
        proxyMenu = self.upperTabMenuBar.addMenu("Proxy")

        self.startProxyAction = QtGui.QAction("Start / Stop Proxy", self)
        self.startProxyAction.setShortcut("Ctrl+P")
        self.startProxyAction.triggered.connect(self.startproxy)
        proxyMenu.addAction(self.startProxyAction)

        self.tabManager.setTabsClosable(True)
        self.tabManager.tabCloseRequested.connect(self.closeTab)
        self.MainLayout.addWidget(self.tabManager)
        self.setCentralWidget(self.centralWidget)
        
        self.threadMonitor = ThreadMonitor(top_parent=self)

        atexit.register(self.saveProgramState)
        self.socketIpc.processFinishedExecution.connect(self.finishedProcess)
        self.newProjectCreated.emit(self)
        self.addProjectsTab()

    def finishedProcess(self, windowInstance, tool: str):
        logging.info(f"{tool} finished execution")

    def addThreadMonitorTab(self):
        if self.tabManager.indexOf(self.threadMonitor) == -1:
            self.tabManager.addTab(self.threadMonitor, "Thread Monitor")
        self.tabManager.setCurrentWidget(self.threadMonitor)

    def addProjectsTab(self):
        # maintab widget
        if not self.isProjectsTabOpen:
            # Create main container widget
            self.mainTabWidget = QWidget()
            self.mainTabWidget.setObjectName("projectsTab")
            self.mainTabLayout = QVBoxLayout()
            self.mainTabLayout.setSpacing(20)
            self.mainTabLayout.setContentsMargins(30, 30, 30, 30)
            
            # Header section
            headerWidget = QWidget()
            headerLayout = QHBoxLayout()
            headerLayout.setContentsMargins(0, 0, 0, 20)
            
            # Add title and icons
            self.projectsHeaderLabel = QLabel()
            self.projectsHeaderLabel.setText("<h1>Projects Dashboard</h1>")
            self.projectsHeaderLabel.setObjectName("projectsHeaderLabel")
            
            # Add the header elements
            headerLayout.addWidget(self.projectsHeaderLabel)
            headerLayout.addStretch()
            
            # Create a search box
            self.projectSearchBox = QLineEdit()
            self.projectSearchBox.setPlaceholderText("Search projects...")
            self.projectSearchBox.setFixedWidth(250)
            self.projectSearchBox.setObjectName("projectSearchBox")
            self.projectSearchBox.textChanged.connect(self.filterProjects)
            headerLayout.addWidget(self.projectSearchBox)
            
            # Add new project button
            self.newProjectButton = QPushButton("New Project")
            self.newProjectButton.setObjectName("newProjectButton")
            self.newProjectButton.clicked.connect(self.AddTargetWindow)
            headerLayout.addWidget(self.newProjectButton)
            
            headerWidget.setLayout(headerLayout)
            self.mainTabLayout.addWidget(headerWidget)
            
            # Create a container for the projects area
            projectsContainer = QWidget()
            projectsContainerLayout = QHBoxLayout()
            projectsContainerLayout.setContentsMargins(0, 0, 0, 0)
            
            # Left side - projects list
            projectsListContainer = QWidget()
            projectsListContainer.setObjectName("projectsListContainer")
            projectsListLayout = QVBoxLayout()
            
            # Add Recent Projects label with icon
            recentHeaderWidget = QWidget()
            recentHeaderLayout = QHBoxLayout()
            recentHeaderLayout.setContentsMargins(0, 0, 0, 10)
            
            self.recentProjectsLabel = QLabel("<h2>Recent Projects</h2>")
            self.recentProjectsLabel.setObjectName("recentProjectsLabel")
            recentHeaderLayout.addWidget(self.recentProjectsLabel)
            recentHeaderLayout.addStretch()
            
            recentHeaderWidget.setLayout(recentHeaderLayout)
            projectsListLayout.addWidget(recentHeaderWidget)
            
            # Add the projects list
            self.addProjects(projectsListLayout)
            
            projectsListContainer.setLayout(projectsListLayout)
            projectsContainerLayout.addWidget(projectsListContainer, 2)
            
            # Right side - project details/stats
            projectDetailsContainer = QWidget()
            projectDetailsContainer.setObjectName("projectDetailsContainer")
            projectDetailsLayout = QVBoxLayout()
            
            # Project details header
            detailsHeaderLabel = QLabel("<h2>Project Details</h2>")
            detailsHeaderLabel.setObjectName("detailsHeaderLabel")
            projectDetailsLayout.addWidget(detailsHeaderLabel)
            
            # Project info form
            self.projectInfoWidget = QWidget()
            self.projectInfoLayout = QFormLayout()
            self.projectInfoLayout.setSpacing(15)
            
            self.selectedProjectLabel = QLabel("Select a project to view details")
            self.selectedProjectLabel.setObjectName("selectedProjectLabel")
            self.projectInfoLayout.addRow(QLabel("<b>Name:</b>"), self.selectedProjectLabel)
            
            self.projectPathLabel = QLabel("")
            self.projectInfoLayout.addRow(QLabel("<b>Path:</b>"), self.projectPathLabel)
            
            self.projectCreatedLabel = QLabel("")
            self.projectInfoLayout.addRow(QLabel("<b>Created:</b>"), self.projectCreatedLabel)
            
            self.projectInfoWidget.setLayout(self.projectInfoLayout)
            projectDetailsLayout.addWidget(self.projectInfoWidget)
            
            # Project actions
            self.projectActionsWidget = QWidget()
            self.projectActionsLayout = QVBoxLayout()
            self.projectActionsLayout.setSpacing(10)
            
            self.openProjectButton = QPushButton("Open Project")
            self.openProjectButton.setObjectName("actionButton")
            self.openProjectButton.clicked.connect(self.openSelectedProject)
            self.openProjectButton.setEnabled(False)
            self.projectActionsLayout.addWidget(self.openProjectButton)
            
            self.deleteProjectButton = QPushButton("Delete Project")
            self.deleteProjectButton.setObjectName("deleteButton")
            self.deleteProjectButton.clicked.connect(self.deleteSelectedProject)
            self.deleteProjectButton.setEnabled(False)
            self.projectActionsLayout.addWidget(self.deleteProjectButton)
            
            self.projectActionsWidget.setLayout(self.projectActionsLayout)
            projectDetailsLayout.addWidget(self.projectActionsWidget)
            projectDetailsLayout.addStretch()
            
            projectDetailsContainer.setLayout(projectDetailsLayout)
            projectsContainerLayout.addWidget(projectDetailsContainer, 1)
            
            projectsContainer.setLayout(projectsContainerLayout)
            self.mainTabLayout.addWidget(projectsContainer)
            
            self.mainTabWidget.setLayout(self.mainTabLayout)
            self.tabManager.addTab(self.mainTabWidget, "Projects")
            self.isProjectsTabOpen = True
        self.tabManager.setCurrentWidget(self.mainTabWidget)

    def addProjects(self, parentLayout):
        available_dirs = []
        with os.scandir(self.defaultWorkspaceDir) as entries:
            for entry in entries:
                if entry.is_dir():
                    if not entry.name == "Proxy":
                        info = {
                            'name': entry.name,
                            'path': entry.path,
                            'created': datetime.fromtimestamp(entry.stat().st_ctime).strftime('%Y-%m-%d %H:%M:%S')
                        }
                        available_dirs.append(info)
        
        # Sort projects by creation date (newest first)
        available_dirs.sort(key=lambda x: x['created'], reverse=True)
        
        # Store the full project info
        self.projects_info = available_dirs
        
        # Create a model with just the names for the list view
        project_names = [project['name'] for project in available_dirs]
        self.dirsModel = QtCore.QStringListModel(project_names)
        
        self.dirListView = QListView()
        self.dirListView.setObjectName("projectsListView")
        self.dirListView.setFont(QtGui.QFont("Segoe UI", 11))
        self.dirListView.setEditTriggers(QListView.NoEditTriggers)
        self.dirListView.setModel(self.dirsModel)
        self.dirListView.clicked.connect(self.projectSelected)
        self.dirListView.doubleClicked.connect(self.openProject)
        
        self.dirsProjectsScrollArea = QScrollArea()
        self.dirsProjectsScrollArea.setObjectName("projectsScrollArea")
        self.dirsProjectsScrollArea.setWidget(self.dirListView)
        self.dirsProjectsScrollArea.setWidgetResizable(True)
        
        parentLayout.addWidget(self.dirsProjectsScrollArea)
    
    def filterProjects(self, text):
        """Filter projects based on search text"""
        if not text:
            # If search is empty, show all projects
            project_names = [project['name'] for project in self.projects_info]
        else:
            # Filter projects that contain the search text
            project_names = [project['name'] for project in self.projects_info 
                           if text.lower() in project['name'].lower()]
        
        self.dirsModel.setStringList(project_names)
    
    def projectSelected(self, index):
        """Update project details when a project is selected"""
        selected_name = self.dirsModel.data(index, QtCore.Qt.DisplayRole)
        
        # Find the selected project in our full info list
        selected_project = next((p for p in self.projects_info if p['name'] == selected_name), None)
        
        if selected_project:
            self.selectedProjectLabel.setText(selected_project['name'])
            self.projectPathLabel.setText(selected_project['path'])
            self.projectCreatedLabel.setText(selected_project['created'])
            self.choosenProjectDir = selected_project['name']
            
            # Enable action buttons
            self.openProjectButton.setEnabled(True)
            self.deleteProjectButton.setEnabled(True)
    
    def openSelectedProject(self):
        """Open the currently selected project"""
        if hasattr(self, 'choosenProjectDir') and self.choosenProjectDir:
            dir_name = os.path.join(self.defaultWorkspaceDir, self.choosenProjectDir)
            if os.path.isdir(dir_name):
                self.AddTargetTab(dir_name)
    
    def deleteSelectedProject(self):
        """Delete the currently selected project after confirmation"""
        if not hasattr(self, 'choosenProjectDir') or not self.choosenProjectDir:
            return
            
        dir_name = os.path.join(self.defaultWorkspaceDir, self.choosenProjectDir)
        if not os.path.isdir(dir_name):
            return
            
        # Show confirmation dialog
        confirm = MessageBox(
            "Confirm Deletion", 
            f"Are you sure you want to delete project '{self.choosenProjectDir}'?\nThis cannot be undone.", 
            "Warning", 
            buttons=["Ok", "Cancel"]
        )
        
        if confirm.exec() == QMessageBox.Ok:
            try:
                # Recursive delete
                shutil.rmtree(dir_name)

                # Drop the project's MongoDB database
                try:
                    from database.mongo import _safe_db_name, _client
                    _client().drop_database(_safe_db_name(dir_name))
                except Exception as db_err:
                    import logging
                    logging.getLogger(__name__).warning(
                        "Could not drop MongoDB database for %s: %s", dir_name, db_err
                    )

                # Refresh the projects list
                if self.isProjectsTabOpen:
                    current_index = self.tabManager.currentIndex()
                    self.closeTab()
                    self.addProjectsTab()
                    self.tabManager.setCurrentIndex(current_index)
            except Exception as e:
                error = MessageBox(
                    "Error", 
                    f"Failed to delete project: {str(e)}", 
                    "Critical", 
                    "Ok"
                )
                error.exec()

    def openChoosenProject(self):
        if hasattr(self, 'choosenProjectDir') and self.choosenProjectDir:
            dir_name = os.path.join(self.defaultWorkspaceDir, self.choosenProjectDir)
            if os.path.isdir(dir_name):
                self.AddTargetTab(dir_name)
            else:
                error = MessageBox(
                    "Error", 
                    "Selected project directory does not exist", 
                    "Warning", 
                    "Ok"
                )
                error.exec()

    def projectDirClicked(self, index):
        clicked_dir = self.dirsModel.data(index, QtCore.Qt.DisplayRole)
        self.choosenProjectDir = clicked_dir

    def AddTargetWindow(self):
        from PySide6.QtWidgets import QLabel as _QLabel
        self.newTargetWindow = QWidget()
        self.newTargetWindow.setFixedWidth(480)
        self.newTargetWindow.setFixedHeight(220)
        self.newTargetWindow.setWindowTitle("New Project")

        self.newTargetWindowLayoutMain = QVBoxLayout()
        self.newTargetWindowLayoutMain.setSpacing(10)
        self.newTargetWindowLayoutMain.setContentsMargins(20, 20, 20, 20)

        hint = _QLabel("Both fields are required. The target domain is used for all scans.")
        hint.setStyleSheet("color:#6C7086; font-size:11px;")
        hint.setWordWrap(True)
        self.newTargetWindowLayoutMain.addWidget(hint)

        self.newTargetWindowLayout = QFormLayout()
        self.newTargetWindowLayout.setSpacing(8)

        self.newTargetTabName = QLineEdit()
        self.newTargetTabName.setPlaceholderText("my-project")
        self.newTargetWindowLayout.addRow("Project Name:", self.newTargetTabName)

        self.newTargetUrlName = QLineEdit()
        self.newTargetUrlName.setPlaceholderText("example.com  or  https://example.com")
        self.newTargetWindowLayout.addRow("Target Domain:", self.newTargetUrlName)

        self.newTargetWindowLayoutMain.addLayout(self.newTargetWindowLayout)

        self.doneButton = QPushButton("Create Project")
        self.doneButton.setObjectName("primaryButton")
        self.doneButton.clicked.connect(self.m_AddTargetTab)
        self.newTargetWindowLayoutMain.addWidget(self.doneButton)

        self.newTargetWindow.setLayout(self.newTargetWindowLayoutMain)
        self.newTargetWindow.show()

    def m_AddTargetTab(self):
        import json
        from datetime import datetime
        tab_name   = self.newTargetTabName.text().strip()
        target_url = self.newTargetUrlName.text().strip()
        if not tab_name:
            self.newTargetTabName.setStyleSheet("QLineEdit { border: 1px solid #F38BA8; }")
            return
        if not target_url:
            self.newTargetUrlName.setStyleSheet("QLineEdit { border: 1px solid #F38BA8; }")
            return
        # Strip protocol so we store just the bare domain
        target_domain = target_url.replace("https://", "").replace("http://", "").rstrip("/").split("/")[0]
        projectDirectory = os.path.join(self.defaultWorkspaceDir, tab_name)
        if not Path(projectDirectory).exists():
            os.makedirs(projectDirectory)
        # Persist project metadata so it survives restarts
        meta = {
            "name":       tab_name,
            "target_url": target_url,
            "target":     target_domain,
            "created_at": datetime.now().isoformat(),
        }
        with open(os.path.join(projectDirectory, "project.json"), "w") as fh:
            json.dump(meta, fh, indent=2)
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

    def closeTab(self, index: int = -1):
        if index == -1:
            index = self.tabManager.currentIndex()
        if index == -1:
            return
        widget = self.tabManager.widget(index)
        if widget and widget.objectName() == "projectsTab":
            self.isProjectsTabOpen = False
        self.tabManager.removeTab(index)
        if widget:
            widget.close()

    def closeEvent(self, event: QtGui.QCloseEvent) -> None:
        # ── 1. Stop the SocketIPC server thread ───────────────────────────────
        try:
            self.socketIpc.stop()
            self.socketIpc.quit()
            self.socketIpc.wait(2000)
        except Exception:
            pass

        # ── 2. Gracefully stop the proxy via control socket ───────────────────
        # Do this before the thread drain so the proxy process exits on its own,
        # making the subsequent proc.terminate() a no-op in the happy path.
        _stop_proxy_graceful()

        # ── 3. Terminate every tracked subprocess, then wait for its QThread ──
        # Build a deduplicated list; proxy_ is already in self.threads but we
        # guard with a set to be safe.
        seen: set[int] = set()
        threads_to_drain: list[QThread] = []
        for t in list(self.threads) + ([self.proxy_] if hasattr(self, "proxy_") else []):
            if id(t) not in seen:
                seen.add(id(t))
                threads_to_drain.append(t)

        for thread in threads_to_drain:
            if not thread.isRunning():
                continue
            proc = getattr(thread, "process", None)
            if proc is not None:
                try:
                    proc.terminate()
                except Exception:
                    pass
            thread.quit()
            if not thread.wait(3000):
                thread.terminate()
                thread.wait(1000)

        return super().closeEvent(event)

    def saveProgramState(self):
        byte_array = self.saveState()
        with open(self.program_state_file, "wb") as file:
            file.write(bytes(byte_array))


    def startproxy(self):
        # Kill any stale proxy from a previous crash (reads proxy_control.txt)
        _stop_proxy_graceful()

        # If a proxy QThread is still alive from this session, drain it first
        if hasattr(self, "proxy_") and self.proxy_.isRunning():
            proc = getattr(self.proxy_, "process", None)
            if proc is not None:
                try:
                    proc.terminate()
                except Exception:
                    pass
            self.proxy_.quit()
            self.proxy_.wait(2000)
            # Remove from threads list so it doesn't get double-drained on exit
            if self.proxy_ in self.threads:
                self.threads.remove(self.proxy_)

        self.proxy_port = _read_proxy_port()
        self.proxy_hostname = "127.0.0.1"
        logging.info("Starting proxy on port %d", self.proxy_port)
        self.proxy_ = AtomProxy(self.proxy_port, top_parent=self)
        self.proxy_.start()
        self.isProxyRunning = True

    def openProject(self, index):
        self.projectSelected(index)
        self.openSelectedProject()


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
    # Suppress noisy third-party loggers
    for _noisy in ("pymongo", "pymongo.serverMonitor", "pymongo.connection",
                   "pymongo.topology", "urllib3", "charset_normalizer"):
        logging.getLogger(_noisy).setLevel(logging.WARNING)
                        
    # Disable hardware acceleration for WebEngine
    os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = "--disable-gpu"
    os.environ["QTWEBENGINE_DISABLE_GPU"] = "1"
    os.environ["QTWEBENGINE_DISABLE_SANDBOX"] = "1"
    os.environ["QTWEBENGINE_REMOTE_DEBUGGING"] = "9090"
    
    App = QApplication()

    # Start MongoDB in the background so it's ready when the pipeline window opens
    import threading as _threading
    def _start_mongo():
        try:
            sys.path.insert(0, os.path.dirname(__file__))
            from database.mongod_manager import ensure_running
            ok, msg = ensure_running()
            logging.info("MongoDB startup: %s — %s", ok, msg)
        except Exception as exc:
            logging.warning("MongoDB startup skipped: %s", exc)
    _threading.Thread(target=_start_mongo, daemon=True).start()

    # Load custom stylesheet
    stylesheet_path = os.path.join(RUNDIR, "src/styles/awe_dark.qss")
    if os.path.exists(stylesheet_path):
        with open(stylesheet_path, "r") as stylesheet_file:
            App.setStyleSheet(stylesheet_file.read())
    else:
        logging.warning(f"Stylesheet file not found: {stylesheet_path}")
        
    # Set application font
    font = QtGui.QFont("Segoe UI", 10)
    App.setFont(font)
    
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
