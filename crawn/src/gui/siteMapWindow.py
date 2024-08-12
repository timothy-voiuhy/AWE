import json
import logging
from pathlib import Path
import re
from PySide6.QtCore import QFileSystemWatcher, Qt, QModelIndex
from PySide6.QtGui import QStandardItem, QStandardItemModel, QIcon

from PySide6.QtWidgets import (QWidget, QMainWindow, QVBoxLayout, QHBoxLayout, QSplitter, QFrame,
                               QPushButton, QLineEdit, QLabel, QCheckBox, QTreeView, QTabWidget)

import os
from jsbeautifier import beautify
from config.config import PROXY_DUMP_DIR, RUNDIR
from gui.actionsWidget import ActionsWidget
from gui.guiUtilities import GuiProxyClient, ReqResTextEditor, SyntaxHighlighter

def cleanNode(parentPath, pr):
    """ remove the node_container and the node_containers of the subnodes from the dirNodeContainers"""
    subnode_dirnames = []
    for dir_ in os.scandir(parentPath):
        dirPath = os.path.join(parentPath, dir_.name)
        subnode_dirnames.append(dirPath)
    for subnode_dirname in subnode_dirnames:
        for node_container in pr.dirNodeContainers:
            if node_container.name == subnode_dirname:
                pr.dirNodeContainers.remove(node_container)

class parentItemContainer():
    def __init__(self, name: str = None, object_=None, obj_dicts: list = None, children: list = None):
        self.name = name
        self.object_ = object_
        self.obj_dicts = obj_dicts
        if self.obj_dicts is None:
            self.obj_dicts = []
        self.children = children
        if self.children is None:
            self.children = []
        self.containerDict = {}

    def addChild(self, child: dict):
        self.children.append(child)

    def addContent(self, content: dict):
        self.obj_dicts.append(content)

    def __dict__(self):
        self.containerDict["name"] = self.name
        self.containerDict["object"] = self.object_
        self.containerDict["contents"] = self.contents
        self.containerDict["children"] = self.children


def populateNode(parentPath,
                 Item: QStandardItem,
                 nodeContainer: parentItemContainer = None,
                 update=False,
                 pr=None,
                 contents=None):
    if update:
        try:
            # remove all the subnodes from the node and also from the pr.dirNodeContainers
            cleanNode(parentPath, pr)
            Item.removeRows(0, Item.rowCount())
        except RuntimeError:
            pass
    for index, element in enumerate(os.scandir(parentPath)):
        if element.is_file():  # if it is a file , append it to the parent item
            filenode = FileNode(pr, element.name, Item, parentPath, nodeContainer, index)
            filenode.makeNode()
        elif element.is_dir():
            node = DirNode(pr, element, parentPath, Item, nodeContainer, index)
            node.makeNode()


class FileNode():
    def __init__(self,pr,text,parentItem,parent_path,parent_node_container,index_in_node):
        self.pr = pr
        self.parent_node_container = parent_node_container
        self.parent_path = parent_path
        self.parentItem = parentItem
        self.text = text
        self.item = QStandardItem()
        self.item.setText(self.text)
        self.name = os.path.join(self.parent_path, text)
        self.obj_idx_dict = {}
        self.index_in_node = index_in_node

    def makeNode(self):
        try:
            self.parentItem.appendRow(self.item)
            self.obj_idx_dict[self.name] = self.index_in_node
            self.parent_node_container.addContent(self.obj_idx_dict)
            self.pr.fileNodes.append(self)
        except RuntimeError:
            pass


class DirNode():
    def __init__(self, parent, dir_: os.DirEntry,
                 parentPath=None,
                 parentNodeItem: QStandardItem = None,
                 parent_node_container: parentItemContainer = None,
                 index_in_node=None):
        super().__init__()
        self.parent_node_container = parent_node_container
        self.parent = parent
        self.dir_ = dir_
        self.parentNodeItem = parentNodeItem
        self.parentpath = parentPath
        self.node_container = parentItemContainer()
        self.Item = QStandardItem(self.dir_.name)
        if self.parentpath is None:
            self.defaultParentPath = os.path.join(self.parent.proxyDumpDir, self.dir_)
        else:
            self.defaultParentPath = os.path.join(self.parentpath, self.dir_)
        self.node_container.name = self.defaultParentPath
        self.node_container.object_ = self.Item
        self.obj_idx_dict = {}
        self.index_in_node = index_in_node

    def addNode(self):
        try:
            if self.parentNodeItem is None:
                self.parent.siteMapTreeModel.appendRow(self.Item)
            else:
                self.parentNodeItem.appendRow(self.Item)
            self.parent.dirNodeContainers.append(self.node_container)
            self.obj_idx_dict[self.node_container.name] = self.index_in_node
            self.parent_node_container.addContent(self.obj_idx_dict)
            # self.parent.dirNodes.append(self) #README if you allow this you must make sure a node is deleted if a dir is deleted
        except RuntimeError:
            pass

    def expandNode(self):
        populateNode(self.defaultParentPath, self.Item, self.node_container, pr=self.parent)

    def makeNode(self):
        self.addNode()
        self.expandNode()

def get_live_path(path:str):
    if path.endswith("/"):
        path = path.strip("/")
    path_obj = Path(path)
    if not path_obj.exists():
        while True:
            dirs_list = path.split("/")
            if len(dirs_list) == 0:
                break
            last_dir = dirs_list[-1]
            # remove directory by directory until find a present directory
            path = path.removesuffix(last_dir)
            if Path(path).exists():
                break
    return path

class SiteMapWindow(QMainWindow):
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.siteMapMainWidget = QWidget()
        self.setCentralWidget(self.siteMapMainWidget)
        self.siteMapMainWidgetLayout = QVBoxLayout()
        self.siteMapMainWidget.setLayout(self.siteMapMainWidgetLayout)
        self.proxyDumpDir = PROXY_DUMP_DIR
        if not os.path.isdir(self.proxyDumpDir):
            os.makedirs(self.proxyDumpDir)
        self.siteDirs = []
        self.watchPaths = []
        self.siteMapScope = ["."]
        self.dirNodeContainers = []
        self.dirNodes = []
        self.fileNodes = []

        self.requestsEditor = ReqResTextEditor()
        self.responseEditor = ReqResTextEditor()

        # splitter
        self.siteMapSplitter = QSplitter()
        self.siteMapMainWidgetLayout.addWidget(self.siteMapSplitter)

        # siteMap
        self.siteMapListViewFrame = QFrame()
        self.siteMapListViewFrame.setMaximumWidth(350)
        self.siteMapSplitter.addWidget(self.siteMapListViewFrame)
        self.siteMapTreeViewLayout = QVBoxLayout()
        self.siteMapListViewFrame.setLayout(self.siteMapTreeViewLayout)

        self.siteMapUpperLayout = QHBoxLayout()
        self.siteMapTreeViewLayout.addLayout(self.siteMapUpperLayout)

        self.siteMapListViewLabel = QLabel()
        self.siteMapListViewLabel.setText("<b>Site Map</b>")
        self.siteMapUpperLayout.addWidget(self.siteMapListViewLabel, alignment=Qt.AlignLeft)

        self.siteMapListViewSettingsButton = QPushButton()
        self.siteMapListViewSettingsButtonIcon = QIcon(
            RUNDIR + "resources/icons/settings-icon-gear-3d-render-png.png")
        self.siteMapListViewSettingsButton.setIcon(self.siteMapListViewSettingsButtonIcon)
        self.siteMapListViewSettingsButton.clicked.connect(self.openSiteMapSettings)
        self.siteMapUpperLayout.addWidget(self.siteMapListViewSettingsButton, alignment=Qt.AlignRight)

        self.siteMapLoggingLabel = QLabel()
        self.siteMapLoggingLabel.setText("Logging:")
        self.siteMapUpperLayout.addWidget(self.siteMapLoggingLabel)

        self.siteMapLoggingCheckBox = QCheckBox()
        self.siteMapLoggingCheckBox.stateChanged.connect(self.HandleLoggingChange)
        self.siteMapUpperLayout.addWidget(self.siteMapLoggingCheckBox)

        self.siteMapTreeModel = QStandardItemModel()
        self.siteMapTreeView = QTreeView()
        self.siteMapTreeView.setAlternatingRowColors(True)
        self.siteMapTreeView.setAnimated(True)
        self.siteMapTreeView.doubleClicked.connect(self.readReqResData)
        self.siteMapTreeView.setUniformRowHeights(True)
        self.siteMapTreeView.setEditTriggers(QTreeView.NoEditTriggers)
        self.siteMapTreeViewLayout.addWidget(self.siteMapTreeView)
        # self.siteMapTreeModel.dataChanged.connect(self.createNodeTree())
        self.proxyFileSystemWatcher = QFileSystemWatcher()
        self.proxyFileSystemWatcher.directoryChanged.connect(self.updateNode)
        self.createNodeTree()
        self.watchPaths = self.getWatchPaths()
        self.proxyFileSystemWatcher.addPaths(self.watchPaths)

        # the request and response area tabs
        self.siteMapReqResTabManager = QTabWidget()
        self.siteMapSplitter.addWidget(self.siteMapReqResTabManager)

        # self.requestsEditor.setFixedWidth(650)
        self.highlighter = SyntaxHighlighter(self.requestsEditor.document())
        self.siteMapReqResTabManager.addTab(self.requestsEditor, "request")
        # self.responseEditor.setFixedWidth(650)
        self.siteMapReqResTabManager.addTab(self.responseEditor, "response")
        self.highlighter = SyntaxHighlighter(self.responseEditor.document())

        self.siteMapScopeCommand = False
        self.logggingOnCommand = False
        self.loggingOffCommand = False

        self.actionsWidget = ActionsWidget(self.parent, self.responseEditor)
        self.actionsWidget.setMaximumWidth(400)
        self.siteMapSplitter.addWidget(self.actionsWidget)

    def getWatchPaths(self):
        siteMapDirs = []
        for root, dirs, files in os.walk(self.proxyDumpDir):
            for direntry in dirs:
                path = os.path.join(root, direntry)
                siteMapDirs.append(path)
        siteMapDirs.append(self.proxyDumpDir)
        return siteMapDirs

    def HandleLoggingChange(self):
        if self.siteMapLoggingCheckBox.isChecked():
            self.loggingOffCommand = False
            self.logggingOnCommand = True
            logging.info("Proxy logging has been enabled")
            self.sendCommandToProxy()
        else:
            self.logggingOnCommand = False
            self.loggingOffCommand = True
            logging.info("Proxy logging has been disabled")
            self.sendCommandToProxy()

    def openSiteMapSettings(self):
        self.siteMapSettingsWidget = QWidget()
        self.siteMapSettingsWidgetLayout = QVBoxLayout()
        self.siteMapSettingsWidget.setLayout(self.siteMapSettingsWidgetLayout)

        self.siteMapSettingsScopeLabel = QLabel()
        self.siteMapSettingsScopeLabel.setText("<b><u>Scope</u></b>")
        self.siteMapSettingsWidgetLayout.addWidget(self.siteMapSettingsScopeLabel)

        self.siteMapSettingsScopeNoteLabel = QLabel()
        self.siteMapSettingsScopeNoteLabel.setText(
            "Add comma separated  values of the domains\n\te.g youtube, google\nThe comma separated values can also be regex patterns")
        self.siteMapSettingsWidgetLayout.addWidget(self.siteMapSettingsScopeNoteLabel)

        self.siteMapSettingsScopeLineEdit = QLineEdit()
        self.siteMapSettingsScopeLineEdit.setPlaceholderText("url, domain, regex")
        self.siteMapSettingsWidgetLayout.addWidget(self.siteMapSettingsScopeLineEdit)

        self.siteMapSettingsScopeDoneButton = QPushButton()
        self.siteMapSettingsScopeDoneButton.setText("Done")
        self.siteMapSettingsScopeDoneButton.clicked.connect(self.setSiteMapScope)
        self.siteMapSettingsScopeDoneButton.setFixedWidth(48)
        self.siteMapSettingsWidgetLayout.addWidget(self.siteMapSettingsScopeDoneButton)

        self.siteMapSettingsWidgetLayout.addStretch()

        self.siteMapSettingsWidget.setFixedWidth(550)
        self.siteMapSettingsWidget.setFixedHeight(600)
        self.siteMapSettingsWidget.setWindowTitle("siteMap scope settings")
        self.siteMapSettingsWidget.show()

    def sendCommandToProxy(self):
        try:
            if self.siteMapScopeCommand:
                command = {"scope": self.siteMapScope}
                request = json.dumps(command)
            elif self.logggingOnCommand:
                command = {"log": 0}
                request = json.dumps(command)
            elif self.loggingOffCommand:
                command = {"log": 1}
                request = json.dumps(command)
            self.guiProxyClient = GuiProxyClient(request, is_command=True, proxy_port=self.parent.proxy_port)
            self.guiProxyClient.start()
        except ConnectionAbortedError or ConnectionResetError:
            logging.warning("Connection error in socket")
            pass

    def readReqResData(self, index: QModelIndex):
        parent_idx = index.parent()
        clicked_file_dir = self.siteMapTreeModel.itemFromIndex(parent_idx).text()
        clicked_file = self.siteMapTreeModel.itemFromIndex(index).text()

        file_obtained = False

        for root, dirs, files in os.walk(self.proxyDumpDir):
            for dirr in dirs:
                if dirr == clicked_file_dir:
                    if root != self.proxyDumpDir:
                        # print(red(f"clicked {root}"))
                        for entry in os.scandir(root):
                            if entry.name == clicked_file:
                                clicked_file_path = os.path.join(root, entry.name)
                                file_obtained = True
                                break
                        if not file_obtained:
                            # print(red(f"walking through dir {root}"))
                            for root_, dirs_, files_ in os.walk(root):
                                for dir__ in dirs_:
                                    dir_path = os.path.join(root_, dir__)  # note here for far and short searches
                                    for entry in os.scandir(dir_path):
                                        # print(red(f"scanning dir: {root_}"))
                                        if entry.name == clicked_file:
                                            clicked_file_path = os.path.join(dir_path, entry.name)
                                            # print(red(f"clicked file path: {clicked_file_path}"))
                                            file_obtained = True
                                            break
                                    if file_obtained:
                                        break

                if file_obtained:
                    break
            if file_obtained:
                break
        if file_obtained and os.path.isfile(clicked_file_path):
            with open(clicked_file_path, "r") as f:
                file_data = f.read().split("\nRESPONSE\n")
                request_packet = file_data[0]
                response_packet = file_data[1]
            self.requestsEditor.clear()
            self.responseEditor.clear()
            self.requestsEditor.setText(request_packet)
            if clicked_file_path.endswith(".js"):
                resp_pkt_cmp = response_packet.split("\n\n")
                headers = resp_pkt_cmp[0]
                js_portion = ""
                for comp in resp_pkt_cmp[1:]:
                    js_portion += "\n\n"
                    js_portion += comp
                js_portion = beautify(js_portion)
                beautified_response = headers + "\n\n" + js_portion
                self.responseEditor.setText(beautified_response)
            elif clicked_file_path.endswith(".json"):
                resp_pkt_cmp = response_packet.split("\n\n")
                headers = resp_pkt_cmp[0]
                json_portion = ""
                for comp in resp_pkt_cmp[1:]:
                    json_portion += "\n\n"
                    json_portion += comp
                json_portion_ = json.dumps(json_portion, indent=4)
                json_portion = json.loads(json_portion_).__str__()
                beautified_response = headers + "\n\n" + json_portion
                self.responseEditor.setText(beautified_response)
            else:
                self.responseEditor.setText(response_packet)

    def setSiteMapScope(self):
        scope = []
        scope_ = self.siteMapSettingsScopeLineEdit.text()
        if "," in scope_:
            scps = scope_.split(",")
            [scope.append(scope__.strip()) for scope__ in scps]
        else:
            scope.append(scope_)
        self.siteMapScope.clear()
        self.siteMapScope.extend(scope)
        self.createNodeTree(scope=self.siteMapScope, new_tree=True)
        self.siteMapSettingsWidget.close()

    @staticmethod
    def getAllEntries(dir_):
        paths = []
        for entry in os.listdir(dir_):
            paths.append(os.path.join(dir_, entry))
        return paths

    @staticmethod
    def getTreeEntries(node_container):
        paths = []
        for obj_dict in node_container.obj_dicts:
            paths.extend(list(obj_dict.keys()))
        return paths

    # @staticmethod
    # def getDeletedEntry(self, all_entries:list, tree_entries:list):
    #     for entry in all_entries:

    def removeAbsentNodes(self):
        """removes absent file nodes and dir nodes that may be due to  deletion or recursive deletion"""
        # file nodes 
        new_fileNodes = []
        for fnode in self.fileNodes:
            node_filename = fnode.name
            if Path(node_filename).exists():
                new_fileNodes.append(fnode)
        self.fileNodes = new_fileNodes
        new_dirNodes = []
        for dirNode in self.dirNodes:
            node_container = dirNode.node_container
            self.dirNodeContainers.remove(node_container)
            if Path(node_filename).exists():
                new_dirNodes.append(dirNode)
        self.dirNodes = new_dirNodes


    

    def updateNode(self, filename):
        # self.proxyFileSystemWatcher.blockSignals()
        signaled_filename = filename
        if not Path(filename).exists():
            base_dir = ""
            base_dir_cmps = filename.split("/")[1:-1]
            for cmp in base_dir_cmps:
                base_dir += "/" + cmp
            filename = base_dir
        # print(red(f"updateNode called on {filename}"))
        for node_container in self.dirNodeContainers:
            if node_container.name == filename:
                # print("parent name found")
                if not Path(signaled_filename).exists():
                    # todo: delete also the filenodes
                    # removing the dirNode
                    live_parent_path = get_live_path(filename).rstrip("/")
                    live_pr_container = ""
                    for nc in self.dirNodeContainers:
                        if nc.name == live_parent_path:
                            live_pr_container = nc
                            break
                    live_pr_item = live_pr_container.object_
                    populateNode(live_parent_path,
                                 live_pr_item,
                                 update=True,
                                 nodeContainer=live_pr_container,
                                 pr=self,
                                 contents=live_pr_container.obj_dicts)
                    self.dirNodeContainers.remove(node_container)
                    self.removeAbsentNodes()
                    
                else:
                    all_entries = self.getAllEntries(dir_=filename)
                    tree_entries = self.getTreeEntries(node_container)
                    # if len(all_entries)-len(tree_entries) < 0:
                    #     print(red("entry has been deleted"))
                    #     # deleted_entry = self.getDeletedEntry(all_entries, tree_entries)
                    # else:
                    #     print(red("entry has been added"))
                    Item = node_container.object_
                    populateNode(filename,
                                 Item,
                                 update=True,
                                 nodeContainer=node_container,
                                 pr=self,
                                 contents=node_container.obj_dicts)

        self.proxyFileSystemWatcher.removePaths(self.watchPaths)
        self.watchPaths = self.getWatchPaths()
        self.proxyFileSystemWatcher.addPaths(self.watchPaths)

    def getSiteDirs(self, scope):
        for site_dir in os.scandir(self.proxyDumpDir):
            if site_dir.is_dir():
                if scope is None:
                    self.siteDirs.append(site_dir)
                else:
                    for sc in scope:
                        pattern = re.compile(sc)
                        if len(pattern.findall(site_dir.name)) != 0:
                            self.siteDirs.append(site_dir)

    def createNodeTree(self, scope: list = None, regex=None, new_tree=False):
        if scope is None:
            scope = self.siteMapScope
        if new_tree is True:
            self.proxyFileSystemWatcher.removePaths(self.watchPaths)
            self.siteMapTreeModel.clear()
            self.siteDirs.clear()
        self.getSiteDirs(scope=scope)
        self.top_model_container = parentItemContainer(name=self.proxyDumpDir)
        self.top_model_container.object_ = self.siteMapTreeModel
        for index, site_dir in enumerate(self.siteDirs):
            node = DirNode(self, site_dir,
                           parentPath=self.proxyDumpDir,
                           parent_node_container=self.top_model_container,
                           index_in_node=index)
            node.makeNode()
        self.dirNodeContainers.append(self.top_model_container)
        self.siteMapTreeView.setModel(self.siteMapTreeModel)
        self.watchPaths = self.getWatchPaths()
        self.proxyFileSystemWatcher.addPaths(self.watchPaths)



