import socket
from PySide6 import QtCore, QtGui
from PySide6.QtCore import Signal, QFileSystemWatcher

from PySide6.QtGui import QStandardItem, QStandardItemModel
import subprocess
from PySide6.QtCore import QThread
from pathlib import Path

from PySide6.QtWidgets import QPushButton, QMainWindow, QWidget, QVBoxLayout, QFormLayout, \
    QCheckBox, QFrame, QLabel, QHBoxLayout, QTreeView, QToolTip, QTextEdit, QTabWidget, \
    QLineEdit, QComboBox, QSplitter, QScrollArea, QListView, QApplication
import os
import json
import re

from config import RUNDIR
from PySide6.QtCore import Qt

import targetWindow
from threadrunners import AtomProxy
from utiliities import (
    red,
    cyan,
    yellow
)
from urllib.parse import urlsplit
import queue
import sys
import logging

import random
import atexit
from multiprocessing import cpu_count

import codecs
from jsbeautifier import beautify
from guiUtilities import HoverButton, TextEditor, SyntaxHighlighter, MessageBox
from browserWindow import BrowserWindow

""" functionalities so far:
program output
choosing pentest type(network, web, active directory,etc)
parsed results from amass, sublist3r, subdomainizer  (location of webserver, on what asns, local or 
hosted)
notepad -- for taking notes on the target being worked on 
browser support 
choosing targets
configuring proxy
configuring settings of atomcore(would be commandline args)
configuring settings of tools be used
http history(request-response) just like in burp
comparer 
terminal
git and github account setup
note: https://iconscout.com/

"""

def getLiveSubdomains(subdomains:list):
    pass

class CustomCheckBox(QCheckBox):
    def __init__(self, tootip_text, parent=None):
        super().__init__(parent)
        self.setToolTip(tootip_text)

    def enterEvent(self, event: QtGui.QEnterEvent) -> None:
        QToolTip().showText(self.mapToGlobal(self.rect().bottomRight()), self.toolTip())


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
    processFinishedExecution = Signal(QWidget, str) # the string here is the name of the process wrapper class
    def __init__(self, create_server = False,
                 create_client=False,
                 server_port=57788,
                 ):
        super().__init__()
        self.create_server  = create_server
        self.create_client = create_client
        self.server_port = server_port
        if self.create_server:
            self.server  = socket.create_server(address=("127.0.0.1", self.server_port),
                                                family=socket.AF_INET
                                                )
        if self.create_client:
            self.client = socket.create_connection(address=("127.0.0.1", self.server_port))
    
    def sendFinishedMessage(self, processObjectName:str):
        if processObjectName == "atomRunner":
            message = "atomRunner"
        elif processObjectName == "getAllUrlsRunner":
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

class parentItemContainer():
    def __init__(self, name:str = None, object_= None, obj_dicts:list= None, children:list=None):
        self.name = name
        self.object_ = object_
        self.obj_dicts = obj_dicts
        if self.obj_dicts is None:
            self.obj_dicts = []
        self.children = children
        if self.children is None:
            self.children = []
        self.containerDict = {}
    
    def addChild(self, child:dict):
        self.children.append(child)

    def addContent(self, content:dict):
        self.obj_dicts.append(content)

    def __dict__(self):
        self.containerDict["name"] = self.name 
        self.containerDict["object"] = self.object_ 
        self.containerDict["contents"] = self.contents
        self.containerDict["children"] = self.children

def cleanNode(parentPath, pr):
    """ remove the node_container and the node_containers of the subnodes from the dirNodeContainers"""
    subnode_dirnames = []
    for dir_ in os.scandir(parentPath):
        dirPath = os.path.join(parentPath, dir_.name)
        subnode_dirnames.append(dirPath)
    for subnode_dirname in subnode_dirnames:
        for node_container in pr.dirNodeContainers:
            if node_container.name  == subnode_dirname:
                pr.dirNodeContainers.remove(node_container)

def populateNode(parentPath,
            Item: QStandardItem,
            nodeContainer:parentItemContainer= None,
            update=False,
            pr = None,
            contents = None):
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


def GetUrls(workingdir):
    hrefLinksFile = os.path.join(workingdir, "href_links")
    # read the index file and return the urls in it
    urls = open(hrefLinksFile, "r").read()
    return urls


class LInkFinderRunner(QThread):
    def __init__(self, workingDir,
                 subdomain: str,
                 top_parent,
                 parent=None,
                 mainWindow = None
                 ):
        super().__init__()
        self.mainWindow = mainWindow
        self.topParent = top_parent
        self.parent  = parent
        self.setObjectName("LinkFinderRunner")
        self.workingDir = workingDir
        self.subdomain = subdomain
        self.pid = 0
        self.process = 0
        self.savePathName = "linkFinder_" + self.subdomain + "Subdomains.txt"
        self.savePath = os.path.join(self.workingDir, self.savePathName)
        self.linkfinder = RUNDIR + "Tools/LinkFinder/linkfinder.py"
        if sys.platform == "win32":
            self.linkfinder = RUNDIR + "Tools\\LinkFinder\\linkfinder.py"

    def getPid(self):
        return self.pid

    def linkFinderRun(self):
        self.subdomain = "https://" + self.subdomain.strip()
        command = f"python {self.linkfinder} -i {self.subdomain} -d -o {self.savePath} -t 20"
        print(red(f"running linkFinder with command:\n\t {command}"))
        self.process = subprocess.Popen(command, shell=True)
        self.parent.linkFinderRunnerPid = self.process.pid
        self.pid  = self.process.pid
        self.process.wait()
        
    def run(self) -> None:
        self.linkFinderRun()
        self.topParent.socketIpc.processFinishedExecution.emit(self.mainWindow, self.objectName())


class getAllUrlsRunner(QThread):
    def __init__(self, workingDir,
                 subdomain,
                 parent=None,
                 top_parent = None,
                 mainWindow = None):
        super().__init__()
        self.mainWindow = mainWindow
        self.topParent = top_parent
        self.parent = parent
        self.setObjectName("getAllUrlsRunner")
        self.subdomain = subdomain
        self.workingDir = workingDir
        self.pid = 0
        self.process = 0
        self.savePathName = "getAllUrls_" + self.subdomain + "Subdomains.txt"
        self.savePath  = os.path.join(self.workingDir, self.savePathName)
        self.mainWindow.threads.append(self)
        self.topParent.ThreadStarted.emit(self.mainWindow, self.objectName())

    def getPid(self):
        return self.pid
    
    def parseOutput(self):
        newfileLines = []
        if Path(self.savePath).exists():
            with open(self.savePath, "r") as f:
                fileLines = f.readlines()
                seen_structs = []
                seen_urls = []
                for url in fileLines:
                    if not url.endswith((".js", ".pdf", ".css", ".txt", ".png", ".svg", "ico")):
                        url_cmps = urlsplit(url)
                        url_path = url_cmps[1] + url_cmps[2]
                        if "?" in url:
                            if "&" in url_cmps[3]:
                                url_paramsets = url_cmps[3].split("&")
                            else:
                                url_paramsets = url_cmps[3].split(";")
                            url_params_dict = {}
                            for url_paramset in url_paramsets:
                                try:
                                    split_url_paramset = url_paramset.split("=")
                                    key = split_url_paramset[0]
                                    value = split_url_paramset[1]
                                    url_params_dict[key] = value
                                except:
                                    pass
                            url_params_struct = list(url_params_dict.keys())
                            url_struct = [url_path, url_params_struct]
                            if url_struct not in seen_structs:
                                newfileLines.append(url)
                                seen_structs.append(url_struct)
                        else:
                            if url_path not in seen_urls:
                                newfileLines.append(url)
                                seen_urls.append(url_path)
            with open(self.savePath, "w") as file:
                file.writelines(newfileLines)

    def run(self) -> None:
        command = "getallurls " + self.subdomain + " > " + self.savePath
        print(red(f"Running getallurls with command:\n\t {command}"))
        self.process = subprocess.Popen(command, shell=True)
        self.pid = self.process.pid
        self.parent.getAllUrlsRunnerPid = self.process.pid
        # self.sleep(2)
        self.process.wait()
        self.topParent.socketIpc.processFinishedExecution.emit(self.mainWindow, self.objectName())
        self.parseOutput()


class AtomRunner(QThread):
    def __init__(self, subdomain,
                 usehttp,
                 useBrowser,
                 parent = None,
                 projectDirPath=None,
                 top_parent = None,
                 objectName = None,
                 mainWindow= None) -> None:
        super().__init__()
        self.mainWindow = mainWindow
        self.setObjectName(objectName)
        self.topParent = top_parent
        self.parent = parent
        self.projectDirPath = projectDirPath
        self.subdomain = subdomain
        self.usehttp = usehttp
        self.usebrowser = useBrowser
        self.recursive = True
        self.pid = 0
        self.process = 0
        self.command  = f"python {RUNDIR + 'src/atomcore.py'} -d {self.subdomain} --dirr {self.subdomain} -p {self.projectDirPath}"
        if self.usehttp is True:
            self.command  = self.command + " --use_http"
        if self.usebrowser is True:
            self.command  = self.command + " --use_browser"
        self.mainWindow.threads.append(self)
        self.topParent.ThreadStarted.emit(self.mainWindow, self.objectName())

    def getPid(self):
        return self.pid

    def run(self):
        # self.runAtom()
        self.process = subprocess.Popen(self.command, shell=True)
        self.pid = self.process.pid
        self.parent.atomRunnerPid = self.process.pid
        self.process.wait()
        self.topParent.socketIpc.processFinishedExecution.emit(self.mainWindow, self.objectName())

class ToolsRunner:
    def __init__(self, workingDir,
                 subdomain,
                 tool = None,
                 parent = None,
                 top_parent = None,
                 mainWindow = None):
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
                                                 top_parent = self.topParent,
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

            LInkFinderRunner_ = LInkFinderRunner(self.workingDir, self.subdomain, parent = self, top_parent=self.topParent, mainWindow=self.mainWindow)
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
                                     parent = self,
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
                                                 parent=self,top_parent=self.topParent,
                                                 mainWindow=self.mainWindow)
            getAllUrlsRunner_.start()
            g_pid  = getAllUrlsRunner_.getPid()

            LInkFinderRunner_ = LInkFinderRunner(self.workingDir,
                                                 self.subdomain,
                                                 parent=self,
                                                 top_parent=self.topParent,
                                                 mainWindow = self.mainWindow)
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
            a_pid  = AtomRunner_.getPid()
            return g_pid, l_pid, a_pid

def getAtomSubdUrls(subdomain, workingDir):
    atomSbdUrls = set()
    for rootDir, dirs, files in os.walk(workingDir):
        for file in files:
            if file == "href_links":
                with open(file, "r") as f:
                    urls = f.readlines()
    for url in urls:
        if url.startsWith((f"https://{subdomain}", f"http://{subdomain}")):
            atomSbdUrls.add(url)
    return list(atomSbdUrls)


def atomGuiGetUrls(subdomain: str, workingDir, parent = None,
                   top_parent = None, mainWindow=None):
    # tools: Atom, getallUrls, linkFinder, xnLinkFinder(Atom)
    subdomain = subdomain.replace("\n", "").strip()
    UrlsList_ = set()
    pids = []
    pathName = "getAllUrls_" + subdomain + "Subdomains.txt"
    pathName = os.path.join(workingDir, pathName)
    if Path(pathName).exists():
        logging.info(f"Found {pathName}, Not running getAllUrls")
        with open(pathName, "r") as f:
            UrlsList = f.readlines()
            [UrlsList_.add(url) for url in UrlsList]
    else:
        ToolsRunner_ = ToolsRunner(workingDir,subdomain,
                                   tool = "getAllUrls",
                                   parent = parent,
                                   top_parent = top_parent,
                                   mainWindow=mainWindow)
        g_pid= ToolsRunner_.runUrlToolsOnSd()
        pids.append(g_pid)

    pathName0 = "linkFinder_"+subdomain+"Subdomains.txt"
    pathName0 = os.path.join(workingDir, pathName0)
    if Path(pathName0).exists():
        logging.info(f"Found {pathName0}, Not running linkFinder")
        # link finder does not produce any urls it just produces output.html   
    else:
        ToolsRunner_ = ToolsRunner(workingDir,
                                   subdomain,
                                   tool="LinkFinder",
                                   parent = parent,
                                   top_parent=top_parent,
                                   mainWindow=mainWindow)
        l_pid= ToolsRunner_.runUrlToolsOnSd()
        pids.append(l_pid)

    try:
        atomSubdUrls = getAtomSubdUrls(subdomain, workingDir) 
        [UrlsList_.add(url) for url in atomSubdUrls]
    except UnboundLocalError as error:
        ToolsRunner_ = ToolsRunner(workingDir, subdomain, tool="Atom",
                                   parent=parent,
                                   top_parent = top_parent,
                                   mainWindow=mainWindow)
        a_pid = ToolsRunner_.runUrlToolsOnSd()
        pids.append(a_pid)

    if len(list(UrlsList_)) == 0:
        return tuple(pids)
    else:
        return list(UrlsList_)
    # runUrlToolsOnSd(workingDir, subdomain)

class UrlGetter(QThread, QtCore.QObject):
    urlGetterFinished = Signal()
    def __init__(self, subdomainUrlDict: dict,
                 workingDir,
                 parent = None,
                 dict_parent= None,
                 top_parent = None,
                 mainWindow = None):
        super().__init__()
        self.setObjectName("UrlGetter")
        self.mainWindow = mainWindow
        self.topParent = top_parent
        self.subdomainUrlDict = subdomainUrlDict
        self.workingDir = workingDir
        self.subdomainsUrlDict_ = {}
        self.parent  = parent
        self.dictParent = dict_parent
        self.receivedSignals = 0
        self.subdomainsUrlDict_file = os.path.join(workingDir, "subdomainsUrlDict.json")
        self.topParent.socketIpc.processFinishedExecution.connect(self.processFinishedExecution)
        self.mainWindow.threads.append(self)
        self.setTerminationEnabled(True)
        self.topParent.ThreadStarted.emit(self.mainWindow, self.objectName())
        self.destroyed.connect(self.closeThread)
    
    def closeThread(self):
        self.topParent.socketIpc.processFinishedExecution.emit(self.mainWindow, self.objectName())

    def processFinishedExecution(self, windowInstance, tool):
        self.receivedSignals += 1

    def run(self):
        i = 0
        successful_subdomains = set()
        error_subdomains = set()
        logging.info(f"UrlGetter to work on {len(list(self.subdomainUrlDict.keys()))}")
        for subdomain in list(self.subdomainUrlDict.keys()):
            subdomain = subdomain.replace("\n", "")
            logging.info(f"running atomGuiGetUrls on : {subdomain}, Number: {i}")
            result = atomGuiGetUrls(subdomain, self.workingDir,
                                    parent= self.parent,
                                    top_parent = self.topParent,
                                    mainWindow=self.mainWindow)
            if type(result) == tuple:
                result = list(result)
                print(red(result))
                print(yellow("Waiting for processes to close"))
                while True:
                    if self.receivedSignals == len(result):
                        self.receivedSignals = 0
                        break
            elif type(result) == list:
                self.subdomainsUrlDict_[subdomain] = result
                self.dictParent.SubdomainUrlDict[subdomain] = result
                self.dictParent.modelUpdater.dictChanged.emit()
                # self.dictParent.subdomainsModel.dataChanged.emit(QtCore.QModelIndex(), QtCore.QModelIndex())
            i += 1
            if cpu_count() <= 4:
                self.sleep(5)
            elif cpu_count() <= 8:
                self.sleep(2)
        self.urlGetterFinished.emit()
        logging.info(f"Worked on {len(self.subdomainUrlDict.keys())} subdomains")
        logging.info(f"{len(list(successful_subdomains))} Successful")
        logging.info(f"{len(list(error_subdomains))} Failed")
        logging.info(f"failed are {list(error_subdomains)}")
        # jsonData = json.dumps(self.subdomainsUrlDict_)
        jsonData = json.dumps(self.dictParent.SubdomainUrlDict)
        with open(self.subdomainsUrlDict_file, "w") as f:
            f.write(jsonData)
        self.topParent.socketIpc.processFinishedExecution.emit(self.mainWindow, self.objectName())


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


class ReqResTextEditor(TextEditor, QtCore.QObject):
    sendToRepeaterSignal = Signal(str)
    sendToDecoderSignal = Signal(str)

    def __init__(self):
        super().__init__()

    def contextMenuEvent(self, event):
        menu = self.createStandardContextMenu()

        sendToRepeaterAction = QtGui.QAction("send to repeater", self)
        sendToRepeaterAction.triggered.connect(self.sendRequestToRepeater)
        menu.addAction(sendToRepeaterAction)

        sendToDecoderAction  = QtGui.QAction("send to decoder", self)
        sendToDecoderAction.triggered.connect(self.sendHighlightedToDecoder)
        menu.addAction(sendToDecoderAction)

        menu.exec()

    def sendHighlightedToDecoder(self):
        # self.sendToDecoderSignal.emit(self.)
        pass

    def sendRequestToRepeater(self):
        # print(red("send to repeater signal has been emitted"))
        self.sendToRepeaterSignal.emit(self.toPlainText())
    

class RepeaterReqResTextEditor(TextEditor):
    def __init__(self):
        super().__init__()
        self.setBaseSize(650, 650)
        self.setMaximumWidth(750)

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

        self.resultTextBox  = QTextEdit()
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

    def decodeBase64(self, text:bytes):
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
                html+="\n\n"
        # browser_window.Page.setContent(bytes(html, "utf-8"), mimeType="html")
        browser_window.Page.setHtml(html)
        self.topParent.tabManager.addTab(browser_window, "render")

class RepeaterWindow(QMainWindow, QtCore.QObject):

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
        self.instanceRepeaterSplitter= None
        self.req_res_tabManager= None
        self.requestsEditorFrame= None
        self.requestsEditorLayout= None
        self.requestsEditor= None
        self.repeaterSendReqButton= None
        self.responseEditor= None
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

        tabAttributes= {
            "instanceRepeaterSplitter":instanceRepeaterSplitter,
            "req_res_tabManager":req_res_tabManager,
            "requestsEditorFrame":requestsEditorFrame,
            "requestsEditorLayout":requestsEditorLayout,
            "requestsEditor":requestsEditor,
            "repeaterSendReqButton":repeaterSendReqButton,
            "responseEditor":responseEditor}

        self.repeaterTabs.append(tabAttributes)
        self.repeaterTabManager.setCurrentIndex(self.repeaterTabManager.indexOf(instanceRepeaterSplitter))
        self.firstTabPresent = True
        if self.repeaterTabManager.currentIndex() == 0:
            self.repeaterTabManager.currentChanged.emit(0)
    

    def changeTabAttributes(self):
        curIndex_ = self.repeaterTabManager.currentIndex()
        if self.firstTabPresent:
            self.instanceRepeaterSplitter= self.repeaterTabs[curIndex_]["instanceRepeaterSplitter"]
            self.req_res_tabManager= self.repeaterTabs[curIndex_]["req_res_tabManager"]
            self.requestsEditorFrame= self.repeaterTabs[curIndex_]["requestsEditorFrame"]
            self.requestsEditorLayout= self.repeaterTabs[curIndex_]["requestsEditorLayout"]
            self.requestsEditor= self.repeaterTabs[curIndex_]["requestsEditor"]
            self.repeaterSendReqButton= self.repeaterTabs[curIndex_]["repeaterSendReqButton"]
            self.responseEditor= self.repeaterTabs[curIndex_]["responseEditor"]


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


class GuiProxyClient(QThread):
    def __init__(self, request:str, is_command=False, proxy_port = None):
        super().__init__()
        self.setObjectName("GuiProxyClient")
        self.is_command = is_command
        self.responseDir = RUNDIR + "tmp/"
        self.respose_file = os.path.join(self.responseDir, "response.txt")
        self.request = self.makeRequestPacket(request)
        self.proxy_port = proxy_port
        self.proxyAddress = ("127.0.0.1", self.proxy_port)
        try:
            self.socket = socket.create_connection(self.proxyAddress,timeout=10)
        except ConnectionRefusedError or ConnectionAbortedError or ConnectionResetError as e:
            logging.error(f"Connection error: {e}")
            self.exit()

    def makeRequestPacket(self, request:str):
        request_lines = request.split("\n")
        new_request = ""
        for rl in request_lines:
            if request_lines.index(rl) == 0:
                new_request = rl
            else:
                new_request = new_request+"\r\n"+rl
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

class FileNode():
    def __init__(self,
                 pr,
                 text,
                 parentItem,
                 parent_path,
                 parent_node_container,
                 index_in_node):
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
        self.parentItem.appendRow(self.item)
        self.obj_idx_dict[self.name] = self.index_in_node
        self.parent_node_container.addContent(self.obj_idx_dict)
        self.pr.fileNodes.append(self)

class DirNode():
    def __init__(self, parent, dir_:os.DirEntry,
                 parentPath=None,
                 parentNodeItem:QStandardItem = None,
                 parent_node_container:parentItemContainer=None,
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
        if self.parentNodeItem is None:
            self.parent.siteMapTreeModel.appendRow(self.Item)
        else:
            self.parentNodeItem.appendRow(self.Item)
        self.parent.dirNodeContainers.append(self.node_container)
        self.obj_idx_dict[self.node_container.name] = self.index_in_node
        self.parent_node_container.addContent(self.obj_idx_dict)
        # self.parent.dirNodes.append(self) #README if you allow this you must make sure a node is deleted if a dir is deleted
    
    def expandNode(self):
        populateNode(self.defaultParentPath, self.Item, self.node_container, pr=self.parent)
    
    def makeNode(self):
        self.addNode()
        self.expandNode()
 
class SiteMapWindow(QMainWindow):
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.siteMapMainWidget = QWidget()
        self.setCentralWidget(self.siteMapMainWidget)
        self.siteMapMainWidgetLayout = QVBoxLayout()
        self.siteMapMainWidget.setLayout(self.siteMapMainWidgetLayout)
        self.proxyDumpDir = "/home/program/AtomProjects/Proxy/"
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
        self.siteMapListViewSettingsButtonIcon = QtGui.QIcon(
            RUNDIR + "resources/icons/settings-icon-gear-3d-render-png.png")
        self.siteMapListViewSettingsButton.setIcon(self.siteMapListViewSettingsButtonIcon)
        self.siteMapListViewSettingsButton.clicked.connect(self.openSiteMapSettings)
        self.siteMapUpperLayout.addWidget(self.siteMapListViewSettingsButton, alignment=Qt.AlignRight)

        self.siteMapLoggingLabel = QLabel()
        self.siteMapLoggingLabel.setText("Logging:")
        self.siteMapUpperLayout.addWidget(self.siteMapLoggingLabel)

        self.siteMapLoggingCheckBox  = QCheckBox()
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
            self.loggingOffCommand  =False
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
                command  = {"scope":self.siteMapScope}
                request = json.dumps(command)
            elif self.logggingOnCommand:
                command = {"log":0}
                request = json.dumps(command)
            elif self.loggingOffCommand:
                command = {"log":1}
                request = json.dumps(command)
            self.guiProxyClient = GuiProxyClient(request, is_command=True, proxy_port=self.parent.proxy_port)
            self.guiProxyClient.start()
        except ConnectionAbortedError or ConnectionResetError:
            logging.warn("Connection error in socket")
            pass

    def readReqResData(self, index: QtCore.QModelIndex):
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
        if file_obtained:
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
                js_portion= ""
                for comp in resp_pkt_cmp[1:]:
                    js_portion+="\n\n"
                    js_portion+=comp
                js_portion = beautify(js_portion)
                beautified_response = headers+"\n\n"+js_portion
                self.responseEditor.setText(beautified_response)
            elif clicked_file_path.endswith(".json"):
                resp_pkt_cmp = response_packet.split("\n\n")
                headers = resp_pkt_cmp[0]
                json_portion= ""
                for comp in resp_pkt_cmp[1:]:
                    json_portion+="\n\n"
                    json_portion+=comp
                json_portion_ = json.dumps(json_portion, indent=4)
                json_portion = json.loads(json_portion_).__str__()
                beautified_response = headers+"\n\n"+json_portion
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


    def updateNode(self, filename):
        # self.proxyFileSystemWatcher.blockSignals()
        signaled_filename = filename
        if not Path(filename).exists():
            base_dir = ""
            base_dir_cmps = filename.split("/")[1:-1]
            for cmp in base_dir_cmps:
                base_dir += "/"+cmp
            filename = base_dir
        print(red(f"updateNode called on {filename}"))
        for node_container in self.dirNodeContainers:                
            if node_container.name == filename:
                print("parent name found")
                if not Path(signaled_filename).exists():
                    # todo: delete also the filenodes
                    self.dirNodeContainers.remove(node_container)
                else:
                    all_entries = self.getAllEntries(dir_= filename)
                    tree_entries  = self.getTreeEntries(node_container)
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
                            pr = self,
                            contents = node_container.obj_dicts)

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

    def createNodeTree(self, scope: list = None, regex=None, new_tree = False):
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
                           parentPath= self.proxyDumpDir,
                           parent_node_container=self.top_model_container,
                           index_in_node=index)
            node.makeNode()
        self.dirNodeContainers.append(self.top_model_container)
        self.siteMapTreeView.setModel(self.siteMapTreeModel)
        self.watchPaths = self.getWatchPaths()
        self.proxyFileSystemWatcher.addPaths(self.watchPaths)
    

    def closeEvent(self, event: QtGui.QCloseEvent) -> None:
        # return super().closeEvent(event)
        self.siteMapUpdater.exit()

class SessionHandlerRunner(QThread, QtCore.QObject):
    def __init__(self, top_parent):
        super().__init__()
        self.top_parent = top_parent
        self.command = f"python {RUNDIR}src/session.py"
        self.setObjectName("SessionHandler")
        self.process = 0
        self.top_parent.threads.append(self)
        self.top_parent.ThreadStarted.emit(self.top_parent, self.objectName())

    def run(self):
        self.process = subprocess.Popen(self.command, shell=True)
        self.process.wait()
        self.top_parent.socketIpc.processFinishedExecution.emit(self.top_parent, self.objectName())


class ThreadMon(QWidget):
    def __init__(self, thread, top_parent):
        super().__init__()
        self.topParent = top_parent
        self.formLayout = QFormLayout()
        self.thread  = thread
        self.nameLabel = QLabel()
        self.nameLabel.setText(thread.objectName())
        self.formLayout.addRow("Thread Name: ", self.nameLabel)
        self.status = self.getStatus()
        self.label = QLabel()
        self.label.setText(self.status)
        self.formLayout.addRow("Status: ",self.label)
        self.threadStopButton = HoverButton("stop thread", "stop the thread from running")
        self.threadStopButton.clicked.connect(self.exitThread)
        self.formLayout.addRow("Stop Thread: ", self.threadStopButton)
        self.process = 0
        self.setLayout(self.formLayout)
        self.topParent.socketIpc.processFinishedExecution.connect(self.closeWidget)

    def closeWidget(self, windowInstance, objectName):
        if objectName == self.thread.objectName():
            for thread in windowInstance.threads:
                if thread.objectName() == objectName:
                    windowInstance.threads.remove(thread)
            self.close()
    
    def getStatus(self):
        try:
            self.process = self.thread.process
            self.status= "Running"
        except AttributeError:
            self.status = "Not Running"
            if self.thread.isRunning():
                self.status = "Running"
        return self.status

    def exitThread(self):
        try:
            self.pid = self.thread.process.pid
            if sys.platform == "win32":
                os.system(f"taskkill /F /PID {int(self.pid)}")
            elif sys.platform == "linux":
                os.system(f"kill {int(self.pid+1)}")
            if self.thread.process.process_name == "atomProxy":
                self.topParent.isProxyRunning = False
            logging.info(f"Terminating subprocess with pid f{self.pid}")
        except AttributeError:
            logging.info(f"Terminating thread {self.thread}")
            self.thread.terminate()
            self.thread.quit()
            if self.thread.isRunning():
                logging.error(f"Failed to terminate thread {self.thread}")

class ThreadMonitor(QMainWindow):
    def __init__(self, top_parent= None):
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

    def addThreadMon(self, windowInstance, threadName):
        for thread in windowInstance.threads:
            if thread.objectName() == threadName:
                for layout in self.windowInstancesLayouts:
                    if layout.objectName() == windowInstance.objectName():
                        threadMonWidget = ThreadMon(thread, self.top_parent)
                        layout.addWidget(threadMonWidget)                    

    def addTab(self, windowInstance):
        logging.info(windowInstance)
        threads = windowInstance.threads
        tabname = windowInstance.objectName().split("/")[-1]

        newTabWidget = QWidget()
        centralWidgetLayout = QVBoxLayout()
        newTabWidget.setLayout(centralWidgetLayout)

        newTabScrollArea = QScrollArea()
        centralWidgetLayout.addWidget(newTabScrollArea)

        scrollAreaWidget  = QWidget()
        newTabLayout= QVBoxLayout()
        newTabLayout.setObjectName(windowInstance.objectName())
        scrollAreaWidget.setLayout(newTabLayout)
        newTabScrollArea.setWidget(scrollAreaWidget)
        newTabScrollArea.setWidgetResizable(True)
        newTabWidget.setObjectName(windowInstance.objectName())
        for thread in threads:
            threadMonWidget = ThreadMon(thread, top_parent = self.top_parent)
            newTabLayout.addWidget(threadMonWidget)
        self.tabManager.addTab(newTabWidget, tabname)
        self.windowInstancesLayouts.append(newTabLayout)
    # def stopRunningThread()

class MainWin(QMainWindow, QtCore.QObject):
    newProjectCreated = Signal(QMainWindow)
    projectClosed = Signal(QMainWindow, int)
    ThreadStarted  = Signal(QWidget, str)
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
        self.isSessionHandlerRunning = False
        self.startSessionHandler()
        self.startproxy()
        
        self.setWindowTitle("AWE(Atom Web Enumeration Framework)")
        self.homeDirectory = os.path.expanduser("~")
        self.defaultWorkspaceDir = os.path.join(self.homeDirectory, "AtomProjects/")
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

        # self.AddTargetTab("target one")
        self.upperTabMenuLayout = QHBoxLayout()
        # close tab button
        self.closeTabButton = QPushButton()
        self.closeTabButton.setText("Close Tab")
        self.closeTabButton.setFixedWidth(120)
        self.closeTabButton.clicked.connect(self.closeTab)
        self.upperTabMenuLayout.addWidget(self.closeTabButton)

        # add target button
        self.addTabButton = QPushButton()
        self.addTabButton.setText("Add Target")
        self.addTabButton.setFixedWidth(120)
        self.addTabButton.clicked.connect(self.AddTargetWindow)
        self.upperTabMenuLayout.addWidget(self.addTabButton)

        # start proxy button
        self.startProxyButton  = QPushButton()
        self.startProxyButton.setText("Start Proxy")
        self.startProxyButton.setFixedWidth(130)
        self.startProxyButton.clicked.connect(self.startproxy)
        self.upperTabMenuLayout.addWidget(self.startProxyButton)

        self.upperTabMenuLayout.setAlignment(self.addTabButton, Qt.AlignLeft)

        self.MainLayout.addLayout(self.upperTabMenuLayout)

        self.MainLayout.addWidget(self.tabManager)
        self.setCentralWidget(self.centralWidget)
        self.mainTabLayout.addStretch()
        # add repeater tab
        self.repeaterWindow = RepeaterWindow(parent=self)
        self.tabManager.addTab(self.repeaterWindow, "Repeater")
        # add site map Target
        self.addSiteMapTab()
        self.addThreadMonitorTab()
        atexit.register(self.saveProgramState)
        self.socketIpc.processFinishedExecution.connect(self.finishedProcess)
        self.newProjectCreated.emit(self)

    def finishedProcess(self, windowInstance, tool:str):
        logging.info(yellow(f"{tool} finished execution"))

    def addThreadMonitorTab(self):
        self.threadMonitor = ThreadMonitor(top_parent= self)
        self.tabManager.addTab(self.threadMonitor, "Thread Monitor")

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
            logging.info("Starting proxy")
            self.proxy_ = AtomProxy(self.proxy_port, top_parent = self)
            self.proxy_.start()
            self.isProxyRunning = True
        else:
            proxyMessageBox = MessageBox("information", "The proxy is Running", "Information", "Ok")
            ret = proxyMessageBox.exec()

    def addRepeaterInstanceTab(self, request: str = None):
        self.repeaterWindow.addReqResInstanceTabManager(request)

    def addSiteMapTab(self):
        self.siteMapWindow = SiteMapWindow(parent = self)
        self.siteMapWindow.requestsEditor.sendToRepeaterSignal.connect(self.addRepeaterInstanceTab)
        # self.siteMapWindow.responseEditor.sendToRepeaterSignal.connect(self.addRepeaterTab)
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
        self.dirListView.setEditTriggers(QListView.NoEditTriggers)
        self.dirListView.setModel(self.dirsModel)
        self.dirListView.clicked.connect(self.projectDirClicked)

        self.dirsProjectsScrollArea = QScrollArea()
        self.dirsProjectsScrollArea.setWidget(self.dirListView)
        self.dirsProjectsScrollArea.setWidgetResizable(True)
        self.dirsProjectsScrollArea.setFixedHeight(450)
        self.dirsProjectsScrollArea.setFixedWidth(450)
        self.mainTabLayout.addWidget(self.dirsProjectsScrollArea, alignment=Qt.AlignCenter)

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
                                                   index = self.openProjectCount)
            self.openMainWindows.append(self.mainWindowInstance)
            self.tabManager.addTab(self.mainWindowInstance, tab_name)
            self.tabManager.setCurrentIndex(
                self.tabManager.indexOf(self.mainWindowInstance)
            )
            self.newTargetWindow.close()

    def AddTargetTab(self, directory=""):
        self.openProjectCount += 1
        self.mainWindowInstance = targetWindow.TargetWindow(directory, self.proxy_port, self, index = self.openProjectCount)
        self.openMainWindows.append(self.mainWindowInstance)
        tab_name = directory.split("/")[-1]
        self.tabManager.addTab(self.mainWindowInstance, tab_name)
        self.tabManager.setCurrentIndex(
            self.tabManager.indexOf(self.mainWindowInstance)
        )

    def closeTab(self):
        self.current_tab_index = self.tabManager.currentIndex()
        if self.current_tab_index > 3:
            self.tabManager.currentWidget().close()
            self.tabManager.removeTab(self.current_tab_index)

    def closeEvent(self, event: QtGui.QCloseEvent) -> None:
        if sys.platform == "win32":
            os.system(f"taskkill /F /PID {self.proxy_.process.pid}")
            os.system(f"taskkill /F /PID {self.sessionHandler.process.pid}")
        elif sys.platform == "linux":
            os.system(f"kill {self.proxy_.process.pid+1}")
            os.system(f"kill {self.sessionHandler.process.pid+1}")
        return super().closeEvent(event)

def getLogNumber(rundir_):
    logs_dir = rundir_+"logs/"
    filenumbers = []
    if len(os.listdir(logs_dir)) != 0:
        for file in os.listdir(logs_dir):
            filenumber = int(file.split(".log")[0].split("log")[1])
            filenumbers.append(filenumber)
        return (max(filenumbers) + 1)
    else:
        return 0

if __name__ == "__main__":
    log_filename = RUNDIR + "logs/log" + str(getLogNumber(RUNDIR)) + ".log"
    if not Path(log_filename).exists():
        if not Path(os.path.dirname(log_filename)).is_dir():
            os.makedirs(os.path.dirname(log_filename))
    logging.basicConfig(level=logging.DEBUG, format= '%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s')
    App = QApplication()
    main_window = MainWin()
    main_window.show()
    sys.exit(App.exec())
    
# TODO:
"""
1.dns server finders
2.controlled speed during enumeration (random speed but controlled increaments and or decreaments )
3.configuring of proxy networks from different providers during enumeration(if speed is good enough then then tor can also be used)
4.api finders
5.tech stack categorizing(webapp frameworks and libraries)
5.location of servers(geographical location, Hosting platform(aws, google, ...))
6.Network mapper

7.visualization engine (2d and 3d)
8.auto-categorization of domain names and urls(pages)
9.ai-intergration in all aspects of the application(from the gui to the testing)
10.Analysis engine(analyzing all the traffic concernnig a specific project that 
has passed through the proxy including all the javascript, css, html, images, http headers, etc)
and the respective presentation gui interface.
"""    