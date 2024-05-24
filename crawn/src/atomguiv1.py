import socket
from PySide6.QtWebEngineCore import QWebEnginePage, QWebEngineSettings, QWebEngineProfile
from PySide6 import QtCore, QtWidgets, QtGui, QtWebEngineWidgets
from PySide6.QtNetwork import QNetworkProxy, QSslCertificate, QSslConfiguration, QNetworkProxyFactory
from PySide6.QtCore import Signal, QRegularExpression

from PySide6.QtGui import QStandardItem, QStandardItemModel
import subprocess
from PySide6.QtCore import QThread
from pathlib import Path

import asyncio
from atomcore import RunMainAtomFunction
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor

import os
import json
import re
import sys

from PySide6.QtGui import QKeyEvent
from utiliities import addHttpsScheme
from PySide6.QtCore import Qt

from utiliities import (
    red,
    cyan,
    AmassSubdProcessor,
    SubDomainizerRunner,
    SublisterRunner,
    rm_same,
    yellow
)
from urllib.parse import urlsplit
import queue
import sys
import logging
import time

import random
import atexit
from multiprocessing import cpu_count

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

# logging.basicConfig()
rundir = "/media/program/01DA55CA5F28E000/MYAPPLICATIONS/AWE/AWE/crawn/"
if sys.platform == "WIN32":
    rundir  = "D:\\MYAPPLICATIONS\\AWE\\AWE\\crawn\\"

class CustomCheckBox(QtWidgets.QCheckBox):
    def __init__(self, tootip_text, parent=None):
        super().__init__(parent)
        self.setToolTip(tootip_text)

    def enterEvent(self, event: QtGui.QEnterEvent) -> None:
        QtWidgets.QToolTip().showText(self.mapToGlobal(self.rect().bottomRight()), self.toolTip())

class HoverButton(QtWidgets.QPushButton):
    def __init__(self, text, tooltip_text, parent=None):
        super().__init__(text, parent)
        self.setToolTip(tooltip_text)

    def enterEvent(self, event: QtGui.QEnterEvent) -> None:
        QtWidgets.QToolTip().showText(self.mapToGlobal(self.rect().bottomLeft()), self.toolTip())

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
    processFinishedExecution = Signal(QtWidgets.QWidget, str) # the string here is the name of the process wrapper class
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
                                                family=socket.AF_INET,
                                                reuse_port=True,
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

class MessageBox(QtWidgets.QMessageBox):
    """Wrapper class for a QMessageBox
    icon: can be either of [Information, Warning, Critical, Question]
    buttons: can be one or more of : 
    ButtonMask, NoButton ,Default ,Escape ,FlagMask, FirstButton, Ok, 
    Save, SaveAll, Open, Yes, YesAll, YesToAll, No, NoAll, NoToAll, Abort
    Retry ,Ignore, Close, Cancel, Discard, Help, Apply, Reset, LastButton
    RestoreDefaults"""
    def __init__(self, windowTitle:str = None, text:str = None, icon:str = None, buttons:list = None):
        super().__init__()
        self.windowTitle_ = windowTitle
        self.text = text
        self.icon = icon
        self.setWindowTitle(self.windowTitle_)
        self.setText(self.text)
        if self.icon == "Information":
            self.setIcon(QtWidgets.QMessageBox.Information)
        elif self.icon == "Warning":
            self.setIcon(QtWidgets.QMessageBox.Error)
        elif self.icon == "Critical":
            self.setIcon(QtWidgets.QMessageBox.Critical)
        elif self.icon == "Question":
            self.setIcon(QtWidgets.QMessageBox.Question)
        # self.setStandardButtons(self.button)

def iterDir(parentPath, parentItem: QStandardItem):
    for element in os.scandir(parentPath):
        if element.is_file():  # if it is a file , append it to the parent item
            element_item = QStandardItem(element.name)
            parentItem.appendRow(element_item)
        elif element.is_dir():
            pPath = os.path.join(parentPath, element.name)
            pItem = QStandardItem(element.name)
            parentItem.appendRow(pItem)
            iterDir(pPath, pItem)


def atomGuiGetSubdomains(projectDirPath, toolName):
    filename = ""
    if toolName == "amass":
        filename = "amassSubdomains.txt"
    elif toolName == "sublist3r":
        filename = "sublisterSubdomains.txt"
    elif toolName == "subdomainizer":
        filename = "subdomainizerSubdomains.txt"
    filepath = os.path.join(projectDirPath + "/", filename).replace(" ", "")
    if not Path(filepath).exists():
        return False, None, None
    else:
        with open(filepath, "r") as file:
            list_subdomains = file.readlines()
            len_subdomains = len(list_subdomains)
            subdomiansStr = ""
            for subdomain in list_subdomains:
                subdomiansStr = subdomiansStr + subdomain
        if len_subdomains == 0:
            return False, None, None
        else:
            return True, subdomiansStr, len_subdomains


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
        self.linkfinder = "/media/program/01DA55CA5F28E000/MYAPPLICATIONS/AWE/AWE/crawn/Tools/LinkFinder/linkfinder.py"

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
        self.command  = f"python {rundir+'src/atomcore.py'} -d {self.subdomain} --dirr {self.subdomain} -p {self.projectDirPath}"
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

class Qterminal(QtWidgets.QTextEdit):
    def __init__(self) -> None:
        super().__init__()
        self.terminalDefaultText = ">>>"
        self.setPlainText(self.terminalDefaultText)
        self.placeCursorAtEnd()
        font = self.font()
        font.setPointSize(font.pointSize() + 1)
        self.setFont(font)
        self.currentWorkingDir = self.getCurrentWorkingDir().replace("\n", "").strip()
        self.acceptRichText()
        self.plainStringRegexPattern = "[a-zA-Z]+"

    def getCurrentWorkingDir(self):
        output = subprocess.Popen(
            "pwd", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        pwd = output.communicate()[0].decode("utf-8")
        return pwd

    # def Initialize(self):
    # self.TextEditTerminal = QtWidgets.QTextEdit()

    def keyPressEvent(self, e: QKeyEvent) -> None:
        if e.key() == Qt.Key_Return or e.key() == Qt.Key_Enter:
            lines = self.toPlainText()
            # self.doSetTextCursor(QtCore.Qmain)
            Lines = lines.split("\n")
            command = (
                Lines[len(Lines) - 1].replace(self.terminalDefaultText, "").strip()
            )
            if command != "":
                if command == "clear":
                    self.clear()
                    self.setPlainText(self.terminalDefaultText)
                    self.placeCursorAtEnd()
                elif command.startswith("cd "):
                    precurrentWorkingDir = ""
                    UserSetWorkingDir = command.split(" ")[1]
                    if UserSetWorkingDir.startswith("/"):
                        precurrentWorkingDir = (
                                self.currentWorkingDir + UserSetWorkingDir + "/"
                        )
                    elif UserSetWorkingDir == "..":
                        if not self.currentWorkingDir == "/":
                            currentWorkingDirr = self.currentWorkingDir.split("/")
                            [
                                currentWorkingDirr.remove(dirr)
                                for dirr in currentWorkingDirr
                                if dirr == ""
                            ]
                            currentWorkingDirr.remove(currentWorkingDirr[-1])
                            newCurrentWorkingDir = ""
                            for dirr in currentWorkingDirr:
                                if currentWorkingDirr.index(dirr) == len(dirr) - 1:
                                    newCurrentWorkingDir = (
                                            newCurrentWorkingDir + "/" + dirr + "/"
                                    )
                                else:
                                    newCurrentWorkingDir = (
                                            newCurrentWorkingDir + "/" + dirr
                                    )
                            precurrentWorkingDir = newCurrentWorkingDir
                    elif UserSetWorkingDir == ".":
                        self.currentWorkingDir = self.currentWorkingDir
                    elif (
                            re.match(self.plainStringRegexPattern, UserSetWorkingDir)
                            is not None
                    ):
                        UserSetWorkingDir = "/" + UserSetWorkingDir + "/"
                        precurrentWorkingDir = (
                                self.currentWorkingDir + UserSetWorkingDir
                        )
                    if os.path.isdir(precurrentWorkingDir):
                        self.currentWorkingDir = precurrentWorkingDir
                    totalLines = lines + "\n" + self.terminalDefaultText
                    # if totalLines[len(totalLines)-1] != self.terminalDefaultText[0]:
                    self.setPlainText(totalLines)
                    self.placeCursorAtEnd()
                else:
                    commandResult = subprocess.Popen(
                        command,
                        shell=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        cwd=self.currentWorkingDir,
                    )
                    commandOutput_ = commandResult.communicate()
                    commandOutput = commandOutput_[0]
                    if commandOutput is not None:
                        commandOutput = commandOutput.decode("utf-8")
                        totalLines = (
                                lines
                                + "\n"
                                + commandOutput
                                + "\n"
                                + self.terminalDefaultText
                        )
                    else:
                        commandError = commandOutput_[1].decode("utf-8")
                        totalLines = (
                                lines + commandError + "\n" + self.terminalDefaultText
                        )
                    self.setPlainText(totalLines)
                    self.placeCursorAtEnd()

        elif e.key() == Qt.Key_Backspace:
            current_text = self.toPlainText()
            current_text_len = len(current_text)
            if current_text[current_text_len - 1] == self.terminalDefaultText[0]:
                pass
            else:
                super().keyPressEvent(e)
        else:
            super().keyPressEvent(e)

    def placeCursorAtEnd(self):
        text_len = len(self.toPlainText())
        cursor = self.textCursor()
        cursor.setPosition(text_len)
        self.setTextCursor(cursor)


class TextEditor(QtWidgets.QTextEdit):
    def __init__(self, parent=None):
        super(TextEditor, self).__init__(parent)
        self.setTabChangesFocus(True)
        self.setTabStopDistance(40)
        self.setAutoIndent(True)
        self.setFontWeight(50)

    def keyPressEvent(self, event: QKeyEvent) -> None:
        if self.autoIndent and event.key() == QtCore.Qt.Key.Key_Return:
            cursor = self.textCursor()
            block = cursor.block()
            text = block.text()
            cursor_position = cursor.positionInBlock()
            leading_spaces = len(text) - len(text.strip())

            if cursor_position > 0 and text.endswith((":", "{")):
                indent = leading_spaces + self.tabStopDistance() // self.fontMetrics().averageCharWidth()
                QtWidgets.QTextEdit.keyPressEvent(self, event)
                cursor.insertText(" " * int(indent))
                return
        elif self.autoIndent and event.key() == QtCore.Qt.Key.Key_Tab:
            cursor = self.textCursor()
            block = cursor.block()
            text = block.text()
            cursor_position = cursor.positionInBlock()
            leading_spaces = len(text) - len(text.strip())

            if cursor_position > 0:
                indent = leading_spaces + self.tabStopDistance() // self.fontMetrics().averageCharWidth()
                # QtWidgets.QTextEdit.keyPressEvent(self, event)
                cursor.insertText(" " * int(indent))
                return

        QtWidgets.QTextEdit.keyPressEvent(self, event)

    def setAutoIndent(self, enabled: bool):
        self.autoIndent = enabled


class SyntaxHighlighter(QtGui.QSyntaxHighlighter):
    def __init__(self, parent=None):
        super(SyntaxHighlighter, self).__init__(parent)

        # the formats for the keywords
        keyword_fmt = QtGui.QTextCharFormat()
        keyword_fmt.setForeground(Qt.yellow)
        # keyword_fmt.setFontWeight(QtGui.QFont.Bold)

        keywords = [
            "class", "def", "if", "else", "elif", "for", "while", "try",
            "except", "finally", "import", "from", "as", "return", "raise"
                                                                   "\."
        ]

        # note the format of a highlight rule: [regularexpression, keywordFormat]
        self.highlightRules = [(QtCore.QRegularExpression("\\b" + keyword + "\\b"), keyword_fmt) for keyword in
                               keywords]

        parentheses_words = ["\(", "\)", "\{", "\}", "\[", "\]"]

        parentheses_fmt = QtGui.QTextCharFormat()
        parentheses_fmt.setForeground(Qt.yellow)
        # parentheses_fmt.setFontWeight(QtGui.QFont.Bold)
        self.highlightRules.extend(
            [(QRegularExpression(keyword), parentheses_fmt) for keyword in parentheses_words]
        )

        # comments 
        comment_fmt = QtGui.QTextCharFormat()
        comment_fmt.setForeground(Qt.magenta)
        # comment_fmt.setFontWeight(QtGui.QFont.Bold)
        self.highlightRules.extend(
            [(QRegularExpression("#.*"), comment_fmt)]
        )

        # python classes self
        self_fmt = QtGui.QTextCharFormat()
        self_fmt.setForeground(Qt.red)
        # self_fmt.setFontWeight(QtGui.QFont.Bold)
        self.highlightRules.extend(
            [(QRegularExpression("self(?=\.)"), self_fmt)]
        )

        # python functions declaration after def
        func_decl_fmt = QtGui.QTextCharFormat()
        func_decl_fmt.setForeground(Qt.magenta)
        # func_decl_fmt.setFontWeight(QtGui.QFont.Bold)
        self.highlightRules.extend(
            [(QRegularExpression(r'(?<=def\s)\w+(?=\()'), func_decl_fmt)]
        )

        string_fmt = QtGui.QTextCharFormat()
        string_fmt.setForeground(Qt.cyan)
        # string_fmt.setFontWeight(QtGui.QFont.Bold)
        self.highlightRules.extend(
            [(QRegularExpression(r'(?<=\").*(?=\")'), string_fmt)]
        )

        # urls 
        url_fmt = QtGui.QTextCharFormat()
        url_fmt.setForeground(Qt.green)
        # url_fmt.setFontWeight(QtGui.QFont.Medium)
        url_fmt.setFontUnderline(True)
        url_fmt.setUnderlineColor(Qt.cyan)
        self.highlightRules.extend(
            [(QRegularExpression("http:\/\/.*\/|https:\/\/.*\/"), url_fmt)]
        )

        # imports_fmt
        imports_fmt = QtGui.QTextCharFormat()
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


class RightDock:
    def __init__(self, MainWindow: QtWidgets.QMainWindow, projectsDir) -> None:
        self.projectsDirPath = projectsDir
        self.MainWindow = MainWindow
        self.rightDockNotePadOpenfile = ""
        self.openEditors = []

    def InitializeDock(self):
        # right dock
        self.RightDock = QtWidgets.QDockWidget("Take Your Notes, Edit Files")
        self.rightDockWidget = QtWidgets.QWidget()
        self.RightDock.setWidget(self.rightDockWidget)

        self.rightDockLayoutMain = QtWidgets.QVBoxLayout()
        self.rightDockWidget.setLayout(self.rightDockLayoutMain)

        self.rightDockUpperWidget = QtWidgets.QWidget()

        self.AddMainMenu()
        self.AddSettingsMenu()

        self.rightDockUpperLayout = QtWidgets.QHBoxLayout()
        self.rightDockUpperLayout.addWidget(self.rightDockMenuButton)
        self.rightDockUpperLayout.addWidget(self.rightDockSettingsButton)
        self.rightDockUpperWidget.setLayout(self.rightDockUpperLayout)
        self.rightDockLayoutMain.addWidget(self.rightDockUpperWidget)

        self.rightDockBottomLayout = QtWidgets.QGridLayout()
        self.rightDockLayoutMain.addLayout(self.rightDockBottomLayout)
        # tabManager for opening multiple files in different tabs
        self.tabManager = QtWidgets.QTabWidget()
        self.rightDockBottomLayout.addWidget(self.tabManager, 1, 0)
        # self.defaultEditor = self.addEditor()
        # self.tabManager.addTab(self.addEditor(), "Editor")
        self.tabManager.currentChanged.connect(self.updateCurretNotepad)

        self.rightDockArea = QtCore.Qt.DockWidgetArea()
        self.MainWindow.addDockWidget(
            self.rightDockArea.RightDockWidgetArea, self.RightDock
        )
        return self.RightDock

    def updateCurretNotepad(self):
        if self.tabManager.currentWidget() is not None:
            self.rightDockNotePadOpenfile = self.tabManager.currentWidget().objectName()

    def addEditor(self):
        # notepad
        self.rightDockNotePad = TextEditor()
        # set the highlighter
        self.highlighter = SyntaxHighlighter(self.rightDockNotePad.document())
        return self.rightDockNotePad

    def increaseFont(self):
        Font = self.rightDockNotePad.font()

        # get the factor of increment
        # make a simple widget, add to it a lineEdit and an ok button
        def setFontSize():
            try:
                fontincreament = int(self.rightDockFontWidgetLineEdit.text())
                Font.setPointSize(Font.pointSize() + fontincreament)
                self.rightDockNotePad.setFont(Font)
                self.rightDockFontWidget.close()
            except ValueError:
                self.rightDockFontWidgetLineEdit.setStyleSheet(
                    "QLineEdit{border: 2px solid red;}"
                )

        self.rightDockFontWidget = QtWidgets.QWidget()
        self.rightDockFontWidgetLayout = QtWidgets.QHBoxLayout()
        self.rightDockFontWidgetLineEdit = QtWidgets.QLineEdit()
        self.rightDockFontWidgetOkButton = QtWidgets.QPushButton("Ok")
        self.rightDockFontWidgetOkButton.clicked.connect(setFontSize)
        self.rightDockFontWidgetLayout.addWidget(self.rightDockFontWidgetOkButton)
        self.rightDockFontWidgetLayout.addWidget(self.rightDockFontWidgetLineEdit)
        self.rightDockFontWidget.setWindowTitle("increase font")
        self.rightDockFontWidget.setLayout(self.rightDockFontWidgetLayout)
        self.rightDockFontWidget.show()

    def AddSettingsMenu(self):
        rightDockSettingsButtonIcon = QtGui.QIcon.fromTheme("preferences-system")
        # settngs menu
        self.rightDockSettingsMenu = QtWidgets.QMenu()
        rightNotepadTheme = self.rightDockSettingsMenu.addAction("theme")
        self.rightDockNotepadFont = self.rightDockSettingsMenu.addAction("font")
        self.rightDockNotepadFont.triggered.connect(self.increaseFont)
        # settings button
        self.rightDockSettingsButton = QtWidgets.QPushButton()
        self.rightDockSettingsButton.setFixedWidth(28)
        self.rightDockSettingsButton.setIcon(rightDockSettingsButtonIcon)
        self.rightDockSettingsButton.clicked.connect(self.ShowSettings)

    def AddMainMenu(self):
        def rightDockTextBroserOpenFile():
            rightDockFileDialog = QtWidgets.QFileDialog()
            rightDockNotePadOpenfile = rightDockFileDialog.getOpenFileName(
                None, "Open File", "/", "All Files (*.*)"
            )[0]
            with open(rightDockNotePadOpenfile, "r") as file:
                text = file.read()
                file.close()
            rightDockNotePad = self.addEditor()
            rightDockNotePad.setAcceptRichText(True)
            rightDockNotePad.setText(text)
            rightDockNotePad.setObjectName(rightDockNotePadOpenfile)
            self.tabManager.addTab(rightDockNotePad, rightDockNotePadOpenfile)
            self.openEditors.append(rightDockNotePad)
            # set the currently opened file to the self
            self.rightDockNotePadOpenfile = rightDockNotePadOpenfile

        def rightDockTextBroserSaveFile():
            if self.rightDockNotePadOpenfile != None:
                saveMessageBox = QtWidgets.QMessageBox()
                saveMessageBox.setWindowTitle("Information")
                saveMessageBox.setText(f"Do you want to save {self.rightDockNotePadOpenfile}")
                saveMessageBox.setIcon(QtWidgets.QMessageBox.Information)
                saveMessageBox.setStandardButtons(QtWidgets.QMessageBox.Ok)
                edited_text = self.tabManager.currentWidget().toPlainText()
                ret = saveMessageBox.exec()
                if ret == QtWidgets.QMessageBox.Ok:
                    with open(self.tabManager.currentWidget().objectName(), "w") as file:
                        file.write(edited_text)
                return ret

        def rightDockTextBroserCloseFile():
            if self.rightDockNotePadOpenfile is not None:
                if rightDockTextBroserSaveFile() == QtWidgets.QMessageBox.Ok:
                    self.rightDockNotePadOpenfile = None
                    self.tabManager.currentWidget().clear()
                    self.tabManager.removeTab(self.tabManager.currentIndex())
                    # edit the current open file pointed to by self
                    if self.tabManager.currentWidget() is not None:
                        self.rightDockNotePadOpenfile = self.tabManager.currentWidget().objectName()
            else:
                infoMessageBox = QtWidgets.QMessageBox()
                infoMessageBox.setWindowTitle("Information")
                infoMessageBox.setText("No open file")
                infoMessageBox.setIcon(QtWidgets.QMessageBox.Information)
                infoMessageBox.setStandardButtons(QtWidgets.QMessageBox.Ok)
                ret = infoMessageBox.exec()
                if ret == QtWidgets.QMessageBox.Ok:
                    pass

        rightDockMenuButtonIcon = QtGui.QIcon.fromTheme("view-list")
        # right dock menu
        self.rightDockMenu = QtWidgets.QMenu()
        self.rightDockOpenNotesFileAction = self.rightDockMenu.addAction(
            "Open Notes File"
        )
        self.rightDockOpenNotesFileAction.triggered.connect(self.rightDockOpenNotesFile)
        self.rightDockOpenFileAction = self.rightDockMenu.addAction("Open File")
        self.rightDockOpenFileAction.triggered.connect(rightDockTextBroserOpenFile)
        self.rightDockOpenSaveAction = self.rightDockMenu.addAction("Save File")
        self.rightDockOpenSaveAction.triggered.connect(rightDockTextBroserSaveFile)
        self.rightDockCloseAction = self.rightDockMenu.addAction("Close file")
        self.rightDockCloseAction.triggered.connect(rightDockTextBroserCloseFile)
        # menu button
        self.rightDockMenuButton = QtWidgets.QPushButton()
        self.rightDockMenuButton.setFixedWidth(28)
        self.rightDockMenuButton.setIcon(rightDockMenuButtonIcon)
        self.rightDockMenuButton.clicked.connect(self.RightDockShowMenu)

    def rightDockOpenNotesFile(self):
        # make a file named target_notes if it does not exists
        self.notesFile = "target_notes"
        self.notesfilepath = os.path.join(self.projectsDirPath, self.notesFile)
        if not Path(self.notesfilepath).exists():
            with open(self.notesfilepath, "a") as file:
                file.close()
        self.rightDockNotePadOpenfile = self.notesfilepath

        filecontents = open(self.notesfilepath, "r").read()
        rightDockNotePad = self.addEditor()
        rightDockNotePad.setAcceptRichText(True)
        rightDockNotePad.setText(filecontents)
        rightDockNotePad.setObjectName(self.notesFile)
        self.tabManager.addTab(rightDockNotePad, self.notesFile)
        self.openEditors.append(rightDockNotePad)
        # set the currently opened file to the self
        self.rightDockNotePadOpenfile = self.notesFile
        # self.rightDockNotePad.setText(filecontents)

    # @classmethod
    def ShowSettings(self):
        self.rightDockSettingsButton.setMenu(self.rightDockSettingsMenu)

    # @classmethod
    def RightDockShowMenu(self):
        self.rightDockMenuButton.setMenu(self.rightDockMenu)


class LowerDock:

    def __init__(self, MainWindow: QtWidgets.QMainWindow, projectDirPath) -> None:
        self.main_window = MainWindow
        self.projectDirPath = projectDirPath

    def InitializeLowerDock(self):
        # lower dock
        self.lowerDock = QtWidgets.QDockWidget("Terminal")
        self.lowerDockWidget = QtWidgets.QWidget()
        self.lowerDockArea = QtCore.Qt.DockWidgetArea()
        self.main_window.addDockWidget(
            self.lowerDockArea.BottomDockWidgetArea, self.lowerDock
        )
        # layout
        self.lowerDockLayout = QtWidgets.QVBoxLayout()
        # self.lowerDock.setMaximumHeight(200)
        # text edit terminal
        self.terminalTextEdit = Qterminal()
        self.lowerDockLayout.addWidget(self.terminalTextEdit)
        self.lowerDockWidget.setLayout(self.lowerDockLayout)
        self.lowerDock.setWidget(self.lowerDockWidget)

        return self.lowerDock


class LeftDock(QtCore.QObject):
    openLinkInBrw = Signal(str)

    def __init__(self, mainWindow: QtWidgets.QMainWindow,
                 projectDirPath,
                 parent  = None,
                 top_parent = None,
                 ) -> None:
        super().__init__()
        self.topParent = top_parent
        self.urlGetterRunning  = False
        self.main_window = mainWindow
        self.projectDirPath = projectDirPath
        self.SubdomainUrlDict = {}
        self.SubdomainUrlDict_file = os.path.join(self.projectDirPath, "subdomainsUrlDict.json")
        self.parent = parent
        self.topParent.socketIpc.processFinishedExecution.connect(self.updateModel)

    def InitializeLeftDock(self):

        def showSbdUrlTree():
            toolNames = ["amass", "sublist3r", "subdomainizer"]
            subdomains = ""
            for tN in toolNames:
                SubdomainResults = atomGuiGetSubdomains(self.projectDirPath, tN)
                if SubdomainResults[0] == False:
                    self.toolNotYetRunAlert = QtWidgets.QMessageBox()
                    self.toolNotYetRunAlert.setWindowTitle("Information")
                    self.toolNotYetRunAlert.setText(
                        f"{tN} has not yet been run on the target,\nDo you want to run {tN}"
                    )
                    self.toolNotYetRunAlert.setIcon(QtWidgets.QMessageBox.Information)
                    self.toolNotYetRunAlert.setStandardButtons(QtWidgets.QMessageBox.Ok)
                    ret = self.toolNotYetRunAlert.exec()
                else:
                    subdomains = subdomains + SubdomainResults[1] + "\n"
                    len_subdomains = SubdomainResults[2]
                    if tN == "amass":
                        self.amassSdCountLabel.setText(str(len_subdomains))
                    elif tN == "subdomainizer":
                        self.subdomainizerSdCountLabel.setText(str(len_subdomains))
                    elif tN == "sublist3r":
                        self.sublist3rSdCountLabel.setText(str(len_subdomains))

            tempFilePath = os.path.join(self.projectDirPath, "subdomainTempFile.txt")
            if Path(tempFilePath).exists():
                os.remove(tempFilePath)
            with open(tempFilePath, "a") as file:
                file.write(subdomains)
            rm_same(tempFilePath)

            with open(tempFilePath, "r") as f:
                list_sd = f.readlines()
                len_subdomains = len(list_sd)
                sdStr = ""
                for sd in list_sd:
                    self.SubdomainUrlDict[sd.replace("\n", "")] = []
                    sdStr += sd
            self.subdomainsModel.clear()
            if len_subdomains != 0:
                for subdomain, urls in self.SubdomainUrlDict.items():
                    parentItem = QStandardItem(subdomain)
                    self.subdomainsModel.appendRow(parentItem)
                    for url in urls:
                        url = url.replace("\n", "")
                        url_item = QStandardItem(url)
                        parentItem.appendRow(url_item)
            else:
                self.noSubdomainsAlert = QtWidgets.QMessageBox()
                self.noSubdomainsAlert.setWindowTitle("Information")
                self.noSubdomainsAlert.setText(
                    "It seems no domain finding tool has been run on the target"
                )
                self.noSubdomainsAlert.setIcon(QtWidgets.QMessageBox.Information)
                self.noSubdomainsAlert.setStandardButtons(QtWidgets.QMessageBox.Ok)
                ret = self.noSubdomainsAlert.exec()
                if ret == QtWidgets.QMessageBox.Ok:
                    pass
            
        # lower dock
        self.leftDock = QtWidgets.QDockWidget("Target Information")
        self.leftDockWidget = QtWidgets.QWidget()
        self.leftDock.setWidget(self.leftDockWidget)
        self.leftDockArea = QtCore.Qt.DockWidgetArea()
        self.main_window.addDockWidget(
            self.leftDockArea.LeftDockWidgetArea, self.leftDock
        )
        # layout
        self.leftDockLayout = QtWidgets.QVBoxLayout()
        self.leftDockWidget.setLayout(self.leftDockLayout)
        # hide or show gen info
        self.infoshowLayout = QtWidgets.QFormLayout()
        self.infoShowCheckBox = QtWidgets.QCheckBox()
        self.infoShowCheckBox.setChecked(True)
        self.infoShowCheckBox.stateChanged.connect(self.hideGenInfo)
        self.infoshowLayout.addRow("hide info", self.infoShowCheckBox)
        self.leftDockLayout.addLayout(self.infoshowLayout)
        # general information layout
        self.generalInformationLayout = QtWidgets.QFormLayout()
        self.generalInformationFrame = QtWidgets.QFrame()
        self.generalInformationFrame.setLayout(self.generalInformationLayout)
        self.generalInformationFrame.setHidden(True)
        self.leftDockLayout.addWidget(self.generalInformationFrame)
        # rows (static information)
        self.urlTargetName = QtWidgets.QLabel("URL: ")
        self.urlName = QtWidgets.QLabel("put here targe name")
        self.generalInformationLayout.addRow(self.urlTargetName, self.urlName)
        self.numberOfSubdomains = QtWidgets.QLabel("nSubdomains")
        self.nSubd = QtWidgets.QLabel("0")
        self.amassSdCount = QtWidgets.QLabel(" =>Amass:")
        self.amassSdCountLabel = QtWidgets.QLabel("0")
        self.subdomainizerSdCount = QtWidgets.QLabel(" =>subdomainizer:")
        self.subdomainizerSdCountLabel = QtWidgets.QLabel("0")
        self.sublist3rSdCount = QtWidgets.QLabel(" =>sublist3r:")
        self.sublist3rSdCountLabel = QtWidgets.QLabel("0")
        self.generalInformationLayout.addRow(self.numberOfSubdomains, self.nSubd)
        self.numberOfUrls = QtWidgets.QLabel("nUrls")
        self.nUrls = QtWidgets.QLabel("0")
        self.generalInformationLayout.addRow(self.amassSdCount, self.amassSdCountLabel)
        self.generalInformationLayout.addRow(
            self.subdomainizerSdCount, self.subdomainizerSdCountLabel
        )
        self.generalInformationLayout.addRow(
            self.sublist3rSdCount, self.sublist3rSdCountLabel
        )
        self.generalInformationLayout.addRow(self.numberOfUrls, self.nUrls)
        # dynamic information
        self.USlayout = QtWidgets.QHBoxLayout()
        self.leftDockLayout.addLayout(self.USlayout)
        # show subdomains button
        self.subdomainsButton = QtWidgets.QPushButton("SubdUrlTree")
        self.subdomainsButton.clicked.connect(showSbdUrlTree)
        self.USlayout.addWidget(self.subdomainsButton)
        # show urls Button
        self.urlsButton = QtWidgets.QPushButton("UrlsScan")
        self.urlsButton.clicked.connect(self.UrlsScan)
        self.USlayout.addWidget(self.urlsButton)

        # subdomains : urls tree
        self.subdomainsModel = QStandardItemModel()
        # ? is it possible to update just part of the model without resetting it
        # self.subdomainsModel.dataChanged.connect(self.updateSubdomainsModel)
        self.subdomainsModel.setHorizontalHeaderLabels(["Subdomain:UrlsMapping"])
        self.subdomainsTreeView = QtWidgets.QTreeView()
        self.subdomainsTreeView.setModel(self.subdomainsModel)
        self.subdomainsTreeView.doubleClicked.connect(self.openLinkInBrowser)
        self.subdomainsTreeView.setAlternatingRowColors(True)
        self.subdomainsTreeView.setAnimated(True)
        self.subdomainsTreeView.setUniformRowHeights(True)
        self.subdomainsTreeView.setEditTriggers(QtWidgets.QTreeView.NoEditTriggers)
        self.leftDockLayout.addWidget(self.subdomainsTreeView)
        return self.leftDock


    def hideGenInfo(self):
        if self.infoShowCheckBox.isChecked():
            self.generalInformationFrame.setHidden(True)
        else:
            self.generalInformationFrame.setHidden(False)

    @QtCore.Slot()
    def UrlsScan(self):
        if Path(self.SubdomainUrlDict_file).exists():
            with open(self.SubdomainUrlDict_file, "r") as f:
                jsonData = f.read()
            self.SubdomainUrlDict = json.loads(jsonData)
            self.subdomainsModel.dataChanged.emit(QtCore.QModelIndex(), QtCore.QModelIndex())
            self.updateModel()
        else:
            if self.urlGetterRunning is False:
                self.urlGetterRunning = True
                self.url_getter = UrlGetter(self.SubdomainUrlDict,
                                            self.projectDirPath,
                                            parent = self.parent,
                                            dict_parent=self,
                                            top_parent = self.topParent,
                                            mainWindow=self.main_window)
                self.url_getter.urlGetterFinished.connect(self.updateModel)
                self.url_getter.start()
            else:
                UrlGetterMessageBox = MessageBox("Information",
                                                 "There is a thread of urlGetter still running\nCannont open another thread",
                                                 "Information")
                UrlGetterMessageBox.setStandardButtons(QtWidgets.QMessageBox.Ok)
                ret = UrlGetterMessageBox.exec()
                if ret == QtWidgets.QMessageBox.Ok:
                    pass

    def updateModel(self, **args):
        self.subdomainsModel.clear()
        self.subdomainsModel.setHorizontalHeaderLabels(["Subdomain:UrlsMapping"])
        for subdomain, urls in self.SubdomainUrlDict.items():
            parentItem = QStandardItem(subdomain)
            self.subdomainsModel.appendRow(parentItem)
            for url in urls:
                url_item = QStandardItem(url)
                parentItem.appendRow(url_item)

    @QtCore.Slot(int)
    def openLinkInBrowser(self, index: QtCore.QModelIndex):
        clicked_link = self.subdomainsModel.itemFromIndex(index).text()
        self.openLinkInBrw.emit(clicked_link)

class customWebEnginePage(QWebEnginePage):
    def certificateError(self, error):
        error.ignoreCertificateError()
        return True

class BrowserWindow(QtWidgets.QMainWindow):
    def __init__(self, link=None) -> None:
        super().__init__()
        self.ca_certs_file = rundir+"src/proxycert/CA/certificate.crt"

        self.init_link = link

        centralWidget = QtWidgets.QWidget()
        self.setCentralWidget(centralWidget)

        self.centralWidgetLayout = QtWidgets.QVBoxLayout()
        centralWidget.setLayout(self.centralWidgetLayout)

        self.browser = QtWebEngineWidgets.QWebEngineView()
        # self.customPage = customWebEnginePage()
        # self.browser.setPage(self.customPage)

        self.browserSettings = self.browser.settings()
        try:
            # self.browserSettings.setAttribute(QWebEngineSettings.WebAttribute.ErrorPageEnabled, False)
            self.browserSettings.setAttribute(QWebEngineSettings.WebAttribute.ForceDarkMode, True)
            # self.browserSettings.setAttribute(QWebEngineSettings.WebAttribute.SslErrorOverrideEnabled, True)
        except AttributeError as e:
            logging.error(f"Some of the attributes were not set. Encoutered error when setting attribute: {e}")
        self.browser.urlChanged.connect(self.handleUrlChange)
        self.browser.loadProgress.connect(self.handleLoadProgress)
        self.browser.loadFinished.connect(self.closeProgressBarWidget)

        self.upperUrlHandlerLayout = QtWidgets.QHBoxLayout()
        self.centralWidgetLayout.addLayout(self.upperUrlHandlerLayout)

        self.lowerCentralLayout = QtWidgets.QHBoxLayout()
        self.centralWidgetLayout.addLayout(self.lowerCentralLayout)
        self.AddUrlHandler()

        self.lowerCentralLayout.addWidget(self.browser)
        # self.browser.createStandardContextMenu()
        if self.init_link is None:
            self.browser.setUrl(QtCore.QUrl("http://google.com/"))
        else:
            # print(f"clicked link is {self.init_link}")
            self.searchUrlOnBrowser(self.init_link)

    def setupProfile(self):
        with open(self.ca_certs_file, "r") as cert_file:
            cert = cert_file.read()
        self.profile = QWebEngineProfile.defaultProfile()
        self.profile.httpCacheType(QWebEngineProfile.MemoryHttpCache)
        self.profile.setPersistentCookiesPolicy(QWebEngineProfile.NoPersistentCookies)
        self.profile.setCaCertficates()

    def closeProgressBarWidget(self):
        self.browserProgressBar.setVisible(False)

    @QtCore.Slot(int)
    def handleLoadProgress(self, prog):
        self.browserProgressBar.setVisible(True)
        self.browserProgressBar.setMinimum(0)
        self.browserProgressBar.setMaximum(100)
        self.browserProgressBar.setValue(prog)

    def handleUrlChange(self):
        _Qurl = self.browser.url()
        str_Url = _Qurl.url()
        self.urlText.setText(str_Url)

    def AddUrlHandler(self):
        self.urlLabel = QtWidgets.QLabel()
        self.urlLabel.setText("Url:")
        self.urlText = QtWidgets.QLineEdit()
        self.searchButton = QtWidgets.QPushButton()
        self.searchButton.setText("search")
        self.clearButton = HoverButton("X", "clear the search area")
        self.clearButton.setFixedWidth(32)
        self.clearButton.clicked.connect(self.urlTextClear)
        self.searchButton.clicked.connect(self.searchUrlOnBrowser)
        self.browserProgressBar = QtWidgets.QProgressBar()
        self.browserProgressBar.setVisible(False)
        self.browserProgressBar.setFormat("Loading")
        self.upperUrlHandlerLayout.addWidget(self.urlLabel)
        self.upperUrlHandlerLayout.addWidget(self.urlText)
        self.upperUrlHandlerLayout.addWidget(self.searchButton)
        self.upperUrlHandlerLayout.addWidget(self.clearButton)
        self.upperUrlHandlerLayout.addWidget(self.browserProgressBar)

    def urlTextClear(self):
        self.urlText.clear()

    def searchUrlOnBrowser(self, link=None):
        if type(link) == bool:
            link = "google.com"
        if link is not None:
            self.target_url = link
        else:
            self.target_url = self.urlText.text()
        self.target_url = addHttpsScheme(self.target_url)
        logging.info(f"using url : {self.target_url}")
        self.browser.setUrl(QtCore.QUrl(self.target_url))
        self.QbrowserURL = self.browser.url()
        self.strUrl = self.QbrowserURL.url()
        self.urlText.setText(self.strUrl)


class NetworkWindow(QtWidgets.QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        # self.IniatializeNetworkWindow()

    def IniatializeNetworkWindow(self):
        self.NetworkWindow_ = QtWidgets.QWidget()
        self.setCentralWidget(self.NetworkWindow_)
        self.setWindowTitle("Network")
        self.NetworkWindowLayoutMain = QtWidgets.QVBoxLayout()
        # network dock
        self.NetworkMapDock = QtWidgets.QDockWidget()
        self.NetworkMapDockArea = QtCore.Qt.DockWidgetArea()
        self.addDockWidget(
            self.NetworkMapDockArea.RightDockWidgetArea, self.NetworkMapDock
        )

        self.test_button = QtWidgets.QPushButton()
        self.test_button.setText("button")

        self.NetworkMapDockWidget = QtWidgets.QWidget(self.NetworkMapDock)
        self.NetworkDockLayout = QtWidgets.QVBoxLayout()
        self.NetworkMapDockWidget.setLayout(self.NetworkDockLayout)

        self.NetworkDockLayout.addWidget(self.test_button)
        self.NetworkWindow_.setLayout(self.NetworkWindowLayoutMain)

        return self.NetworkWindow_


class NetworkMap(QtWidgets.QWidget):
    def __init__(self) -> None:
        super().__init__()

    def InitializeNetworkMapWidget(self):
        self.NetworkMapWidget = QtWidgets.QWidget()

class SubdomainizerThreadRunner(QThread):
    def __init__(self, subDomainizerUrlTarget, projectDirPath):
        super().__init__()
        self.setObjectName("SubdomainizerThreadRunner")
        self.subDomainizerUrlTarget = subDomainizerUrlTarget
        self.projectDirPath = projectDirPath

    def subdomainizerRun(self):
        self.subDomainizerRunner = SubDomainizerRunner(
            self.subDomainizerUrlTarget, self.projectDirPath
        )
        self.subDomainizerRunner.Run()

    def run(self) -> None:
        self.subdomainizerRun()
        print(yellow("Subdomaizer finished running"))


class Sublist3rThreadRunner(QThread):
    def __init__(
            self,
            domain,
            projectDirPath,
            bruteforce: bool = None,
            searchengines: list = None,
            threads: int = None,
            ports: list = None,
    ):
        super().__init__()
        self.setObjectName("Sublist3rThreadRunner")
        self.domain = domain
        self.projectDirPath = projectDirPath
        self.bruteforce = bruteforce
        self.searchengines = searchengines
        self.threads = threads
        self.ports = ports

    def sublist3rRun(self):
        self.sublisterRunner = SublisterRunner(
            self.domain,
            self.projectDirPath,
            bruteforce=self.bruteforce,
            search_engines=self.searchengines,
            threads=self.threads,
            ports=self.ports,
        )
        self.sublisterRunner.RunOnDomain()

    def run(self) -> None:
        self.sublist3rRun()
        print(yellow("Sublister finished running"))


class AmassThreadRunner(QThread):
    def __init__(self, amassUrlTarget, projectDirPath):
        super().__init__()
        self.setObjectName("AmassThreadRunner")
        self.amassUrlTarget = amassUrlTarget
        self.projectDirPath = projectDirPath

    def amassRun(self):
        amassProcessor = AmassSubdProcessor(
            domain=self.amassUrlTarget, workingDir=self.projectDirPath
        )
        amassProcessor.Run()

    def run(self) -> None:
        self.amassRun()
        # return super().run()


class TestTargetWindow(QtWidgets.QMainWindow):
    def __init__(self, projectDirPath, parent) -> None:
        super().__init__()
        self.parent = parent
        self.useHttp = False
        self.useBrowser = False
        self.runAmass = False
        self.subliterBruteForce = False
        self.sublisterScanPorts = False
        self.sublisterUseSearchEngines = False
        self.projectDirPath = projectDirPath

    def Initialize(self):
        def runSublist3r():
            # configure search engines
            self.searchEngines = []
            searchEngine_string = self.sublist3rSearchEngines.text().strip()
            if not self.sublisterUseSearchEngines:
                self.searchEngines = None
            else:
                if searchEngine_string.endswith(","):
                    searchEngine_string = searchEngine_string[:-1]
                self.searchEngines = searchEngine_string.split(",")

            # configure ports
            self.sublisterPorts = []
            Port_string = self.sublist3rPorts.text().strip()
            if not self.sublisterScanPorts:
                Ports = None
            else:
                if Port_string.endswith(","):
                    Port_string = Port_string[:-1]
                Ports = Port_string.split(",")

                for port in Ports:
                    try:
                        int(port.strip())
                    except:
                        self.sublist3rPorts.setStyleSheet(
                            "QLineEdit{border: 2px Solid red; }"
                        )
                        Ports = None
            # configure threads
            try:
                sublisterThreads = int(self.sublist3rThreads.text())
            except:
                sublisterThreads = None
                self.sublist3rThreads.setStyleSheet(
                    "QLineEdit({border: 2px Solid red;})"
                )

            try:
                self.sublist3rRunner = Sublist3rThreadRunner(
                    self.sublist3rUrlTarget.text(),
                    self.projectDirPath,
                    self.subliterBruteForce,
                    self.searchEngines,
                    sublisterThreads,
                    Ports,
                )
                self.sublist3rRunner.setObjectName("sublist3rRunner")
                self.parent.threads.append(self.sublist3rRunner)
                self.sublist3rRunner.start()
            except:
                self.sublisterFailRunMessageBox = QtWidgets.QMessageBox()
                self.sublisterFailRunMessageBox.setWindowTitle("Warning")
                self.sublisterFailRunMessageBox.setText(
                    "Sublister has a problem running!! \nThis can be due to invalid args \nor a faulty internet connection\nDo you want to run it again"
                )
                self.sublisterFailRunMessageBox.setIcon(QtWidgets.QMessageBox.Warning)
                self.sublisterFailRunMessageBox.setStandardButtons(
                    QtWidgets.QMessageBox.Ok
                )
                ret = self.sublisterFailRunMessageBox.exec()
                if ret == QtWidgets.QMessageBox.Ok:
                    pass

        def runsubDomainizer():
            self.subDomainizerRunner = SubdomainizerThreadRunner(
                self.subDomainizerUrlTarget.text(), self.projectDirPath
            )
            self.subDomainizerRunner.setObjectName("SubdomainizerRunner")
            self.parent.threads.append(self.subDomainizerRunner)
            self.subDomainizerRunner.start()

        def runAmass():
            self.amassRunner = AmassThreadRunner(
                self.amassUrlTarget.text(), self.projectDirPath
            )
            self.amassRunner.setObjectName("AmassRunner")
            self.parent.threads.append(self.amassRunner)
            self.amassRunner.start()
            # amassRunner.run()

        self.centralWidget = QtWidgets.QWidget()
        self.setCentralWidget(self.centralWidget)

        self.centralWidgetLayout = QtWidgets.QVBoxLayout()
        self.centralWidget.setLayout(self.centralWidgetLayout)
        # tab manager
        self.tabManager = QtWidgets.QTabWidget()
        # atom tab
        self.atomRunner = QtWidgets.QWidget()
        self.atomRunnerLayout = QtWidgets.QVBoxLayout()
        self.atomRunner.setLayout(self.atomRunnerLayout)
        # options layout
        self.atomRunnerOptionsLayout = QtWidgets.QFormLayout()
        self.atomUrlTarget = QtWidgets.QLineEdit()
        self.atomUrlLabel = QtWidgets.QLabel("Target url: ")
        self.atomUseHttp = QtWidgets.QLabel("Use Http: ")
        self.atomUseHttpCheckBox = QtWidgets.QCheckBox()
        self.atomUseHttpCheckBox.stateChanged.connect(self.registerUseHttp)
        self.atomUseBrowser = QtWidgets.QLabel("Use Browser: ")
        self.atomUseBrowserCheckBox = QtWidgets.QCheckBox()
        self.atomUseBrowserCheckBox.stateChanged.connect(self.registerUseBrowser)
        self.atomRunAmass = QtWidgets.QLabel("Run Amass")
        self.atomRunAmassCheckBox = QtWidgets.QCheckBox()
        self.atomRunAmassCheckBox.stateChanged.connect(self.registerRunAmass)
        # add options to options layout
        self.atomRunnerOptionsLayout.addRow(self.atomUrlLabel, self.atomUrlTarget)
        self.atomRunnerOptionsLayout.addRow(
            self.atomUseBrowser, self.atomUseBrowserCheckBox
        )
        self.atomRunnerOptionsLayout.addRow(self.atomUseHttp, self.atomUseHttpCheckBox)
        self.atomRunnerOptionsLayout.addRow(
            self.atomRunAmass, self.atomRunAmassCheckBox
        )
        # add form layout to vbox layout
        self.atomRunnerLayout.addLayout(self.atomRunnerOptionsLayout)
        # run Button
        self.atomRunButton = QtWidgets.QPushButton()
        self.atomRunButton.setText("Run Atom")
        self.atomRunButton.clicked.connect(self.runAtom)
        self.atomRunnerLayout.addWidget(self.atomRunButton)
        # add tab atom runner to testing window
        self.tabManager.addTab(self.atomRunner, "Atom Runner")

        # amass tab
        self.amassRunner = QtWidgets.QWidget()
        self.amassRunnerLayout = QtWidgets.QVBoxLayout()
        self.amassRunner.setLayout(self.amassRunnerLayout)
        # # options layout
        self.amassRunnerOptionsLayout = QtWidgets.QFormLayout()
        self.amassUrlTarget = QtWidgets.QLineEdit()
        self.amassUrlLabel = QtWidgets.QLabel("Target domain: ")
        # add options to options layout
        self.amassRunnerOptionsLayout.addRow(self.amassUrlLabel, self.amassUrlTarget)
        # add form layout to vbox layout
        self.amassRunnerLayout.addLayout(self.amassRunnerOptionsLayout)
        # run Button
        self.amassRunButton = QtWidgets.QPushButton()
        self.amassRunButton.setText("Run Amass")
        self.amassRunButton.clicked.connect(runAmass)
        self.amassRunnerLayout.addWidget(self.amassRunButton)

        self.tabManager.addTab(self.amassRunner, "Amass Runner")

        # SubDomainizerRunner
        self.subDomainizerRunner = QtWidgets.QWidget()
        self.subDomainizerRunnerLayout = QtWidgets.QVBoxLayout()
        self.subDomainizerRunner.setLayout(self.subDomainizerRunnerLayout)
        # # options layout
        self.subDomainizerRunnerOptionsLayout = QtWidgets.QFormLayout()
        self.subDomainizerUrlTarget = QtWidgets.QLineEdit()
        self.subDomainizerUrlLabel = QtWidgets.QLabel("Target domain: ")
        # add options to options layout
        self.subDomainizerRunnerOptionsLayout.addRow(
            self.subDomainizerUrlLabel, self.subDomainizerUrlTarget
        )
        # add form layout to vbox layout
        self.subDomainizerRunnerLayout.addLayout(self.subDomainizerRunnerOptionsLayout)
        # run Button
        self.subDomainizerRunButton = QtWidgets.QPushButton()
        self.subDomainizerRunButton.setText("Run subDomainizer")
        self.subDomainizerRunButton.clicked.connect(runsubDomainizer)
        self.subDomainizerRunnerLayout.addWidget(self.subDomainizerRunButton)

        self.tabManager.addTab(self.subDomainizerRunner, "subdomainizer")

        # SubDomainizerRunner
        self.sublist3rRunner = QtWidgets.QWidget()
        self.sublist3rRunnerLayout = QtWidgets.QVBoxLayout()
        self.sublist3rRunner.setLayout(self.sublist3rRunnerLayout)
        # # options layout
        self.sublist3rRunnerOptionsLayout = QtWidgets.QFormLayout()
        self.sublist3rUrlTarget = QtWidgets.QLineEdit()
        self.sublist3rUrlLabel = QtWidgets.QLabel("Target domain: ")
        self.sublist3rBruteForceLabel = QtWidgets.QLabel()
        self.sublist3rBruteForceLabel.setText("Allow BruteForce")
        self.sublist3rBruteforcebutton = QtWidgets.QCheckBox()
        self.sublist3rBruteforcebutton.stateChanged.connect(
            self.registerSubliterBruteforceButton
        )
        self.sublist3rUseSearchEngniesCheckBox = QtWidgets.QCheckBox()
        self.sublist3rUseSearchEngniesCheckBox.stateChanged.connect(
            self.registerSublisterUseSearchEngines
        )
        self.sublist3rUseSearchEnginesLabel = QtWidgets.QLabel()
        self.sublist3rUseSearchEnginesLabel.setText("Use SearchEngines:")
        self.sublist3rSearchEnginesLabel = QtWidgets.QLabel()
        self.sublist3rSearchEnginesLabel.setText("SearchEngines:")
        self.sublist3rSearchEngines = QtWidgets.QLineEdit()
        self.sublist3rSearchEngines.setHidden(True)
        self.sublist3rSearchEngines.setPlaceholderText(
            "write comma separated values of search engines"
        )
        self.sublist3rScanPortsLabel = QtWidgets.QLabel()
        self.sublist3rScanPortsLabel.setText("Scan Ports")
        self.sublist3rScanPortsCheckBox = QtWidgets.QCheckBox()
        self.sublist3rScanPortsCheckBox.stateChanged.connect(
            self.registerSublisterScanPorts
        )
        self.sublist3rPortsLabel = QtWidgets.QLabel()
        self.sublist3rPortsLabel.setText("Ports:")
        self.sublist3rPorts = QtWidgets.QLineEdit()
        self.sublist3rPorts.setPlaceholderText(
            "write command separated values of ports"
        )
        self.sublist3rPorts.setVisible(False)
        self.sublist3rThreadsLabel = QtWidgets.QLabel()
        self.sublist3rThreadsLabel.setText("Number of threads")
        self.sublist3rThreads = QtWidgets.QLineEdit()
        self.sublist3rThreads.setPlaceholderText("number of threads to be used (int)")

        # add options to options layout
        self.sublist3rRunnerOptionsLayout.addRow(
            self.sublist3rUrlLabel, self.sublist3rUrlTarget
        )
        self.sublist3rRunnerOptionsLayout.addRow(
            self.sublist3rBruteForceLabel, self.sublist3rBruteforcebutton
        )
        self.sublist3rRunnerOptionsLayout.addRow(
            self.sublist3rUseSearchEnginesLabel, self.sublist3rUseSearchEngniesCheckBox
        )
        self.sublist3rRunnerOptionsLayout.addRow(
            self.sublist3rSearchEnginesLabel, self.sublist3rSearchEngines
        )
        self.sublist3rRunnerOptionsLayout.addRow(
            self.sublist3rScanPortsLabel, self.sublist3rScanPortsCheckBox
        )
        self.sublist3rRunnerOptionsLayout.addRow(
            self.sublist3rPortsLabel, self.sublist3rPorts
        )
        self.sublist3rRunnerOptionsLayout.addRow(
            self.sublist3rThreadsLabel, self.sublist3rThreads
        )

        # add form layout to vbox layout
        self.sublist3rRunnerLayout.addLayout(self.sublist3rRunnerOptionsLayout)
        # run Button
        self.sublist3rRunButton = QtWidgets.QPushButton()
        self.sublist3rRunButton.setText("Run sublist3r")
        self.sublist3rRunButton.clicked.connect(runSublist3r)
        self.sublist3rRunnerLayout.addWidget(self.sublist3rRunButton)

        self.tabManager.addTab(self.sublist3rRunner, "sublist3r")
        # add tab manager to central widget layout
        self.centralWidgetLayout.addWidget(self.tabManager)

    def registerSublisterUseSearchEngines(self):
        if self.sublist3rUseSearchEngniesCheckBox.isChecked():
            self.sublist3rSearchEngines.setVisible(True)
            self.sublisterUseSearchEngines = True
        else:
            self.sublist3rSearchEngines.setVisible(False)
            self.sublisterUseSearchEngines = False

    def registerSublisterScanPorts(self):
        if self.sublist3rScanPortsCheckBox.isChecked():
            self.sublist3rPorts.setVisible(True)
            self.sublisterScanPorts = True
        else:
            self.sublist3rPorts.setVisible(False)
            self.sublisterScanPorts = False

    def registerRunAmass(self):
        if self.atomRunAmassCheckBox.isChecked():
            self.runAmass = True
        else:
            self.runAmass = False

    def registerSubliterBruteforceButton(self):
        if self.sublist3rBruteforcebutton.isChecked():
            self.subliterBruteForce = True
        else:
            self.subliterBruteForce = False

    def registerUseHttp(self):
        if self.atomUseHttpCheckBox.isChecked():
            self.useHttp = True
        else:
            self.useHttp = False

    def registerUseBrowser(self):
        if self.atomUseBrowserCheckBox.isChecked():
            self.useBrowser = True
        else:
            self.useBrowser = False

    def runatom(self):
        domain = self.atomUrlTarget.text()
        directory = domain
        usehttp = self.useHttp
        usebrowser = self.useBrowser
        with ProcessPoolExecutor(max_workers=4) as executor:
            executor.submit(
                asyncio.run(RunMainAtomFunction(domain, directory, usehttp, usebrowser))
            )

    def runAtom(self):
        with ThreadPoolExecutor(max_workers=1000) as executor:
            executor.submit(self.runatom)


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self, projectDirPath: str, proxy_port, topParent, index):
        super().__init__()
        self.projectIndex = index
        self.topParent = topParent
        self.rootCACertificate = None
        self.current_tab_index = None
        self.projectDirPath = projectDirPath
        self.threads = []
        self.setObjectName(self.projectDirPath)
        # Docks
        lowerDock = LowerDock(self, self.projectDirPath)
        self.LowerDock = lowerDock.InitializeLowerDock()
        self.LowerDock.setVisible(False)
        rightDock = RightDock(self, self.projectDirPath)
        self.RightDock = rightDock.InitializeDock()
        leftdock = LeftDock(self, self.projectDirPath, parent = self, top_parent = self.topParent)
        leftdock.openLinkInBrw.connect(self.openNewBrowserTab)
        self.LeftDock = leftdock.InitializeLeftDock()

        # central widget
        centralWidget = QtWidgets.QWidget()
        self.centralWidgetLayout = QtWidgets.QVBoxLayout()

        self.uppperCentralLayout = QtWidgets.QHBoxLayout()
        self.centralWidgetLayout.addLayout(self.uppperCentralLayout)
        self.AddTopMenu()

        self.browserTabWidget = QtWidgets.QTabWidget()
        self.centralWidgetLayout.addWidget(self.browserTabWidget)
        self.openNewBrowserTab()

        centralWidget.setLayout(self.centralWidgetLayout)
        self.setCentralWidget(centralWidget)

        # network button
        self.NetworkButtonIcon = QtGui.QIcon.fromTheme("network-wired")
        self.NetworkButton = QtWidgets.QPushButton()
        self.NetworkButton.setIcon(self.NetworkButtonIcon)
        self.NetworkButton.setFixedWidth(28)
        self.NetworkButton.clicked.connect(self.OpenNetworkWindow)
        self.uppperCentralLayout.addWidget(self.NetworkButton)

        # add new browser tab 
        self.newBrowserTabButton = HoverButton("+","add a new browser tab")
        self.newBrowserTabButton.clicked.connect(self.openNewBrowserTab)
        self.newBrowserTabButton.setFixedWidth(20)
        self.uppperCentralLayout.addWidget(self.newBrowserTabButton)

        # close Browser Tab
        self.closeTabButton = HoverButton("x", "close the curret tab")
        self.closeTabButton.setFixedWidth(20)
        self.closeTabButton.clicked.connect(self.closeBrowserTab)
        self.uppperCentralLayout.addWidget(self.closeTabButton)

        self.proxy_status = False

        # disable proxy tab
        self.HandleProxyButton = HoverButton("enable Proxy", "enable or disable the proxy")
        self.HandleProxyButton.setFixedWidth(140)
        self.HandleProxyButton.clicked.connect(self.HandleProxy)
        self.uppperCentralLayout.addWidget(self.HandleProxyButton)

        # test target button
        self.testTargetButton = QtWidgets.QPushButton()
        self.testTargetButton.setText("Test target")
        self.testTargetButton.setFixedWidth(140)
        self.testTargetButton.clicked.connect(self.OpenTestTargetWindow)
        self.uppperCentralLayout.addWidget(self.testTargetButton, alignment=Qt.AlignLeft)

        self.setWindowTitle("atom")

        self.centralWidgetLayout.addStretch()
        self.proxy_port  = proxy_port
        self.topParent.newProjectCreated.emit(self)

    def closeEvent(self, event: QtGui.QCloseEvent) -> None:
        self.topParent.projectClosed.emit(self, self.projectIndex)
        return super().closeEvent(event)

    def openNewBrowserTab(self, link: str = None):
        BrowserWindow_ = BrowserWindow(link=link)
        tab_name = "newT"
        try:
            if link is not None:
                if link.startswith(("https", "http")):
                    tab_name = link.split("//")[1].split(".")[0]
                else:
                    tab_name = link.split(".")[0]
        except:
            tab_name = "newT"
        self.browserTabWidget.addTab(BrowserWindow_, tab_name)
        self.browserTabWidget.setCurrentIndex(
            self.browserTabWidget.indexOf(BrowserWindow_)
        )

    def closeBrowserTab(self):
        self.current_tab_index = self.browserTabWidget.currentIndex()
        if self.current_tab_index != 0:
            self.browserTabWidget.removeTab(self.current_tab_index)

    def LoadCA_Certificate(self):
        self.rootCACertificate = QSslCertificate()
        self.rootCACertificateFile = rundir + "src/proxycert/CA/certificate.crt"
        # self.rootCACertificate.importPkcs12(self.rootCACertificateFile) this is a wrong approach

        self.sslConfig = QSslConfiguration.defaultConfiguration()
        self.sslConfig.addCaCertificate(self.rootCACertificate)

        QSslConfiguration.setDefaultConfiguration(self.sslConfig)

    def HandleProxy(self):
        if self.proxy_status is False:
            self.enableProxy(use_default=True)
            self.HandleProxyButton.setText("DisableProxy")
            self.proxy_status = True
        else:
            self.HandleProxyButton.setText("EnableProxy")
            self.proxy_status = False
            QNetworkProxyFactory.setUseSystemConfiguration(True)

    def enableProxy(self, use_default = False):
        if use_default:
            self.proxy_hostname = "127.0.0.1"
            self.proxy_port = self.proxy_port
            proxy = QNetworkProxy()
            proxy.setType(QNetworkProxy.HttpProxy)
            proxy.setHostName(self.proxy_hostname)
            proxy.setPort(self.proxy_port)
            self.LoadCA_Certificate()
            QNetworkProxy.setApplicationProxy(proxy)
        else:
            self.enableProxyCheckBox.setChecked(True)
            self.proxy_hostname = self.proxyHostNameLineEdit.text()
            if self.proxy_hostname == " ":
                self.proxy_hostname = "127.0.0.1"
            try:
                self.proxy_port = int(self.proxyPortNameLineEdit.text())
                if self.proxy_port == " ":
                    self.proxy_port = self.proxy_port
                proxy = QNetworkProxy()
                proxy.setType(QNetworkProxy.HttpProxy)
                proxy.setHostName(self.proxy_hostname)
                proxy.setPort(self.proxy_port)
                QNetworkProxy.setApplicationProxy(proxy)
                self.enableProxyCheckBox.setChecked(True)
                self.LoadCA_Certificate()
            except ValueError:
                self.proxyPortNameLineEdit.setStyleSheet("QLineEdit{border: 2px solid red;}")
                self.enableProxyCheckBox.setChecked(False)

    def OpenTestTargetWindow(self):
        self.testWindow = TestTargetWindow(self.projectDirPath, parent = self)
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
        self.centralWidgetMenu = QtWidgets.QMenu()
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
        # top menu Button
        self.MenuIcon = QtGui.QIcon(rundir + "resources/icons/settings-icon-gear-3d-render-png.png")
        self.menuButton = QtWidgets.QPushButton()
        self.menuButton.setIcon(self.MenuIcon)
        self.menuButton.setFixedWidth(28)
        self.menuButton.clicked.connect(self.ShowMenu)
        self.uppperCentralLayout.addWidget(self.menuButton)

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

    def ShowMenu(self):
        self.menuButton.setMenu(self.centralWidgetMenu)

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


class ProxyInterceptWindow(QtWidgets.QMainWindow):
    def __init__(self, projectDirPath):
        super().__init__()
        self.projectDirPath = projectDirPath

        self.MainWidget = QtWidgets.QWidget()
        self.setCentralWidget(self.MainWidget)


class ReqResTextEditor(TextEditor, QtCore.QObject):
    sendToRepeaterSignal = Signal(str)

    def __init__(self):
        super().__init__()

    def contextMenuEvent(self, event):
        menu = self.createStandardContextMenu()

        sendToRepeaterAction = QtGui.QAction("send to repeater", self)
        sendToRepeaterAction.triggered.connect(self.sendRequestToRepeater)
        menu.addAction(sendToRepeaterAction)

        menu.exec()

    def sendRequestToRepeater(self):
        # print(red("send to repeater signal has been emitted"))
        self.sendToRepeaterSignal.emit(self.toPlainText())


class RepeaterReqResTextEditor(TextEditor):
    def __init__(self):
        super().__init__()
        self.setBaseSize(650, 650)
        self.setMaximumWidth(750)


class SiteMapUpdater(QThread, QtCore.QObject):
    fileStructureChanged = Signal()

    def __init__(self, proxyDumpDir):
        super().__init__()
        self.proxyDumpDir = proxyDumpDir
        self.old_proxyDumpDirComponents = set()
        self.new_proxyDumpDirComponents = set()
        self.stateNotChanged = 0
        self.program_start_mins = int(time.asctime().split(":")[1])
        atexit.register(self.terminate)

    def checkDirChange(self):
        while True:
            self.program_go_mins = int(time.asctime().split(":")[1])
            self.spentMins = abs(self.program_go_mins - self.program_start_mins)
            self.new_proxyDumpDirComponents.clear()
            for _, dirs, files in os.walk(self.proxyDumpDir):
                [self.new_proxyDumpDirComponents.add(dir_) for dir_ in dirs]
                [self.new_proxyDumpDirComponents.add(file) for file in files]

            if not self.old_proxyDumpDirComponents == self.new_proxyDumpDirComponents:
                self.fileStructureChanged.emit()
                self.old_proxyDumpDirComponents = self.new_proxyDumpDirComponents.copy()  # set the old list to equal to the new list such that it becomes the new old
                self.stateNotChanged = 0
                self.program_start_mins = int(time.asctime().split(":")[1])
            else:
                if self.spentMins >= 2:
                    self.stateNotChanged += 1
                    if self.stateNotChanged == 10:
                        logging.info("File structure not Changed=> SiteMapUpdater Thread Sleeping...")
                        milliseconds = lambda x: (x*60)
                        self.sleep(milliseconds(3))
                        self.stateNotChanged = 0
                pass

    def run(self) -> None:
        self.checkDirChange()


class RepeaterWindow(QtWidgets.QMainWindow, QtCore.QObject):

    # tabChangeSignal  = Signal(int)
    def __init__(self, parent=None):
        super().__init__()
        self.parent = parent
        self.repeaterMainWidget = QtWidgets.QWidget()
        self.setCentralWidget(self.repeaterMainWidget)
        self.repeaterMainWidgetLayout = QtWidgets.QVBoxLayout()
        self.repeaterMainWidget.setLayout(self.repeaterMainWidgetLayout)

        self.repeaterSplitter = QtWidgets.QSplitter()
        self.repeaterMainWidgetLayout.addWidget(self.repeaterSplitter)

        self.repeaterTabManager = QtWidgets.QTabWidget()
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
        self.responseDir = rundir+"tmp/"
        if not Path(self.responseDir).is_dir():
            os.makedirs(self.responseDir)
        self.response_file = os.path.join(self.responseDir, "response.txt")
        if not Path(self.response_file).exists():
            with open(self.response_file, "w") as f:
                f.close()

    def addReqResInstanceTabManager(self, request: str = None):
        instanceRepeaterSplitter = QtWidgets.QSplitter()
        self.repeaterTabManager.addTab(instanceRepeaterSplitter, "new")

        req_res_tabManager = QtWidgets.QTabWidget()
        instanceRepeaterSplitter.addWidget(req_res_tabManager)

        requestsEditorFrame = QtWidgets.QFrame()
        requestsEditorFrame.setBaseSize(650, 650)
        requestsEditorFrame.setMaximumWidth(750)
        requestsEditorLayout = QtWidgets.QVBoxLayout()
        requestsEditorFrame.setLayout(requestsEditorLayout)

        requestsEditor = RepeaterReqResTextEditor()
        if request is not None:
            requestsEditor.setText(request)
        highlighter = SyntaxHighlighter(requestsEditor.document())
        requestsEditorLayout.addWidget(requestsEditor)
        req_res_tabManager.addTab(requestsEditorFrame, "request")

        repeaterSendReqButton = QtWidgets.QPushButton()
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
        except ConnectionAbortedError or ConnectionResetError:
            pass

    def updateResponseEditor(self):
        self.responseEditor.clear()
        with open(self.response_file, 'r') as file:
            response = file.read()
        self.responseEditor.setText(response)

class GuiProxyClient(QThread):
    def __init__(self, request:str, is_command=False, proxy_port = None):
        super().__init__()
        self.setObjectName("GuiProxyClient")
        self.is_command = is_command    
        self.responseDir = rundir+"tmp/"
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
            self.socket.close()
            self.exit()
            if not self.is_command:
                response = self.socket.recv(496000).decode("utf-8")
                with open(self.respose_file, 'w') as file:
                    file.write(response)
        except Exception as e:
            logging.error(f"Encountered error: {e}")
            self.exit()

    def run(self):
        self.send()


class SiteMapWindow(QtWidgets.QMainWindow):
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.siteMapMainWidget = QtWidgets.QWidget()
        self.setCentralWidget(self.siteMapMainWidget)
        self.siteMapMainWidgetLayout = QtWidgets.QVBoxLayout()
        self.siteMapMainWidget.setLayout(self.siteMapMainWidgetLayout)
        self.proxyDumpDir = "/home/program/AtomProjects/Proxy/"
        if not os.path.isdir(self.proxyDumpDir):
            os.makedirs(self.proxyDumpDir)
        self.siteDirs = []
        self.siteMapScope = ["."]

        self.requestsEditor = ReqResTextEditor()
        self.responseEditor = ReqResTextEditor()

        # splitter
        self.siteMapSplitter = QtWidgets.QSplitter()
        self.siteMapMainWidgetLayout.addWidget(self.siteMapSplitter)

        # siteMap
        self.siteMapListViewFrame = QtWidgets.QFrame()
        self.siteMapListViewFrame.setMaximumWidth(350)
        self.siteMapSplitter.addWidget(self.siteMapListViewFrame)
        self.siteMapTreeViewLayout = QtWidgets.QVBoxLayout()
        self.siteMapListViewFrame.setLayout(self.siteMapTreeViewLayout)

        self.siteMapUpperLayout = QtWidgets.QHBoxLayout()
        self.siteMapTreeViewLayout.addLayout(self.siteMapUpperLayout)

        self.siteMapListViewLabel = QtWidgets.QLabel()
        self.siteMapListViewLabel.setText("<b>Site Map</b>")
        self.siteMapUpperLayout.addWidget(self.siteMapListViewLabel, alignment=Qt.AlignLeft)

        self.siteMapListViewSettingsButton = QtWidgets.QPushButton()
        self.siteMapListViewSettingsButtonIcon = QtGui.QIcon(
            rundir + "resources/icons/settings-icon-gear-3d-render-png.png")
        self.siteMapListViewSettingsButton.setIcon(self.siteMapListViewSettingsButtonIcon)
        self.siteMapListViewSettingsButton.clicked.connect(self.openSiteMapSettings)
        self.siteMapUpperLayout.addWidget(self.siteMapListViewSettingsButton, alignment=Qt.AlignRight)

        self.siteMapLoggingLabel = QtWidgets.QLabel()
        self.siteMapLoggingLabel.setText("Logging:")
        self.siteMapUpperLayout.addWidget(self.siteMapLoggingLabel)

        self.siteMapLoggingCheckBox  = QtWidgets.QCheckBox()
        self.siteMapLoggingCheckBox.stateChanged.connect(self.HandleLoggingChange)
        self.siteMapUpperLayout.addWidget(self.siteMapLoggingCheckBox)

        self.siteMapTreeModel = QStandardItemModel()
        self.siteMapTreeView = QtWidgets.QTreeView()
        self.siteMapTreeView.setAlternatingRowColors(True)
        self.siteMapTreeView.setAnimated(True)
        self.siteMapTreeView.doubleClicked.connect(self.readReqResData)
        self.siteMapTreeView.setUniformRowHeights(True)
        self.siteMapTreeView.setEditTriggers(QtWidgets.QTreeView.NoEditTriggers)
        self.siteMapTreeViewLayout.addWidget(self.siteMapTreeView)
        # self.siteMapTreeModel.dataChanged.connect(self.getSites())
        self.getSites()
        # update siteMap class
        self.siteMapUpdater = SiteMapUpdater(self.proxyDumpDir)
        self.siteMapUpdater.fileStructureChanged.connect(self.getSites)
        self.siteMapUpdater.destroyed.connect(self.closeEvent)
        self.siteMapUpdater.setObjectName("siteMapUpdater")
        self.parent.threads.append(self.siteMapUpdater)
        self.siteMapUpdater.start()

        # the request and response area tabs
        self.siteMapReqResTabManager = QtWidgets.QTabWidget()
        self.siteMapSplitter.addWidget(self.siteMapReqResTabManager)

        self.requestsEditor.setFixedWidth(650)
        self.highlighter = SyntaxHighlighter(self.requestsEditor.document())
        self.siteMapReqResTabManager.addTab(self.requestsEditor, "request")
        self.responseEditor.setFixedWidth(650)
        self.siteMapReqResTabManager.addTab(self.responseEditor, "response")
        self.highlighter = SyntaxHighlighter(self.responseEditor.document())

        self.siteMapScopeCommand = False
        self.logggingOnCommand = False
        self.loggingOffCommand = False

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
        self.siteMapSettingsWidget = QtWidgets.QWidget()
        self.siteMapSettingsWidgetLayout = QtWidgets.QVBoxLayout()
        self.siteMapSettingsWidget.setLayout(self.siteMapSettingsWidgetLayout)

        self.siteMapSettingsScopeLabel = QtWidgets.QLabel()
        self.siteMapSettingsScopeLabel.setText("<b><u>Scope</u></b>")
        self.siteMapSettingsWidgetLayout.addWidget(self.siteMapSettingsScopeLabel)

        self.siteMapSettingsScopeNoteLabel = QtWidgets.QLabel()
        self.siteMapSettingsScopeNoteLabel.setText(
            "Add comma separated  values of the domains\n\te.g youtube, google\nThe comma separated values can also be regex patterns")
        self.siteMapSettingsWidgetLayout.addWidget(self.siteMapSettingsScopeNoteLabel)

        self.siteMapSettingsScopeLineEdit = QtWidgets.QLineEdit()
        self.siteMapSettingsScopeLineEdit.setPlaceholderText("url, domain, regex")
        self.siteMapSettingsWidgetLayout.addWidget(self.siteMapSettingsScopeLineEdit)

        self.siteMapSettingsScopeDoneButton = QtWidgets.QPushButton()
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
        self.getSites(scope=self.siteMapScope)
        self.siteMapSettingsWidget.close()

    def getSites(self, scope: list = None, regex=None):
        if scope is None:
            scope = self.siteMapScope
        # print(red("get sites has been called"))
        self.siteMapTreeModel.clear()
        self.siteDirs.clear()
        for site_dir in os.scandir(self.proxyDumpDir):
            if site_dir.is_dir():
                if scope is None:
                    self.siteDirs.append(site_dir)
                else:
                    for sc in scope:
                        pattern = re.compile(sc)
                        if len(pattern.findall(site_dir.name)) != 0:
                            self.siteDirs.append(site_dir)

        for site_dir in self.siteDirs:
            parentItem = QStandardItem(site_dir.name)
            self.siteMapTreeModel.appendRow(parentItem)
            defaultParentPath = os.path.join(self.proxyDumpDir, site_dir.name + "/")
            iterDir(defaultParentPath, parentItem)
        self.siteMapTreeView.setModel(self.siteMapTreeModel)

    def closeEvent(self, event: QtGui.QCloseEvent) -> None:
        # return super().closeEvent(event)
        self.siteMapUpdater.exit()

class AtomProxy(QThread, QtCore.QObject):
    getProxyProcessPid  = Signal(int)
    def __init__(self, proxy_port, top_parent):
        super().__init__()
        self.topParent = top_parent
        self.proxy_port = proxy_port
        self.setObjectName("AtomProxy")
        self.process = 0
        self.topParent.threads.append(self)
        self.topParent.ThreadStarted.emit(self.topParent, self.objectName())

    def run(self):
        command= f"python {rundir}/src/proxyhandlerv2.py -p {self.proxy_port}"
        self.process = subprocess.Popen(args=command, shell=True, cwd=rundir+"/src/")
        self.getProxyProcessPid.emit(self.process.pid)
        self.process.wait()
        self.topParent.socketIpc.processFinishedExecution.emit(self.topParent, self.objectName())

class ThreadMon(QtWidgets.QWidget):
    def __init__(self, thread, top_parent):
        super().__init__()
        self.topParent = top_parent
        self.formLayout = QtWidgets.QFormLayout()
        self.thread  = thread
        self.nameLabel = QtWidgets.QLabel()
        self.nameLabel.setText(thread.objectName())
        self.formLayout.addRow("Thread Name: ", self.nameLabel)
        self.status = self.getStatus()
        self.label = QtWidgets.QLabel()
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
            self.status  = "Running"
        except AttributeError:
            self.status = "Not Running"
            if self.thread.isRunning():
                self.status = "Running"
        return self.status

    def exitThread(self):
        try:
            self.pid = self.thread.process.pid
            os.system(f"kill {int(self.pid+1)}")
            logging.info(f"Terminating subprocess with pid f{self.pid}")
        except AttributeError:
            logging.info(f"Terminating thread {self.thread}")
            self.thread.terminate()
            self.thread.quit()
            if self.thread.isRunning():
                logging.error(f"Failed to terminate thread {self.thread}")

class ThreadMonitor(QtWidgets.QMainWindow):
    def __init__(self, top_parent= None):
        """ the data should be a dict of the form {"mainWindowInstance":[running_threads]}"""
        super().__init__()
        self.top_parent = top_parent
        self.windowInstances = self.top_parent.openMainWindows
        self.central_widget = QtWidgets.QWidget()
        self.setCentralWidget(self.central_widget)
        self.threadMonLayout = QtWidgets.QVBoxLayout()
        self.central_widget.setLayout(self.threadMonLayout)
        self.tabManager = QtWidgets.QTabWidget()
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

        newTabWidget = QtWidgets.QWidget()
        centralWidgetLayout = QtWidgets.QVBoxLayout()
        newTabWidget.setLayout(centralWidgetLayout)

        newTabScrollArea = QtWidgets.QScrollArea()
        centralWidgetLayout.addWidget(newTabScrollArea)

        scrollAreaWidget  = QtWidgets.QWidget()
        newTabLayout= QtWidgets.QVBoxLayout()
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

class MainWin(QtWidgets.QMainWindow, QtCore.QObject):
    newProjectCreated = Signal(QtWidgets.QMainWindow)
    projectClosed = Signal(QtWidgets.QMainWindow, int)
    ThreadStarted  = Signal(QtWidgets.QWidget, str)
    def __init__(self) -> None:
        super().__init__()
        self.openProjectCount = 0
        # SocketIPC
        self.socketIpc = SocketIPC(create_server=True)
        self.socketIpc.start()
        self.setObjectName("mainWindow")
        self.threads = []
        self.openMainWindows = [self]

        self.program_state_file = rundir+"programState/programState.txt"
        if not Path(self.program_state_file).exists():
            if not Path(os.path.dirname(self.program_state_file)).is_dir():
                os.makedirs(os.path.dirname(self.program_state_file))
        if Path(self.program_state_file).exists():
            with open(self.program_state_file, "rb") as file:
                program_state_bytes = file.read()
            # self.restoreState(program_state_bytes)
        self.proxy_port = 0
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
        self.centralWidget = QtWidgets.QWidget()
        self.tabManager = QtWidgets.QTabWidget()
        # self.centralWidget.setStyleSheet("background-color: #170048;")
        # central widget layout
        self.MainLayout = QtWidgets.QVBoxLayout()
        self.centralWidget.setLayout(self.MainLayout)

        # maintab  widget
        self.mainTabWidget = QtWidgets.QWidget()
        self.mainTabLayout = QtWidgets.QVBoxLayout()
        self.buttonAddTab = QtWidgets.QPushButton()
        self.recentProjectsLabel = QtWidgets.QLabel()
        self.recentProjectsLabel.setText("<b>Recent Projects</b>")
        self.mainTabLayout.addWidget(self.recentProjectsLabel, alignment=Qt.AlignCenter)

        self.addProjects()

        self.openBarFrame = QtWidgets.QFrame()
        self.openBarLayout = QtWidgets.QHBoxLayout()
        self.choosenProjectDir = QtWidgets.QLineEdit()
        self.choosenProjectDir.setFixedWidth(400)
        self.openBarLayout.addWidget(self.choosenProjectDir)
        self.openProjectButton = QtWidgets.QPushButton()
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
        self.tabManager.addTab(self.mainTabWidget, "Welcome")

        # self.AddTargetTab("target one")
        self.upperTabMenuLayout = QtWidgets.QHBoxLayout()
        # close tab button
        self.closeTabButton = QtWidgets.QPushButton()
        self.closeTabButton.setText("Close Tab")
        self.closeTabButton.setFixedWidth(120)
        self.closeTabButton.clicked.connect(self.closeTab)
        self.upperTabMenuLayout.addWidget(self.closeTabButton)

        self.SiteMapButton = QtWidgets.QPushButton()
        self.SiteMapButton.setText("SiteMap")
        self.SiteMapButton.setFixedWidth(110)
        self.SiteMapButton.clicked.connect(self.addSiteMapTab)
        self.upperTabMenuLayout.addWidget(self.SiteMapButton)
        # add target button
        self.addTabButton = QtWidgets.QPushButton()
        self.addTabButton.setText("Add Target")
        self.addTabButton.setFixedWidth(120)
        self.addTabButton.clicked.connect(self.AddTargetWindow)
        self.upperTabMenuLayout.addWidget(self.addTabButton)

        self.addThreadMonitorTabButton = HoverButton("ThM", "open the thread Monitor tab")
        self.addThreadMonitorTabButton.setFixedWidth(40)
        self.addThreadMonitorTabButton.clicked.connect(self.addThreadMonitorTab)
        self.upperTabMenuLayout.addWidget(self.addThreadMonitorTabButton)

        # start proxy button
        self.startProxyButton  = QtWidgets.QPushButton()
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
        print(red(f"{tool} finished execution"))

    def addThreadMonitorTab(self):
        self.threadMonitor = ThreadMonitor(top_parent= self)
        self.tabManager.addTab(self.threadMonitor, "Thread Monitor")

    def saveProgramState(self):
        byte_array = self.saveState()
        with open(self.program_state_file, "wb") as file:
            file.write(bytes(byte_array))

    def startproxy(self):
        self.proxy_port = random.randint(8000, 10000)
        logging.info("Starting proxy")
        self.proxy_ = AtomProxy(self.proxy_port, top_parent = self)
        # self.proxy_.getProxyProcessPid.connect()
        self.proxy_.start()

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
        self.dirListView = QtWidgets.QListView()
        self.dirListView.setEditTriggers(QtWidgets.QListView.NoEditTriggers)
        self.dirListView.setModel(self.dirsModel)
        self.dirListView.clicked.connect(self.projectDirClicked)

        self.dirsProjectsScrollArea = QtWidgets.QScrollArea()
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
        self.newTargetWindow = QtWidgets.QWidget()
        self.newTargetWindow.setFixedHeight(600)
        self.newTargetWindow.setFixedWidth(600)
        self.newTargetWindow.setWindowTitle("Add Target")
        # new target window layout main
        self.newTargetWindowLayoutMain = QtWidgets.QVBoxLayout()
        # new target window layout for form
        self.newTargetWindowLayout = QtWidgets.QFormLayout()
        self.newTargetTabName = QtWidgets.QLineEdit()
        self.newTargetUrlName = QtWidgets.QLineEdit()
        self.projectDir = QtWidgets.QLineEdit()
        # form layout setup
        self.newTargetWindowLayout.addRow("Project Name:", self.newTargetTabName)
        self.newTargetWindowLayout.addRow("Target Url:", self.newTargetUrlName)
        self.newTargetWindowLayout.addRow("project path: ", self.projectDir)

        self.newTargetWindowLayoutMain.addLayout(self.newTargetWindowLayout)
        # done button
        self.doneButton = QtWidgets.QPushButton()
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
            self.projectWindowCount += 1
            self.mainWindowInstance = MainWindow(projectDirectory,
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
        self.mainWindowInstance = MainWindow(directory, self.proxy_port, self, index = self.openProjectCount)
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
        os.system(f"kill {self.proxy_.process.pid+1}")
        return super().closeEvent(event)

def getLogNumber():
    logs_dir = rundir+"logs/"
    filenumbers = []
    if len(os.listdir(logs_dir)) != 0:
        for file in os.listdir(logs_dir):
            filenumber = int(file.split(".log")[0].split("log")[1])
            filenumbers.append(filenumber)
        return (max(filenumbers) + 1)
    else:
        return 0

if __name__ == "__main__":
    log_filename = rundir+"logs/log"+str(getLogNumber())+".log"
    if not Path(log_filename).exists():
        if not Path(os.path.dirname(log_filename)).is_dir():
            os.makedirs(os.path.dirname(log_filename))
    logging.basicConfig(level=logging.DEBUG, format= '%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s')
    App = QtWidgets.QApplication()
    main_window = MainWin()
    main_window.showMinimized()
    sys.exit(App.exec())
    