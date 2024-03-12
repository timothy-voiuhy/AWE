from typing import Optional
from aiohttp import ThreadedResolver
from PySide6 import QtCore, QtWidgets, QtGui, QtWebEngineWidgets
from PySide6.QtNetwork import QNetworkProxyQuery, QNetworkProxy, QSsl, QSslCertificate, QSslConfiguration
from PySide6.QtCore import Signal, SignalInstance
import subprocess
from PySide6.QtCore import QThread
from pathlib import Path
import asyncio

from attr import s
from atomcore import RunMainAtomFunction
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
import os
import json
import re
import sys
from PySide6.QtGui import QKeyEvent
from utiliities import addHttpsScheme
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QWidget
from utiliities import (
    red,
    cyan,
    AmassSubdProcessor,
    SubDomainizerRunner,
    SublisterRunner,
    rm_same,
)

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

"""


class amassFailure(Exception):
    pass


def HighlightUrls():
    pass


def GetUrls(workingdir):
    hrefLinksFile = os.path.join(workingdir, "href_links")
    # read the index file and return the urls in it
    urls = open(hrefLinksFile, "r").read()
    return urls


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


# accessign default icons
# pixmapi = QtWidgets.QStyle.SP_MessageBoxCritical
# icon = self.style().standardIcon(pixmapi)
class RightDock:
    def __init__(self, MainWindow: QtWidgets.QMainWindow, projectsDir) -> None:
        self.projectsDirPath = projectsDir
        self.MainWindow = MainWindow
        self.rightDockNotePadOpenfile = ""

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
        # notepad
        self.rightDockNotePad = QtWidgets.QTextEdit()
        self.rightDockBottomLayout.addWidget(self.rightDockNotePad, 1, 0)

        self.rightDockArea = QtCore.Qt.DockWidgetArea()
        self.MainWindow.addDockWidget(
            self.rightDockArea.RightDockWidgetArea, self.RightDock
        )
        return self.RightDock

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
            self.rightDockNotePadOpenfile = rightDockFileDialog.getOpenFileName(
                None, "Open File", "/", "All Files (*.*)"
            )[0]
            with open(self.rightDockNotePadOpenfile, "r") as file:
                text = file.read()
                file.close()
            self.rightDockNotePad.setAcceptRichText(True)
            self.rightDockNotePad.setText(text)

        def rightDockTextBroserSaveFile():
            if self.rightDockNotePadOpenfile != None:
                saveMessageBox = QtWidgets.QMessageBox()
                saveMessageBox.setWindowTitle("Information")
                saveMessageBox.setText("Do you want to save this file")
                saveMessageBox.setIcon(QtWidgets.QMessageBox.Information)
                saveMessageBox.setStandardButtons(QtWidgets.QMessageBox.Ok)
                edited_text = self.rightDockNotePad.toPlainText()
                ret = saveMessageBox.exec()
                if ret == QtWidgets.QMessageBox.Ok:
                    with open(self.rightDockNotePadOpenfile, "w") as file:
                        file.write(edited_text)
                return ret

        def rightDockTextBroserCloseFile():
            if self.rightDockNotePadOpenfile is not None:
                if rightDockTextBroserSaveFile() == QtWidgets.QMessageBox.Ok:
                    self.rightDockNotePadOpenfile = None
                    self.rightDockNotePad.clear()
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
        self.rightDockOpenFileAction = self.rightDockMenu.addAction("Open Existing")
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
            # create the notesfile in the notesfilepath
            with open(self.notesfilepath, "a") as file:
                file.close()
        # no need to first choose the file using the qtfiledialog
        self.rightDockNotePadOpenfile = self.notesfilepath
        # open the file and place its contents on the notepad
        filecontents = open(self.notesfilepath, "r").read()
        self.rightDockNotePad.setText(filecontents)

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

    def __init__(self, mainWindow: QtWidgets.QMainWindow, projectDirPath) -> None:
        super().__init__()
        self.main_window = mainWindow
        self.projectDirPath = projectDirPath

    def InitializeLeftDock(self):
        def showUrls():
            urls = GetUrls(self.projectDirPath)
            Urls = urls.split("\n")
            nUrls = len(Urls)
            self.nUrls.setText(str(nUrls))
            self.subdomainsModel.setStringList(Urls)

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
        # general information layout
        self.generalInformationLayout = QtWidgets.QFormLayout()
        self.generalInformationFrame = QtWidgets.QFrame()
        self.generalInformationFrame.setLayout(self.generalInformationLayout)
        # self.generalInformation = QtWidgets.Q
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
        self.subdomainsButton = QtWidgets.QPushButton("Sub-domains")
        self.USlayout.addWidget(self.subdomainsButton)
        self.subdomainsButton.clicked.connect(self.showSubDomains)
        # show urls Button
        self.urlsButton = QtWidgets.QPushButton("Show Urls")
        self.urlsButton.clicked.connect(showUrls)
        self.USlayout.addWidget(self.urlsButton)

        # subdomains and urls
        self.subdomainsModel = QtCore.QStringListModel()
        self.subdomainsListview = QtWidgets.QListView()
        self.subdomainsListview.doubleClicked.connect(self.openLinkInBrowser)
        self.subdomainsListview.setModel(self.subdomainsModel)

        self.subdomainsScrollArea = QtWidgets.QScrollArea()
        self.subdomainsScrollArea.setWidgetResizable(True)
        self.subdomainsScrollArea.setWidget(self.subdomainsListview)
        self.leftDockLayout.addWidget(self.subdomainsScrollArea)

        return self.leftDock

    @QtCore.Slot(int)
    def openLinkInBrowser(self, index):
        clicked_link = self.subdomainsModel.data(index, QtCore.Qt.DisplayRole)
        self.openLinkInBrw.emit(clicked_link)

    def showSubDomains(self):
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
        with open(tempFilePath, "a") as file:
            file.write(subdomains)
        rm_same(tempFilePath)
        with open(tempFilePath, "r") as f:
            list_sd = f.readlines()
            len_subdomains = len(list_sd)
            sd = ""
            for s in list_sd:
                sd += s
        if len_subdomains != 0:
            subdomains_string_list = sd.split("\n")
            self.subdomainsModel.setStringList(subdomains_string_list)
            self.nSubd.setText(str(len_subdomains))
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


class BrowserWindow(QtWidgets.QMainWindow):
    def __init__(self, link=None) -> None:
        super().__init__()

        self.init_link = link

        centralWidget= QtWidgets.QWidget()
        self.setCentralWidget(centralWidget)

        self.centralWidgetLayout = QtWidgets.QVBoxLayout()
        centralWidget.setLayout(self.centralWidgetLayout)

        self.browser = QtWebEngineWidgets.QWebEngineView()
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
            self.searchUrlOnBrowser(self.init_link)

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
        self.clearButton = QtWidgets.QPushButton()
        self.clearButton.setText("X")
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
        if link is not None:
            self.target_url = self.urlText.text()
        else:
            self.target_url = link
        self.target_url = addHttpsScheme(self.target_url)
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
        self.subDomainizerUrlTarget = subDomainizerUrlTarget
        self.projectDirPath = projectDirPath

    def subdomainizerRun(self):
        self.subDomainizerRunner = SubDomainizerRunner(
            self.subDomainizerUrlTarget, self.projectDirPath
        )
        self.subDomainizerRunner.Run()

    def run(self) -> None:
        self.subdomainizerRun()


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


class AmassThreadRunner(QThread):
    def __init__(self, amassUrlTarget, projectDirPath):
        super().__init__()
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
    def __init__(self, projectDirPath) -> None:
        super().__init__()
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
            self.subDomainizerRunner.start()

        def runAmass():
            self.amassRunner = AmassThreadRunner(
                self.amassUrlTarget.text(), self.projectDirPath
            )
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
    def __init__(self, projectDirPath: str):
        super().__init__()
        self.projectDirPath = projectDirPath

        # Docks
        lowerDock = LowerDock(self, self.projectDirPath)
        self.LowerDock = lowerDock.InitializeLowerDock()
        self.LowerDock.setVisible(False)
        rightDock = RightDock(self, self.projectDirPath)
        self.RightDock = rightDock.InitializeDock()
        leftdock = LeftDock(self, self.projectDirPath)
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
        self.newBrowserTabButton = QtWidgets.QPushButton()
        self.newBrowserTabButton.setText("NewBrowserTab")
        self.newBrowserTabButton.clicked.connect(self.openNewBrowserTab)
        self.newBrowserTabButton.setFixedWidth(150)
        self.uppperCentralLayout.addWidget(self.newBrowserTabButton)

        # close Browser Tab
        self.closeTabButton = QtWidgets.QPushButton()
        self.closeTabButton.setText("Close Tab")
        self.closeTabButton.setFixedWidth(120)
        self.closeTabButton.clicked.connect(self.closeBrowserTab)
        self.uppperCentralLayout.addWidget(self.closeTabButton)

        # test target button
        self.testTargetButton = QtWidgets.QPushButton()
        self.testTargetButton.setText("Test target")
        self.testTargetButton.setFixedWidth(140)
        self.testTargetButton.clicked.connect(self.OpenTestTargetWindow)
        self.uppperCentralLayout.addWidget(self.testTargetButton, alignment=Qt.AlignLeft)

        self.setWindowTitle("atom")

        self.centralWidgetLayout.addStretch()

    def openNewBrowserTab(self, link:str=None):
        BrowserWindow_ = BrowserWindow(link = link)
        tab_name = "newT"
        try:
            if link is not None:
                if link.startswith(("https", "http")):
                    tab_name = link.split("//")[1].split(".")[0]
                else:
                    tab_name = link.split(".")[0]   
        except:
            tab_name = "newT" 
        self.browserTabWidget.addTab(BrowserWindow_,tab_name)
        self.browserTabWidget.setCurrentIndex(
                self.browserTabWidget.indexOf(BrowserWindow_)
            )

    def closeBrowserTab(self):
        self.browserTabWidget
        self.current_tab_index = self.browserTabWidget.currentIndex()
        if self.current_tab_index != 0:
            self.browserTabWidget.removeTab(self.current_tab_index)

    def LoadCA_Certificate(self):
        self.rootCACertificate = QSslCertificate()
        self.rootCACertificateFile = "./proxycert/CA/certificate.crt"
        # self.rootCACertificate.importPkcs12(self.rootCACertificateFile) this is a wrong approach

        self.sslConfig = QSslConfiguration.defaultConfiguration()
        self.sslConfig.addCaCertificate(self.rootCACertificate)

        QSslConfiguration.setDefaultConfiguration(self.sslConfig)

    def enableProxy(self):
        if not self.enableProxyCheckBox.isChecked():
            self.proxy_hostname = self.proxyHostNameLineEdit.text()
            try:
                self.proxy_port = int(self.proxyPortNameLineEdit.text())
                proxy  = QNetworkProxy()
                proxy.setType(QNetworkProxy.HttpProxy)
                proxy.setHostName(self.proxy_hostname)
                proxy.setPort(self.proxy_port)
                QNetworkProxy.setApplicationProxy(proxy)
                self.enableProxyCheckBox.setChecked(True)
                # self.LoadCA_Certificate()    
            except ValueError:
                self.proxyPortNameLineEdit.setStyleSheet("QLineEdit{border: 2px solid red;}")
                self.enableProxyCheckBox.setChecked(False)

    def OpenTestTargetWindow(self):
        self.testWindow = TestTargetWindow(self.projectDirPath)
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
        self.MenuIcon = QtGui.QIcon.fromTheme("view-list")
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
        self.enableProxyCheckBox.stateChanged.connect(self.enableProxy)
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


class SiteMapDock:
    def __init__(self, main_window: QtWidgets.QMainWindow) -> None:
        self.main_window = main_window

    def InitializeSiteMapDock(self):
        self.SiteMapDock = QtWidgets.QDockWidget("Site Map")
        self.SiteMapDockWidget = QtWidgets.QWidget()
        self.SiteMapDock.setWidget(self.leftDockWidget)
        self.SiteMapDockArea = QtCore.Qt.DockWidgetArea()
        self.main_window.addDockWidget(
            self.SiteMapDockArea.LeftDockWidgetArea, self.SiteMapDock
        )
        # layout
        self.SiteMapDockLayout = QtWidgets.QVBoxLayout()
        self.SiteMapDockWidget.setLayout(self.SiteMapDockLayout)

        return self.SiteMapDock


class ProxyInterceptWindow(QtWidgets.QMainWindow):
    def __init__(self, projectDirPath):
        super().__init__()
        self.projectDirPath = projectDirPath

        # docks
        SiteMapDock = SiteMapDock(self)  # site map dock
        self.siteMapDock = SiteMapDock.InitializeSiteMapDock()

        self.MainWidget = QtWidgets.QWidget()
        self.setCentralWidget(self.MainWidget)


class MainWin(QtWidgets.QMainWindow):
    def __init__(self) -> None:
        super().__init__()
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
        self.buttonAddTab.setFixedWidth(110)
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
        self.SiteMapButton.clicked.connect(self.OpenSiteMapWindow)
        self.upperTabMenuLayout.addWidget(self.SiteMapButton)
        # add target button
        self.addTabButton = QtWidgets.QPushButton()
        self.addTabButton.setText("Add Target")
        self.addTabButton.setFixedWidth(120)
        self.addTabButton.clicked.connect(self.AddTargetWindow)
        self.upperTabMenuLayout.addWidget(self.addTabButton)
        self.upperTabMenuLayout.setAlignment(self.addTabButton, Qt.AlignLeft)
        self.MainLayout.addLayout(self.upperTabMenuLayout)

        self.MainLayout.addWidget(self.tabManager)
        self.setCentralWidget(self.centralWidget)
        self.mainTabLayout.addStretch()

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
                    available_dirs.append(entry.name)
        self.dirsModel = QtCore.QStringListModel(available_dirs)
        self.dirListView  = QtWidgets.QListView()
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

    def OpenSiteMapWindow(self):
        pass

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
        self.doneButton.clicked.connect(self.AddTargetTab)

        self.newTargetWindow.setLayout(self.newTargetWindowLayoutMain)
        self.newTargetWindow.show()

    def AddTargetTab(self, directory=None):
        if directory is None:
            tab_name = self.newTargetTabName.text()
            if tab_name == "":
                self.newTargetTabName.setStyleSheet("border: 1px solid red;")
            else:
                projectDirectory = os.path.join(self.defaultWorkspaceDir, tab_name)
                if not Path(projectDirectory).exists():
                    os.makedirs(projectDirectory)
                self.mainWindowInstance = MainWindow(projectDirectory)
                self.tabManager.addTab(self.mainWindowInstance, tab_name)
                self.tabManager.setCurrentIndex(
                    self.tabManager.indexOf(self.mainWindowInstance)
                )
                self.newTargetWindow.close()
        else:
            self.mainWindowInstance = MainWindow(directory)
            tab_name = directory.split("/")[-1]
            self.tabManager.addTab(self.mainWindowInstance, tab_name)
            self.tabManager.setCurrentIndex(
                self.tabManager.indexOf(self.mainWindowInstance)
            )              

    def closeTab(self):
        self.current_tab_index = self.tabManager.currentIndex()
        if self.current_tab_index != -1:
            self.tabManager.removeTab(self.current_tab_index)


if __name__ == "__main__":
    App = QtWidgets.QApplication()
    main_window = MainWin()
    main_window.showMaximized()
    sys.exit(App.exec())
