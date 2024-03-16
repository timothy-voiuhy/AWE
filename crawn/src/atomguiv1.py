from typing import Optional
from PySide6 import QtCore, QtWidgets, QtGui, QtWebEngineWidgets
from PySide6.QtNetwork import QNetworkProxyQuery, QNetworkProxy, QSsl, QSslCertificate, QSslConfiguration
from PySide6.QtCore import Signal, QRegularExpression

from PySide6.QtGui import QStandardItem, QStandardItemModel
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
    yellow
)
from urllib.parse import urlsplit

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


class amassFailure(Exception):
    pass


def HighlightUrls():
    pass

def iterDir(parentPath, parentItem:QStandardItem):
    for element in os.scandir(parentPath):
        if element.is_file():# if it is a file , append it to the parent item
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

class linkFinderRunner(QThread):
    def __init__(self,workingDir, subdomain:str):
        super().__init__()
        self.workingDir = workingDir
        self.subdomain = subdomain
        self.savePathName = "linkFinder"+self.subdomain+"Subdomains.txt"
        self.savePath = os.path.join(self.workingDir, self.savePathName)
        self.linkfinder = "/media/program/01DA55CA5F28E000/MYAPPLICATIONS/AWE/AWE/crawn/Tools/LinkFinder/linkfinder.py"

    def linkFinderRun(self):
        self.subdomain = "https://"+self.subdomain.strip()
        command = f"python {self.linkfinder} -i {self.subdomain} -d -o {self.savePath} -t 20"
        print(red(f"running linkFinder with command:\n\t {command}"))
        subprocess.run(command, shell=True)

    def run(self) -> None:
        self.linkFinderRun()    

class getAllUrlsRunner(QThread):
    def __init__(self, workingDir, subdomain):
        super().__init__()
        self.subdomain = subdomain
        self.workingDir = workingDir
        self.savePathName = "getAllUrls_"+self.subdomain+"Subdomains.txt"
        self.savePath = os.path.join(self.workingDir, self.savePathName)

    def getAllUrlsRun(self):
        command  = "getallurls "+self.subdomain+" > "+self.savePath
        print(red(f"Running getallurls with command:\n\t {command}"))
        subprocess.run(command, shell=True)
        print(yellow("finished running getallurls"))
        newfileLines = []
        with open(self.savePath, "r") as f:
            fileLines = f.readlines()
            seen_structs = []
            seen_urls = []
            for url in fileLines:
                if not url.endswith((".js", ".pdf", ".css",".txt", ".png", ".svg", "ico")):
                    url_cmps = urlsplit(url)
                    url_path = url_cmps[1]+url_cmps[2]
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
        self.getAllUrlsRun()    

class AtomRunner:
    def __init__(self, subdomain, usehttp, useBrowser) -> None:
        self.subdomain =  subdomain
        self.usehttp = usehttp
        self.usebrowser = useBrowser
        self.recursive = True

    def runatom(self):
        directory = self.subdomain
        usehttp = self.usehttp
        usebrowser = self.usebrowser
        with ProcessPoolExecutor(max_workers=4) as executor:
            executor.submit(
                asyncio.run(RunMainAtomFunction(self.subdomain, directory, usehttp, usebrowser, recur_=self.recursive))
            )

    def runAtom(self):
        with ThreadPoolExecutor(max_workers=1000) as executor:
            executor.submit(self.runatom)

def runUrlToolsOnSd(workingDir, subdomain):
    getAllUrlsRunner_ = getAllUrlsRunner(workingDir, subdomain)
    getAllUrlsRunner_.run()
    # linkFinderRunner_ = linkFinderRunner(workingDir, subdomain)
    # linkFinderRunner_.run()
    # AtomRunner_ = AtomRunner(subdomain, usehttp=False, useBrowser=False)
    # AtomRunner_.runatom()

def getAtomSubdUrls(subdomain, workingDir):
    atomSbdUrls = []
    for rootDir, dirs, files in os.walk(workingDir):
        for file in files:
            if file == "href_links":
                with open(file, "r") as f:
                    urls = f.readlines()
    for url in urls:
        if url.startsWith((f"https://{subdomain}", f"http://{subdomain}")):
            atomSbdUrls.append(url)
    return atomSbdUrls                  


def atomGuiGetUrls(subdomain:str, workingDir):
    # tools: Atom, getallUrls, linkFinder, xnLinkFinder(Atom)
    subdomain = subdomain.replace("\n","").strip()
    UrlsList_ = []
    
    pathName = "getAllUrls"+subdomain+"Subdomains.txt"
    pathName = os.path.join(workingDir, pathName)
    if Path(pathName).exists():
        with open(pathName, "r") as f:
            UrlsList = f.readlines()
            UrlsList_.extend(UrlsList)
    else:
        runUrlToolsOnSd(workingDir, subdomain)
    # pathName0 = "linkFinder"+subdomain+"Subdomains.txt"
    # pathName0 = os.path.join(workingDir, pathName0)
    # if Path(pathName0).exists():
    #     with open(pathName0, "r") as f:
    #         UrlsList0 = f.readlines()
    #         UrlsList_.extend(UrlsList0)        
    # atomSubdUrls = getAtomSubdUrls(subdomain, workingDir) 
    # UrlsList_.extend(atomSubdUrls)   
    return UrlsList_
        # runUrlToolsOnSd(workingDir, subdomain)

class UrlGetter(QThread):
    def __init__(self, subdomainUrlDict:dict, workingDir):
        super().__init__()
        self.subdomainUrlDict = subdomainUrlDict
        self.workingDir = workingDir
        self.subdomainsUrlDict_ = {}
        self.subdomainsUrlDict_file = os.path.join(workingDir, "subdomainsUrlDict.json")

    def run(self):
        for subdomain in list(self.subdomainUrlDict.keys()):
            urls = atomGuiGetUrls(subdomain, self.workingDir)
            self.subdomainsUrlDict_[subdomain] = urls
        jsonData = json.dumps(self.subdomainsUrlDict_)
        with open(self.subdomainsUrlDict_file, "w") as f:
            f.write(jsonData)


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
        if  self.autoIndent and event.key() == QtCore.Qt.Key.Key_Return:
            cursor = self.textCursor()
            block = cursor.block()
            text = block.text()
            cursor_position = cursor.positionInBlock()
            leading_spaces = len(text)-len(text.strip())

            if cursor_position > 0 and text.endswith((":", "{")):
                indent = leading_spaces+self.tabStopDistance()//self.fontMetrics().averageCharWidth()
                QtWidgets.QTextEdit.keyPressEvent(self, event)
                cursor.insertText(" "*int(indent))
                return 
        elif self.autoIndent and event.key() == QtCore.Qt.Key.Key_Tab:
            cursor = self.textCursor()
            block = cursor.block()
            text = block.text()
            cursor_position = cursor.positionInBlock()
            leading_spaces = len(text)-len(text.strip())

            if cursor_position >0:
                indent = leading_spaces+self.tabStopDistance()//self.fontMetrics().averageCharWidth()
                # QtWidgets.QTextEdit.keyPressEvent(self, event)
                cursor.insertText(" "*int(indent))
                return

        QtWidgets.QTextEdit.keyPressEvent(self, event)

    def setAutoIndent(self, enabled:bool):
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
        self.highlightRules = [(QtCore.QRegularExpression("\\b" + keyword + "\\b"), keyword_fmt) for keyword in keywords]

        parentheses_words = ["\(", "\)", "\{", "\}", "\[", "\]"]

        parentheses_fmt = QtGui.QTextCharFormat()
        parentheses_fmt.setForeground(Qt.yellow)
        # parentheses_fmt.setFontWeight(QtGui.QFont.Bold)
        self.highlightRules.extend(
            [(QRegularExpression(keyword), parentheses_fmt) for keyword in parentheses_words ]
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
        for pattern , format in self.highlightRules:
            expression = QRegularExpression(pattern)
            match_iter = expression.globalMatch(text)
            while match_iter.hasNext():
                match = match_iter.next()
                index = match.capturedStart()
                length = match.capturedLength()
                self.setFormat(index, length, format)


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
        self.rightDockNotePad = TextEditor()
        self.rightDockBottomLayout.addWidget(self.rightDockNotePad, 1, 0)
        # set the highlighter
        self.highlighter = SyntaxHighlighter(self.rightDockNotePad.document())

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
        self.SubdomainUrlDict = {}
        self.SubdomainUrlDict_file = os.path.join(self.projectDirPath, "subdomainsUrlDict.json")

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
            with open(tempFilePath, "a") as file:
                file.write(subdomains)
            rm_same(tempFilePath)
        
            with open(tempFilePath, "r") as f:
                list_sd = f.readlines()
                len_subdomains = len(list_sd)
                sdStr = ""
                for sd in list_sd:
                    self.SubdomainUrlDict[sd] = []
                    sdStr += sd

            if len_subdomains != 0:
                for subdomain, urls in self.SubdomainUrlDict.items():
                    parentItem = QStandardItem(subdomain)
                    self.subdomainsModel.appendRow(parentItem)
                    for url in urls:
                        url = url.replace("\n","")
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
        self.infoShowCheckBox  = QtWidgets.QCheckBox()
        self.infoShowCheckBox.stateChanged.connect(self.hideGenInfo)
        self.infoshowLayout.addRow("hide info", self.infoShowCheckBox)
        self.leftDockLayout.addLayout(self.infoshowLayout)
        # general information layout
        self.generalInformationLayout = QtWidgets.QFormLayout()
        self.generalInformationFrame = QtWidgets.QFrame()
        self.generalInformationFrame.setLayout(self.generalInformationLayout)
        # self.generalInformationFrame.setHidden(True)
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
        self.subdomainsModel.setHorizontalHeaderLabels(["Subdomain:UrlsMapping"])
        self.subdomainsTreeView  = QtWidgets.QTreeView()
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
        else:   
            self.url_getter = UrlGetter(self.SubdomainUrlDict, self.projectDirPath)
            self.url_getter.start()
            self.url_getter.subdomainsUrlDict_
            with open(self.SubdomainUrlDict_file, "r") as f:
                jsonData = f.read()
            self.SubdomainUrlDict = json.loads(jsonData) 
            self.subdomainsModel.dataChanged.emit(QtCore.QModelIndex(), QtCore.QModelIndex())
        self.subdomainsModel.clear()  
        self.subdomainsModel.setHorizontalHeaderLabels(["Subdomain:UrlsMapping"])     
        for subdomain, urls in self.SubdomainUrlDict.items():
            parentItem = QStandardItem(subdomain)
            self.subdomainsModel.appendRow(parentItem)
            for url in urls:
                url_item = QStandardItem(url)
                parentItem.appendRow(url_item)

    @QtCore.Slot(int)
    def openLinkInBrowser(self, index:QtCore.QModelIndex):
        clicked_link = self.subdomainsModel.itemFromIndex(index).text()
        self.openLinkInBrw.emit(clicked_link)

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
            # print(f"clicked link is {self.init_link}")
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

    def searchUrlOnBrowser(self, link=""):
        self.target_url = self.urlText.text()
        if link is not False:
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
        self.enableProxyCheckBox.setChecked(True)
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
        self.proxyDoneButton.clicked.connect(self.enableProxy())
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

        # docks
        SiteMapDock = SiteMapDock(self)  # site map dock
        self.siteMapDock = SiteMapDock.InitializeSiteMapDock()

        self.MainWidget = QtWidgets.QWidget()
        self.setCentralWidget(self.MainWidget)

class ReqResTextEditor(TextEditor):
    def __init__(self):
        super().__init__()

class SiteMapUpdater(QThread, QtCore.QObject):
    fileStructureChanged = Signal()
    def __init__(self, proxyDumpDir):
        super().__init__()
        self.proxyDumpDir = proxyDumpDir
        self.old_proxyDumpDirComponents = set()
        self.new_proxyDumpDirComponents = set()
        self.stateNotChanged = 0

    def checkDirChange(self):
        while True:
            self.new_proxyDumpDirComponents.clear()
            for _, dirs, files in os.walk(self.proxyDumpDir):
                [self.new_proxyDumpDirComponents.add(dir_) for dir_ in dirs]
                [self.new_proxyDumpDirComponents.add(file) for file in files] 

            if not self.old_proxyDumpDirComponents == self.new_proxyDumpDirComponents:
                # print(red("structure changed"))
                self.fileStructureChanged.emit()
                self.old_proxyDumpDirComponents = self.new_proxyDumpDirComponents.copy() # set the old list to equal to the new list such that it becomes the new old
            else:
                # self.stateNotChanged++
                pass

    def run(self) -> None:
        self.checkDirChange()


class SiteMapWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.siteMapMainWidget = QtWidgets.QWidget()
        self.setCentralWidget(self.siteMapMainWidget)
        self.siteMapMainWidgetLayout = QtWidgets.QVBoxLayout()
        self.siteMapMainWidget.setLayout(self.siteMapMainWidgetLayout)
        self.proxyDumpDir = "/home/program/AtomProjects/Proxy/"
        self.siteDirs = []
        
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
        self.siteMapListViewSettingsButtonIcon = QtGui.QIcon("./resources/icons/settings-icon-gear-3d-render-png.png")
        self.siteMapListViewSettingsButton.setIcon(self.siteMapListViewSettingsButtonIcon)
        self.siteMapListViewSettingsButton.clicked.connect(self.openSiteMapSettings)
        self.siteMapUpperLayout.addWidget(self.siteMapListViewSettingsButton, alignment=Qt.AlignRight)

        self.siteMapTreeModel =  QStandardItemModel()
        self.siteMapTreeView = QtWidgets.QTreeView()
        self.siteMapTreeView.setAlternatingRowColors(True)
        self.siteMapTreeView.setAnimated(True)
        self.siteMapTreeView.setUniformRowHeights(True)
        self.siteMapTreeView.setEditTriggers(QtWidgets.QTreeView.NoEditTriggers)
        self.siteMapTreeViewLayout.addWidget(self.siteMapTreeView)
        # self.siteMapTreeModel.dataChanged.connect(self.getSites())
        self.getSites()
        #update siteMap class 
        self.siteMapUpdater = SiteMapUpdater(self.proxyDumpDir)
        self.siteMapUpdater.fileStructureChanged.connect(self.getSites)
        self.siteMapUpdater.destroyed.connect(self.closeEvent)
        self.siteMapUpdater.start()
    
        # the request and response area tabs
        self.siteMapReqResTabManager = QtWidgets.QTabWidget()
        self.siteMapSplitter.addWidget(self.siteMapReqResTabManager)

        self.requestsTab = ReqResTextEditor()
        self.highlighter = SyntaxHighlighter(self.requestsTab.document())
        self.siteMapReqResTabManager.addTab(self.requestsTab, "request")
        self.responseTab = ReqResTextEditor()
        self.siteMapReqResTabManager.addTab(self.responseTab, "response")
        self.highlighter = SyntaxHighlighter(self.responseTab.document())
        
    def openSiteMapSettings(self):
        self.siteMapSettingsWidget = QtWidgets.QWidget()
        self.siteMapSettingsWidgetLayout = QtWidgets.QVBoxLayout()
        self.siteMapSettingsWidget.setLayout(self.siteMapSettingsWidgetLayout)

        self.siteMapSettingsScopeLabel = QtWidgets.QLabel()
        self.siteMapSettingsScopeLabel.setText("<b><u>Scope</u></b>")
        self.siteMapSettingsWidgetLayout.addWidget(self.siteMapSettingsScopeLabel)

        self.siteMapSettingsScopeNoteLabel= QtWidgets.QLabel()
        self.siteMapSettingsScopeNoteLabel.setText("Add comma separated  values of the domains\n\te.g youtube, google\nThe comma separated values can also be regex patterns")
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

    def setSiteMapScope(self):
        scope = []
        scope_ = self.siteMapSettingsScopeLineEdit.text()
        if "," in scope_:
            scps = scope_.split(",")
            [scope.append(scope__.strip()) for scope__ in scps]
        else:
            scope.append(scope_)
        self.getSites(scope= scope)    
        self.siteMapSettingsWidget.close()    

    def getSites(self, scope:list=None, regex=None):
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
            defaultParentPath = os.path.join(self.proxyDumpDir, site_dir.name+"/")
            iterDir(defaultParentPath, parentItem)
        self.siteMapTreeView.setModel(self.siteMapTreeModel)    

    def closeEvent(self, event: QtGui.QCloseEvent) -> None:
        # return super().closeEvent(event)
        self.siteMapUpdater.exit()


class MainWin(QtWidgets.QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        
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
        self.SiteMapButton.clicked.connect(self.addSiteMapTab)
        self.upperTabMenuLayout.addWidget(self.SiteMapButton)
        # add site map Target
        self.addSiteMapTab()
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

    def addSiteMapTab(self):
        self.siteMapWindow = SiteMapWindow()
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
