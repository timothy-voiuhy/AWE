import os
import re
import subprocess

from PySide6.QtCore import Qt
from PySide6.QtGui import QKeyEvent
from PySide6.QtWidgets import QMainWindow, QDockWidget, QWidget, QVBoxLayout, QTextEdit


class Qterminal(QTextEdit):
    def __init__(self) -> None:
        super().__init__()
        self.placeCursorAtEnd()
        font = self.font()
        font.setPointSize(font.pointSize() + 1)
        self.setFont(font)
        self.currentWorkingDir = self.getCurrentWorkingDir().replace("\n", "").strip()
        self.terminalDefaultText = f">>>[{self.currentWorkingDir}]"
        self.setPlainText(self.terminalDefaultText)
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
                Lines[len(Lines) - 1].replace(self.terminalDefaultText, "").strip())
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
                        cwd=self.currentWorkingDir,)
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

class LowerDock:

    def __init__(self, MainWindow: QMainWindow, projectDirPath) -> None:
        self.main_window = MainWindow
        self.projectDirPath = projectDirPath

    def InitializeLowerDock(self):
        # lower dock
        self.lowerDock = QDockWidget("Terminal")
        self.lowerDockWidget = QWidget()
        self.lowerDockArea = Qt.DockWidgetArea()
        self.main_window.addDockWidget(
            self.lowerDockArea.BottomDockWidgetArea, self.lowerDock
        )
        # layout
        self.lowerDockLayout = QVBoxLayout()
        # self.lowerDock.setMaximumHeight(200)
        # text edit terminal
        self.terminalTextEdit = Qterminal()
        self.lowerDockLayout.addWidget(self.terminalTextEdit)
        self.lowerDockWidget.setLayout(self.lowerDockLayout)
        self.lowerDock.setWidget(self.lowerDockWidget)

        return self.lowerDock