import os
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QMainWindow, QDockWidget, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QTabWidget, \
    QLineEdit, QPushButton, QMenu, QFileDialog, QMessageBox

from gui.guiUtilities import TextEditor, SyntaxHighlighter


class RightDock:
    def __init__(self, MainWindow: QMainWindow, projectsDir) -> None:
        self.projectsDirPath = projectsDir
        self.MainWindow = MainWindow
        self.rightDockNotePadOpenfile = ""
        self.openEditors = []

    def InitializeDock(self):
        # right dock
        self.RightDock = QDockWidget("Take Your Notes, Edit Files")
        self.rightDockWidget = QWidget()
        self.RightDock.setWidget(self.rightDockWidget)

        self.rightDockLayoutMain = QVBoxLayout()
        self.rightDockWidget.setLayout(self.rightDockLayoutMain)

        self.rightDockUpperWidget = QWidget()

        self.AddMainMenu()
        self.AddSettingsMenu()

        self.rightDockUpperLayout = QHBoxLayout()
        self.rightDockUpperLayout.addWidget(self.rightDockMenuButton)
        self.rightDockUpperLayout.addWidget(self.rightDockSettingsButton)
        self.rightDockUpperWidget.setLayout(self.rightDockUpperLayout)
        self.rightDockLayoutMain.addWidget(self.rightDockUpperWidget)

        self.rightDockBottomLayout = QGridLayout()
        self.rightDockLayoutMain.addLayout(self.rightDockBottomLayout)
        # tabManager for opening multiple files in different tabs
        self.tabManager = QTabWidget()
        self.rightDockBottomLayout.addWidget(self.tabManager, 1, 0)
        # self.defaultEditor = self.addEditor()
        # self.tabManager.addTab(self.addEditor(), "Editor")
        self.tabManager.currentChanged.connect(self.updateCurretNotepad)

        self.rightDockArea = Qt.DockWidgetArea()
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

        self.rightDockFontWidget = QWidget()
        self.rightDockFontWidgetLayout = QHBoxLayout()
        self.rightDockFontWidgetLineEdit = QLineEdit()
        self.rightDockFontWidgetOkButton = QPushButton("Ok")
        self.rightDockFontWidgetOkButton.clicked.connect(setFontSize)
        self.rightDockFontWidgetLayout.addWidget(self.rightDockFontWidgetOkButton)
        self.rightDockFontWidgetLayout.addWidget(self.rightDockFontWidgetLineEdit)
        self.rightDockFontWidget.setWindowTitle("increase font")
        self.rightDockFontWidget.setLayout(self.rightDockFontWidgetLayout)
        self.rightDockFontWidget.show()

    def AddSettingsMenu(self):
        rightDockSettingsButtonIcon = QIcon.fromTheme("preferences-system")
        # settngs menu
        self.rightDockSettingsMenu = QMenu()
        rightNotepadTheme = self.rightDockSettingsMenu.addAction("theme")
        self.rightDockNotepadFont = self.rightDockSettingsMenu.addAction("font")
        self.rightDockNotepadFont.triggered.connect(self.increaseFont)
        # settings button
        self.rightDockSettingsButton = QPushButton()
        self.rightDockSettingsButton.setFixedWidth(28)
        self.rightDockSettingsButton.setIcon(rightDockSettingsButtonIcon)
        self.rightDockSettingsButton.clicked.connect(self.ShowSettings)

    def AddMainMenu(self):
        def rightDockTextBroserOpenFile():
            rightDockFileDialog = QFileDialog()
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
                saveMessageBox = QMessageBox()
                saveMessageBox.setWindowTitle("Information")
                saveMessageBox.setText(f"Do you want to save {self.rightDockNotePadOpenfile}")
                saveMessageBox.setIcon(QMessageBox.Information)
                saveMessageBox.setStandardButtons(QMessageBox.Ok)
                edited_text = self.tabManager.currentWidget().toPlainText()
                ret = saveMessageBox.exec()
                if ret == QMessageBox.Ok:
                    with open(self.tabManager.currentWidget().objectName(), "w") as file:
                        file.write(edited_text)
                return ret

        def rightDockTextBroserCloseFile():
            if self.rightDockNotePadOpenfile is not None:
                if rightDockTextBroserSaveFile() == QMessageBox.Ok:
                    self.rightDockNotePadOpenfile = None
                    self.tabManager.currentWidget().clear()
                    self.tabManager.removeTab(self.tabManager.currentIndex())
                    # edit the current open file pointed to by self
                    if self.tabManager.currentWidget() is not None:
                        self.rightDockNotePadOpenfile = self.tabManager.currentWidget().objectName()
            else:
                infoMessageBox = QMessageBox()
                infoMessageBox.setWindowTitle("Information")
                infoMessageBox.setText("No open file")
                infoMessageBox.setIcon(QMessageBox.Information)
                infoMessageBox.setStandardButtons(QMessageBox.Ok)
                ret = infoMessageBox.exec()
                if ret == QMessageBox.Ok:
                    pass

        rightDockMenuButtonIcon = QIcon.fromTheme("view-list")
        # right dock menu
        self.rightDockMenu = QMenu()
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
        self.rightDockMenuButton = QPushButton()
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