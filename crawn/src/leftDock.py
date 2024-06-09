import json
import os
from pathlib import Path

from PySide6.QtCore import QObject, Signal, Qt, QModelIndex, Slot
from PySide6.QtGui import QStandardItem, QStandardItemModel
from PySide6.QtWidgets import QMainWindow, QMessageBox, QDockWidget, QWidget, QVBoxLayout, QFormLayout, QCheckBox, \
    QFrame, QLabel, QHBoxLayout, QPushButton, QTreeView

from functionUtils import atomGuiGetSubdomains
from guiUtilities import MessageBox
from main import UrlGetter
from utiliities import rm_same


class LeftDock(QObject):
    openLinkInBrw = Signal(str)

    def __init__(self, mainWindow: QMainWindow,
                 projectDirPath,
                 parent=None,
                 top_parent=None,
                 ) -> None:
        super().__init__()
        self.topParent = top_parent
        self.urlGetterRunning = False
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
                    self.toolNotYetRunAlert = QMessageBox()
                    self.toolNotYetRunAlert.setWindowTitle("Information")
                    self.toolNotYetRunAlert.setText(
                        f"{tN} has not yet been run on the target,\nDo you want to run {tN}")
                    self.toolNotYetRunAlert.setIcon(QMessageBox.Question)
                    # self.toolNotYetRunAlert.setStandardButtons(QMessageBox.Ok)
                    # self.toolNotYetRunAlert.setStandardButtons()

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

            # return only the subdomains which are alive
            # subdomains = getLiveSubdomains(subdomains)

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
                self.noSubdomainsAlert = QMessageBox()
                self.noSubdomainsAlert.setWindowTitle("Information")
                self.noSubdomainsAlert.setText(
                    "It seems no domain finding tool has been run on the target"
                )
                self.noSubdomainsAlert.setIcon(QMessageBox.Information)
                self.noSubdomainsAlert.setStandardButtons(QMessageBox.Ok)
                ret = self.noSubdomainsAlert.exec()
                if ret == QMessageBox.Ok:
                    pass

        # lower dock
        self.leftDock = QDockWidget("Target Information")
        self.leftDockWidget = QWidget()
        self.leftDock.setWidget(self.leftDockWidget)
        self.leftDockArea = Qt.DockWidgetArea()
        self.main_window.addDockWidget(
            self.leftDockArea.LeftDockWidgetArea, self.leftDock
        )
        # layout
        self.leftDockLayout = QVBoxLayout()
        self.leftDockWidget.setLayout(self.leftDockLayout)
        # hide or show gen info
        self.infoshowLayout = QFormLayout()
        self.infoShowCheckBox = QCheckBox()
        self.infoShowCheckBox.setChecked(True)
        self.infoShowCheckBox.stateChanged.connect(self.hideGenInfo)
        self.infoshowLayout.addRow("hide info", self.infoShowCheckBox)
        self.leftDockLayout.addLayout(self.infoshowLayout)
        # general information layout
        self.generalInformationLayout = QFormLayout()
        self.generalInformationFrame = QFrame()
        self.generalInformationFrame.setLayout(self.generalInformationLayout)
        self.generalInformationFrame.setHidden(True)
        self.leftDockLayout.addWidget(self.generalInformationFrame)
        # rows (static information)
        self.urlTargetName = QLabel("URL: ")
        self.urlName = QLabel("put here targe name")
        self.generalInformationLayout.addRow(self.urlTargetName, self.urlName)
        self.numberOfSubdomains = QLabel("nSubdomains")
        self.nSubd = QLabel("0")
        self.amassSdCount = QLabel(" =>Amass:")
        self.amassSdCountLabel = QLabel("0")
        self.subdomainizerSdCount = QLabel(" =>subdomainizer:")
        self.subdomainizerSdCountLabel = QLabel("0")
        self.sublist3rSdCount = QLabel(" =>sublist3r:")
        self.sublist3rSdCountLabel = QLabel("0")
        self.generalInformationLayout.addRow(self.numberOfSubdomains, self.nSubd)
        self.numberOfUrls = QLabel("nUrls")
        self.nUrls = QLabel("0")
        self.generalInformationLayout.addRow(self.amassSdCount, self.amassSdCountLabel)
        self.generalInformationLayout.addRow(
            self.subdomainizerSdCount, self.subdomainizerSdCountLabel
        )
        self.generalInformationLayout.addRow(
            self.sublist3rSdCount, self.sublist3rSdCountLabel
        )
        self.generalInformationLayout.addRow(self.numberOfUrls, self.nUrls)
        # dynamic information
        self.USlayout = QHBoxLayout()
        self.leftDockLayout.addLayout(self.USlayout)
        # show subdomains button
        self.subdomainsButton = QPushButton("SubdUrlTree")
        self.subdomainsButton.clicked.connect(showSbdUrlTree)
        self.USlayout.addWidget(self.subdomainsButton)
        # show urls Button
        self.urlsButton = QPushButton("UrlsScan")
        self.urlsButton.clicked.connect(self.UrlsScan)
        self.USlayout.addWidget(self.urlsButton)

        # subdomains : urls tree
        self.subdomainsModel = QStandardItemModel()
        # ? is it possible to update just part of the model without resetting it
        # self.subdomainsModel.dataChanged.connect(self.updateSubdomainsModel)
        self.subdomainsModel.setHorizontalHeaderLabels(["Subdomain:UrlsMapping"])
        self.subdomainsTreeView = QTreeView()
        self.subdomainsTreeView.setModel(self.subdomainsModel)
        self.subdomainsTreeView.doubleClicked.connect(self.openLinkInBrowser)
        self.subdomainsTreeView.setAlternatingRowColors(True)
        self.subdomainsTreeView.setAnimated(True)
        self.subdomainsTreeView.setUniformRowHeights(True)
        self.subdomainsTreeView.setEditTriggers(QTreeView.NoEditTriggers)
        self.leftDockLayout.addWidget(self.subdomainsTreeView)
        return self.leftDock

    def hideGenInfo(self):
        if self.infoShowCheckBox.isChecked():
            self.generalInformationFrame.setHidden(True)
        else:
            self.generalInformationFrame.setHidden(False)

    @Slot()
    def UrlsScan(self):
        if Path(self.SubdomainUrlDict_file).exists():
            with open(self.SubdomainUrlDict_file, "r") as f:
                jsonData = f.read()
            self.SubdomainUrlDict = json.loads(jsonData)
            self.subdomainsModel.dataChanged.emit(QModelIndex(), QModelIndex())
            self.updateModel()
        else:
            if self.urlGetterRunning is False:
                self.urlGetterRunning = True
                self.url_getter = UrlGetter(self.SubdomainUrlDict,
                                            self.projectDirPath,
                                            parent=self.parent,
                                            dict_parent=self,
                                            top_parent=self.topParent,
                                            mainWindow=self.main_window)
                self.url_getter.urlGetterFinished.connect(self.updateModel)
                self.url_getter.start()
            else:
                UrlGetterMessageBox = MessageBox("Information",
                                                 "There is a thread of urlGetter still running\nCannont open another thread",
                                                 "Information",
                                                 "Ok")
                UrlGetterMessageBox.setStandardButtons(QMessageBox.Ok)
                ret = UrlGetterMessageBox.exec()
                if ret == QMessageBox.Ok:
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

    @Slot(int)
    def openLinkInBrowser(self, index: QModelIndex):
        clicked_link = self.subdomainsModel.itemFromIndex(index).text()
        self.openLinkInBrw.emit(clicked_link)