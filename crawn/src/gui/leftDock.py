import json
import logging
import os
from pathlib import Path

from PySide6.QtCore import QObject, Signal, Qt, QModelIndex, Slot, QThread
from PySide6.QtGui import QStandardItem, QStandardItemModel
from PySide6.QtWidgets import QMainWindow, QMessageBox, QDockWidget, QWidget, QVBoxLayout, QFormLayout, QCheckBox, \
    QFrame, QLabel, QHBoxLayout, QPushButton, QTreeView, QScrollArea, QTextBrowser, QSplitter, QTableWidget, QTableView

from gui.functionUtils import atomGuiGetSubdomains, atomGuiGetUrls
from gui.guiUtilities import MessageBox, HoverButton
from utiliities import red, rm_same, yellow, runWhoisOnTarget


class UrlGetter(QThread, QObject):
    urlGetterFinished = Signal()

    def __init__(self, subdomain_url_dict: dict,
                 working_dir,
                 parent=None,
                 dict_parent=None,
                 top_parent=None,
                 main_window=None):
        super().__init__()
        self.setObjectName("UrlGetter")
        self.mainWindow = main_window
        self.topParent = top_parent
        self.subdomainUrlDict = subdomain_url_dict
        self.workingDir = working_dir
        self.subdomainsUrlDict_ = {}
        self.parent = parent
        self.dictParent = dict_parent
        self.receivedSignals = 0
        self.subdomainsUrlDict_file = os.path.join(working_dir, "subdomainsUrlDict.json")
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
                                    parent=self.parent,
                                    top_parent=self.topParent,
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
            if os.cpu_count() <= 4:
                self.sleep(5)
            elif 8 >= os.cpu_count() > 4:
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


class LeftDock(QObject):
    openLinkInBrw = Signal(str)

    def __init__(self, main_window,
                 project_dir_path,
                 parent=None,
                 top_parent=None,
                 ) -> None:
        super().__init__()
        self.whois_text_results = None
        self.topParent = top_parent
        self.urlGetterRunning = False
        self.main_window = main_window
        self.projectDirPath = project_dir_path
        self.SubdomainUrlDict = {}
        self.SubdomainUrlDict_file = os.path.join(self.projectDirPath, "subdomainsUrlDict.json")
        self.parent = parent
        self.topParent.socketIpc.processFinishedExecution.connect(self.updateModel)

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
        self.left_dock_layout = QVBoxLayout()
        self.leftDockWidget.setLayout(self.left_dock_layout)

        self.left_dock_splitter = QSplitter()
        self.left_dock_layout.addWidget(self.left_dock_splitter)
        # self.left_dock_splitter.
        self.left_dock_splitter.setLayoutDirection(Qt.LayoutDirection.LeftToRight)

        self.left_dock_up_widget = QWidget()
        # self.left_dock_up_widget.setBaseSize(100, 600)
        self.left_dock_splitter.addWidget(self.left_dock_up_widget)
        self.left_dock_up_widget_layout = QVBoxLayout()
        self.left_dock_up_widget.setLayout(self.left_dock_up_widget_layout)

        # general information scroll area
        self.gen_info_scroll_area = QScrollArea()
        self.left_dock_up_widget_layout.addWidget(self.gen_info_scroll_area)
        self.gen_info_scroll_bar_widget = QWidget()
        self.gen_info_scroll_bar_wid_layout = QVBoxLayout()
        self.gen_info_scroll_bar_widget.setLayout(self.gen_info_scroll_bar_wid_layout)
        self.gen_info_scroll_area.setWidget(self.gen_info_scroll_bar_widget)
        self.gen_info_scroll_area.setWidgetResizable(True)

        # hide or show gen info checkbox
        self.infoshowLayout = QFormLayout()
        self.infoShowCheckBox = QCheckBox()
        self.infoShowCheckBox.setChecked(True)
        self.infoShowCheckBox.stateChanged.connect(self.hideGenInfo)
        self.infoshowLayout.addRow("hide info", self.infoShowCheckBox)
        self.gen_info_scroll_bar_wid_layout.addLayout(self.infoshowLayout)

        # general information frame and layout
        self.general_information_frame = QFrame()
        self.gen_info_scroll_bar_wid_layout.addWidget(self.general_information_frame)
        self.general_information_layout = QFormLayout()
        self.general_information_frame.setLayout(self.general_information_layout)
        self.general_information_frame.setHidden(True)

        # rows (static information)
        self.urlTargetName = QLabel("main server: ")
        self.urlName = QLabel(self.main_window.main_server_name)
        self.general_information_layout.addRow(self.urlTargetName, self.urlName)
        self.numberOfSubdomains = QLabel("nSubdomains")
        self.nSubd = QLabel("0")
        self.amassSdCount = QLabel(" =>Amass:")
        self.amassSdCountLabel = QLabel("0")
        self.subdomainizerSdCount = QLabel(" =>subdomainizer:")
        self.subdomainizerSdCountLabel = QLabel("0")
        self.sublist3rSdCount = QLabel(" =>sublist3r:")
        self.sublist3rSdCountLabel = QLabel("0")
        self.general_information_layout.addRow(self.numberOfSubdomains, self.nSubd)
        self.numberOfUrls = QLabel("nUrls")
        self.nUrls = QLabel("0")
        self.general_information_layout.addRow(self.amassSdCount, self.amassSdCountLabel)
        self.general_information_layout.addRow(
            self.subdomainizerSdCount, self.subdomainizerSdCountLabel
        )
        self.general_information_layout.addRow(
            self.sublist3rSdCount, self.sublist3rSdCountLabel
        )
        self.general_information_layout.addRow(self.numberOfUrls, self.nUrls)

        # whois
        self.whois_label = QLabel()
        self.whois_label.setText("<b>whois results<b/>")
        self.gen_info_scroll_bar_wid_layout.addWidget(self.whois_label, alignment=Qt.AlignLeft)
        self.whois_frame = QFrame()
        self.whois_frame.setMaximumWidth(800)
        self.whois_frame_layout = QVBoxLayout()
        self.whois_frame.setLayout(self.whois_frame_layout)
        self.run_whois_button = HoverButton("run whois", "run the whois tool on the target")
        self.run_whois_button.clicked.connect(self.run_whois)
        self.whois_frame_layout.addWidget(self.run_whois_button, alignment=Qt.AlignLeft)
        self.whois_text_widget = QTextBrowser()
        # self.whois_text_widget.setFixedWidth(800)
        self.whois_text_widget.setMaximumWidth(800)
        self.whois_text_widget.setReadOnly(True)
        self.whois_frame_layout.addWidget(self.whois_text_widget)
        self.gen_info_scroll_bar_wid_layout.addWidget(self.whois_frame, alignment=Qt.AlignLeft)

        # location
        self.location_label = QLabel()
        self.location_label.setText("<b>server locations</b>")
        self.generate_table_button = HoverButton("Generate Table", "generate the summary as a table")
        self.generate_table_button.clicked.connect(self.draw_location_table)
        self.gen_info_scroll_bar_wid_layout.addWidget(self.location_label, alignment=Qt.AlignLeft)
        self.gen_info_scroll_bar_wid_layout.addWidget(self.generate_table_button, alignment=Qt.AlignLeft)

        # ip:server_name:name_record:geo_location => table
        self.location_table = QTableWidget()
        self.gen_info_scroll_bar_wid_layout.addWidget(self.location_table)
        # self.draw_location_table()

        # dns severs

        # dynamic information
        self.left_dock_down_widget = QWidget()
        self.left_dock_splitter.addWidget(self.left_dock_down_widget)
        self.left_dock_down_widget_layout = QVBoxLayout()
        self.left_dock_down_widget.setLayout(self.left_dock_down_widget_layout)

        self.USlayout = QHBoxLayout()
        self.left_dock_down_widget_layout.addLayout(self.USlayout)
        # show subdomains button
        self.subdomainsButton = HoverButton("SubdUrlTree", "show the subdomain url tree")
        self.subdomainsButton.clicked.connect(showSbdUrlTree)
        self.USlayout.addWidget(self.subdomainsButton)
        # show urls Button
        self.urlsButton = HoverButton("UrlsScan", "scan all the subdomains for endpoints(urls)")
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
        self.left_dock_down_widget_layout.addWidget(self.subdomainsTreeView)

    def InitializeLeftDock(self):
        return self.leftDock

    def draw_location_table(self):
        self.location_table.setColumnCount(4)
        # self.location_table.colum
        # self.location_table.setRowCount()

    def run_whois(self):
        self.whois_text_results = runWhoisOnTarget(self.main_window.main_server_name, self.projectDirPath)
        self.whois_text_widget.setText(self.whois_text_results.decode("utf-8"))

    def hideGenInfo(self):
        if self.infoShowCheckBox.isChecked():
            self.general_information_frame.setHidden(True)
        else:
            self.general_information_frame.setHidden(False)

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
                                            main_window=self.main_window)
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
