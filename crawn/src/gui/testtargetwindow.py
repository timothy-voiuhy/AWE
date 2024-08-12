import asyncio
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
import os
from pathlib import Path
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QMainWindow, QMessageBox, QWidget, QVBoxLayout, QTabWidget, QFormLayout, QLineEdit, \
    QLabel, QCheckBox, QPushButton

from atomcore import RunMainAtomFunction
from gui.guiUtilities import HoverButton
from gui.threadrunners import Sublist3rThreadRunner, SubdomainizerThreadRunner, AmassThreadRunner


class TestTargetWindow(QMainWindow):
    def __init__(self, projectDirPath, parent, top_parent) -> None:
        super().__init__()
        self.setWindowTitle("Test Target")
        self.parent = parent
        self.main_window = self.parent
        self.useHttp = False
        self.useBrowser = False
        self.runAmass = False
        self.subliterBruteForce = False
        self.sublisterScanPorts = False
        self.sublisterUseSearchEngines = False
        self.projectDirPath = projectDirPath
        self.top_parent = top_parent
        self.amass_run_file = os.path.join(self.projectDirPath, "amass_.txt")

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
                self.sublisterFailRunMessageBox = QMessageBox()
                self.sublisterFailRunMessageBox.setWindowTitle("Warning")
                self.sublisterFailRunMessageBox.setText(
                    "Sublister has a problem running!! \nThis can be due to invalid args \nor a faulty internet connection\nDo you want to run it again"
                )
                self.sublisterFailRunMessageBox.setIcon(QMessageBox.Warning)
                self.sublisterFailRunMessageBox.setStandardButtons(
                    QMessageBox.Ok)
                ret = self.sublisterFailRunMessageBox.exec()
                if ret == QMessageBox.Ok:
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
                self.amassUrlTarget.text(), self.projectDirPath, self.main_window, self.top_parent)
            self.amassRunner.setObjectName("AmassRunner")
            self.parent.threads.append(self.amassRunner)
            self.amassRunner.start()
            # amassRunner.run()
        
        def runAmassParse():
            self.amass_runner = AmassThreadRunner(amassUrlTarget=None, projectDirPath=self.projectDirPath,main_window=self.main_window, only_parse_data= True, top_parent=self.top_parent)
            self.amass_runner.setObjectName("AmassRunner")
            self.parent.threads.append(self.amass_runner)
            self.amass_runner.start()

        self.centralWidget = QWidget()
        self.setCentralWidget(self.centralWidget)

        self.centralWidgetLayout = QVBoxLayout()
        self.centralWidget.setLayout(self.centralWidgetLayout)
        # tab manager
        self.tabManager = QTabWidget()
        # atom tab
        self.atomRunner = QWidget()
        self.atomRunnerLayout = QVBoxLayout()
        self.atomRunner.setLayout(self.atomRunnerLayout)
        # options layout
        self.atomRunnerOptionsLayout = QFormLayout()
        self.atomUrlTarget = QLineEdit()
        self.atomUrlLabel = QLabel("Target url: ")
        self.atomUseHttp = QLabel("Use Http: ")
        self.atomUseHttpCheckBox = QCheckBox()
        self.atomUseHttpCheckBox.stateChanged.connect(self.registerUseHttp)
        self.atomUseBrowser = QLabel("Use Browser: ")
        self.atomUseBrowserCheckBox = QCheckBox()
        self.atomUseBrowserCheckBox.stateChanged.connect(self.registerUseBrowser)
        self.atomRunAmass = QLabel("Run Amass")
        self.atomRunAmassCheckBox = QCheckBox()
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
        self.atomRunButton = QPushButton()
        self.atomRunButton.setText("Run Atom")
        self.atomRunButton.clicked.connect(self.runAtom)
        self.atomRunnerLayout.addWidget(self.atomRunButton)
        # add tab atom runner to testing window
        self.tabManager.addTab(self.atomRunner, "Atom")

        # amass tab
        self.amassRunner = QWidget()
        self.amassRunnerLayout = QVBoxLayout()
        self.amassRunner.setLayout(self.amassRunnerLayout)
        # # options layout
        self.amassRunnerOptionsLayout = QFormLayout()
        self.amassUrlTarget = QLineEdit()
        self.amassUrlLabel = QLabel("Target domain: ")
        # add options to options layout
        self.amassRunnerOptionsLayout.addRow(self.amassUrlLabel, self.amassUrlTarget)
        # add form layout to vbox layout
        self.amassRunnerLayout.addLayout(self.amassRunnerOptionsLayout)

        if Path(self.amass_run_file).exists():
            self.data_file_exists_label = QLabel()
            self.data_file_exists_label.setText("<b>data file exits</b>")
            self.amassRunnerLayout.addWidget(self.data_file_exists_label, alignment=Qt.AlignLeft)

            self.amass_parse_data_button = HoverButton("parse data", "parse the amass data in the data file")
            self.amass_parse_data_button.clicked.connect(runAmassParse)
            self.amassRunnerLayout.addWidget(self.amass_parse_data_button, alignment=Qt.AlignLeft)

        # run Button
        self.amassRunButton = QPushButton()
        self.amassRunButton.setText("Run Amass")
        self.amassRunButton.clicked.connect(runAmass)
        self.amassRunButton.setFixedWidth(80)
        self.amassRunnerLayout.addWidget(self.amassRunButton)
        self.amassRunnerLayout.setAlignment(Qt.AlignTop)

        self.tabManager.addTab(self.amassRunner, "Amass")

        # SubDomainizerRunner
        self.subDomainizerRunner = QWidget()
        self.subDomainizerRunnerLayout = QVBoxLayout()
        self.subDomainizerRunner.setLayout(self.subDomainizerRunnerLayout)
        # # options layout
        self.subDomainizerRunnerOptionsLayout = QFormLayout()
        self.subDomainizerUrlTarget = QLineEdit()
        self.subDomainizerUrlLabel = QLabel("Target domain: ")
        # add options to options layout
        self.subDomainizerRunnerOptionsLayout.addRow(
            self.subDomainizerUrlLabel, self.subDomainizerUrlTarget
        )
        # add form layout to vbox layout
        self.subDomainizerRunnerLayout.addLayout(self.subDomainizerRunnerOptionsLayout)
        # run Button
        self.subDomainizerRunButton = QPushButton()
        self.subDomainizerRunButton.setText("Run subDomainizer")
        self.subDomainizerRunButton.clicked.connect(runsubDomainizer)
        self.subDomainizerRunnerLayout.addWidget(self.subDomainizerRunButton)

        self.tabManager.addTab(self.subDomainizerRunner, "subdomainizer")

        # SubDomainizerRunner
        self.sublist3rRunner = QWidget()
        self.sublist3rRunnerLayout = QVBoxLayout()
        self.sublist3rRunner.setLayout(self.sublist3rRunnerLayout)
        # # options layout
        self.sublist3rRunnerOptionsLayout = QFormLayout()
        self.sublist3rUrlTarget = QLineEdit()
        self.sublist3rUrlLabel = QLabel("Target domain: ")
        self.sublist3rBruteForceLabel = QLabel()
        self.sublist3rBruteForceLabel.setText("Allow BruteForce")
        self.sublist3rBruteforcebutton = QCheckBox()
        self.sublist3rBruteforcebutton.stateChanged.connect(
            self.registerSubliterBruteforceButton
        )
        self.sublist3rUseSearchEngniesCheckBox = QCheckBox()
        self.sublist3rUseSearchEngniesCheckBox.stateChanged.connect(
            self.registerSublisterUseSearchEngines
        )
        self.sublist3rUseSearchEnginesLabel = QLabel()
        self.sublist3rUseSearchEnginesLabel.setText("Use SearchEngines:")
        self.sublist3rSearchEnginesLabel = QLabel()
        self.sublist3rSearchEnginesLabel.setText("SearchEngines:")
        self.sublist3rSearchEngines = QLineEdit()
        self.sublist3rSearchEngines.setHidden(True)
        self.sublist3rSearchEngines.setPlaceholderText(
            "write comma separated values of search engines"
        )
        self.sublist3rScanPortsLabel = QLabel()
        self.sublist3rScanPortsLabel.setText("Scan Ports")
        self.sublist3rScanPortsCheckBox = QCheckBox()
        self.sublist3rScanPortsCheckBox.stateChanged.connect(
            self.registerSublisterScanPorts
        )
        self.sublist3rPortsLabel = QLabel()
        self.sublist3rPortsLabel.setText("Ports:")
        self.sublist3rPorts = QLineEdit()
        self.sublist3rPorts.setPlaceholderText(
            "write command separated values of ports"
        )
        self.sublist3rPorts.setVisible(False)
        self.sublist3rThreadsLabel = QLabel()
        self.sublist3rThreadsLabel.setText("Number of threads")
        self.sublist3rThreads = QLineEdit()
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
        self.sublist3rRunButton = QPushButton()
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