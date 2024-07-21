import logging
import os
from pathlib import Path

from PySide6 import QtWebEngineWidgets
from PySide6.QtCore import QUrl
from PySide6.QtWebEngineCore import QWebEnginePage, QWebEngineSettings, QWebEngineCertificateError, QWebEngineProfile
from PySide6.QtWidgets import QWidget, QVBoxLayout, QMainWindow, QHBoxLayout, QLabel, QLineEdit, QPushButton, \
    QProgressBar

from config.config import RUNDIR
from gui.guiUtilities import HoverButton
from utiliities import addHttpsScheme


class BrowserWindow(QMainWindow):
    def __init__(self, link=None) -> None:
        super().__init__()
        self.ca_certs_file = RUNDIR + "src/proxycert/CA/certificate.crt"
        self.downloadPath = RUNDIR + "WebEngineDownloads/"
        if not Path(self.downloadPath).exists():
            os.makedirs(self.downloadPath)
        self.init_link = link
        centralWidget = QWidget()
        self.setCentralWidget(centralWidget)

        self.centralWidgetLayout = QVBoxLayout()
        centralWidget.setLayout(self.centralWidgetLayout)

        self.browser = QtWebEngineWidgets.QWebEngineView()
        self.Page = QWebEnginePage()
        self.Page.certificateError.connect(self.browserCertificateError)
        # self.Page.setProperty()
        self.browser.setPage(self.Page)

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

        self.upperUrlHandlerLayout = QHBoxLayout()
        self.centralWidgetLayout.addLayout(self.upperUrlHandlerLayout)

        self.lowerCentralLayout = QHBoxLayout()
        self.centralWidgetLayout.addLayout(self.lowerCentralLayout)
        self.AddUrlHandler()

        self.lowerCentralLayout.addWidget(self.browser)
        # self.browser.createStandardContextMenu()
        if self.init_link == None:
            self.browser.setUrl(QUrl("http://google.com/"))
        else:
            self.searchUrlOnBrowser(self.init_link)

    def browserCertificateError(self, error: QWebEngineCertificateError):
        error.acceptCertificate()

    def setupProfile(self):
        self.profile = QWebEngineProfile.defaultProfile()
        self.profile.httpCacheType(QWebEngineProfile.MemoryHttpCache)
        self.profile.setPersistentCookiesPolicy(QWebEngineProfile.NoPersistentCookies)
        self.profile.setHttpUserAgent(
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")
        self.profile.setDownloadPath(self.downloadPath)

    def closeProgressBarWidget(self):
        self.browserProgressBar.setVisible(False)

    # @Slot(int)
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
        self.urlLabel = QLabel()
        self.urlLabel.setText("Url:")
        self.urlText = QLineEdit()
        self.searchButton = QPushButton()
        self.searchButton.setText("search")
        self.clearButton = HoverButton("X", "clear the search area")
        self.clearButton.setFixedWidth(32)
        self.clearButton.clicked.connect(self.urlTextClear)
        self.searchButton.clicked.connect(self.handleSearchButton)
        self.browserProgressBar = QProgressBar()
        self.browserProgressBar.setVisible(False)
        self.browserProgressBar.setFormat("Loading")
        self.upperUrlHandlerLayout.addWidget(self.urlLabel)
        self.upperUrlHandlerLayout.addWidget(self.urlText)
        self.upperUrlHandlerLayout.addWidget(self.searchButton)
        self.upperUrlHandlerLayout.addWidget(self.clearButton)
        self.upperUrlHandlerLayout.addWidget(self.browserProgressBar)

    def urlTextClear(self):
        self.urlText.clear()

    def searchUrlOnBrowser(self, link: str):
        self.browser.setUrl(QUrl(addHttpsScheme(link)))
        self.QbrowserURL = self.browser.url()
        self.strUrl = self.QbrowserURL.url()
        self.urlText.setText(self.strUrl)

    def handleSearchButton(self):
        self.target_url = self.urlText.text()
        logging.debug(self.target_url)
        self.target_url = addHttpsScheme(self.target_url)
        # logging.info(f"using url : {self.target_url}")
        self.browser.setUrl(QUrl(self.target_url))
        self.QbrowserURL = self.browser.url()
        self.strUrl = self.QbrowserURL.url()
        self.urlText.setText(self.strUrl)