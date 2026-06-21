import logging
import os
from pathlib import Path

from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtCore import QUrl, QFileInfo
from PySide6.QtNetwork import QSslCertificate, QSslConfiguration
from PySide6.QtWebEngineCore import QWebEnginePage, QWebEngineSettings, QWebEngineCertificateError, QWebEngineProfile, QWebEngineDownloadRequest
from PySide6.QtWidgets import QWidget, QVBoxLayout, QMainWindow, QHBoxLayout, QLabel, QLineEdit, QPushButton, \
    QProgressBar, QFileDialog
from PySide6.QtGui import QAction
from config.config import HOME_DIR, RUNDIR, CERTIFICATE_FILE
from gui.guiUtilities import HoverButton
from utiliities import addHttpsScheme


class BrowserWindow(QMainWindow):
    def __init__(self, link=None) -> None:
        super().__init__()
        self.certificate_file = CERTIFICATE_FILE
        self.downloadPath = HOME_DIR+"/Downloads/"
        self.browser_cache_path = os.path.join(RUNDIR, "web_cache")
        if not Path(self.downloadPath).exists():
            os.makedirs(self.downloadPath)
        self.init_link = link
        centralWidget = QWidget()
        self.setCentralWidget(centralWidget)
        self.centralWidgetLayout = QVBoxLayout()
        centralWidget.setLayout(self.centralWidgetLayout)
        self.engine_profile = self.setupProfile()
        self.browser = QWebEngineView(self.engine_profile)
        self.Page = QWebEnginePage()
        # Configure WebEngine for software rendering
        self.Page.settings().setAttribute(QWebEngineSettings.WebAttribute.WebGLEnabled, False)
        self.Page.settings().setAttribute(QWebEngineSettings.WebAttribute.Accelerated2dCanvasEnabled, False)
        self.Page.settings().setAttribute(QWebEngineSettings.WebAttribute.AutoLoadIconsForPage, False)
        self.Page.settings().setAttribute(QWebEngineSettings.WebAttribute.ShowScrollBars, True)
        self.Page.certificateError.connect(self.browserCertificateError)
        self.browser.setPage(self.Page)
        self.trust_certificate()
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

    def trust_certificate(self):
        with open(self.certificate_file, "rb") as cert_file:
            cert_data = cert_file.read()
        self.certificate = QSslCertificate(cert_data)
        self.ssl_config = QSslConfiguration.defaultConfiguration()
        self.ssl_config.addCaCertificate(self.certificate)
        QSslConfiguration.setDefaultConfiguration(self.ssl_config)

    def browserCertificateError(self, error: QWebEngineCertificateError):
        error.acceptCertificate()

    def setupProfile(self):
        self.profile = QWebEngineProfile.defaultProfile()
        self.profile.setPersistentCookiesPolicy(QWebEngineProfile.AllowPersistentCookies)
        self.profile.setHttpUserAgent("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")
        self.profile.setDownloadPath(self.downloadPath)
        # self.profile.setPersistentStoragePath(self.downloadPath)
        self.profile.settings().setAttribute(QWebEngineSettings.WebAttribute.ForceDarkMode, True)
        self.profile.settings().setAttribute(QWebEngineSettings.WebAttribute.PluginsEnabled, True)
        # Disable GPU-accelerated features
        self.profile.settings().setAttribute(QWebEngineSettings.WebAttribute.WebGLEnabled, False)
        self.profile.settings().setAttribute(QWebEngineSettings.WebAttribute.Accelerated2dCanvasEnabled, False)
        self.profile.settings().setAttribute(QWebEngineSettings.WebAttribute.JavascriptCanAccessClipboard, True)
        self.profile.settings().setAttribute(QWebEngineSettings.WebAttribute.JavascriptEnabled, True)
        self.profile.settings().setAttribute(QWebEngineSettings.WebAttribute.JavascriptCanOpenWindows, True)
        self.profile.settings().setAttribute(QWebEngineSettings.WebAttribute.PdfViewerEnabled, True)
        self.profile.settings().setAttribute(QWebEngineSettings.WebAttribute.LocalStorageEnabled, True)
        # Disable animations and fancy features that might cause rendering issues
        self.profile.settings().setAttribute(QWebEngineSettings.WebAttribute.ScrollAnimatorEnabled, False)
        self.profile.downloadRequested.connect(self.handleDownload)
        # self.profile.setCachePath(self.browser_cache_path)
        # self.profile.httpCacheType(QWebEngineProfile.MemoryHttpCache)
        return self.profile

    def handleDownload(self, download:QWebEngineDownloadRequest):
        old_path = download.url().path()  # download.path()
        suffix = QFileInfo(old_path).suffix()
        path, _ = QFileDialog.getSaveFileName(self, "Save File", old_path, "*." + suffix)
        if path:
            download.setDownloadFileName(path)
            download.accept()

    def handleDownloadProgressBar(self, download:QWebEngineDownloadRequest):
        total_bytes = download.totalBytes()
        download.receivedBytesChanged(self.showdownoadProgress)

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
        self.urlLabel.setText("URL")
        self.urlText = QLineEdit()
        self.urlText.setObjectName("urlText")
        self.urlText.setPlaceholderText("Enter URL…")
        self.searchButton = QPushButton()
        self.searchButton.setText("Go")
        self.searchButton.setObjectName("searchButton")
        self.clearButton = HoverButton("✕", "clear the search area")
        self.clearButton.setObjectName("clearButton")
        self.clearButton.setFixedWidth(34)
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
        self.target_url = addHttpsScheme(self.target_url)
        # logging.info(f"using url : {self.target_url}")
        self.browser.setUrl(QUrl(self.target_url))
        self.QbrowserURL = self.browser.url()
        self.strUrl = self.QbrowserURL.url()
        self.urlText.setText(self.strUrl)