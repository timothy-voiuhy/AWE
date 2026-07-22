import json
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
from gui.appearance import load_ui_settings
from gui.guiUtilities import HoverButton
from utilities import addHttpsScheme

_BROWSER_UA = {
    "Chrome":  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Firefox": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
}

# Persists each project's open browser-tab URLs so they can be restored the
# next time that project is opened — QtWebEngine has no built-in multi-window
# session restore of its own. Sessions are scoped per project (keyed by the
# project directory) under a "projects" map, so opening project A never
# restores project B's tabs.
_SESSION_FILE = Path(os.path.expanduser("~")) / ".config" / "awe" / "browser_session.json"


class BrowserWindow(QMainWindow):
    # Strong refs so windows spawned during session restore aren't GC'd, and
    # so we can enumerate open windows to persist their URLs.
    _instances: list = []
    # Project keys whose saved session has already been consumed this process,
    # so each project restores its tabs exactly once per launch.
    _restored_keys: set = set()
    _pending_restore_links: list = []

    def __init__(self, link=None, session_key=None) -> None:
        super().__init__()
        self.certificate_file = CERTIFICATE_FILE
        self.downloadPath = HOME_DIR+"/Downloads/"
        self.browser_cache_path = os.path.join(RUNDIR, "web_cache")
        if not Path(self.downloadPath).exists():
            os.makedirs(self.downloadPath)
        self.init_link = link
        # Identifies which project this tab belongs to for session save/restore.
        # None marks a transient window (e.g. an HTTP-response render) that must
        # neither restore nor be persisted.
        self.session_key = session_key
        # Restore this project's saved tabs once; fill in this window's link
        # only if the caller didn't request a specific one.
        restored_links = self._take_restorable_session(session_key)
        if restored_links and self.init_link is None:
            self.init_link = restored_links.pop(0)
        # Hold strong references so PySide6 GC doesn't collect them before
        # Qt processes acceptCertificate() — without this the call is a silent no-op.
        self._pending_cert_errors: list = []
        centralWidget = QWidget()
        self.setCentralWidget(centralWidget)
        self.centralWidgetLayout = QVBoxLayout()
        centralWidget.setLayout(self.centralWidgetLayout)
        self.engine_profile = self.setupProfile()
        self.browser = QWebEngineView(self.engine_profile)
        # Must pass the profile so page settings actually apply to the active page.
        self.Page = QWebEnginePage(self.engine_profile, self.browser)
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

        BrowserWindow._instances.append(self)
        # Any remaining restored URLs (beyond the one this window took) are
        # left for the caller to pop via pop_pending_restore_links() and open
        # as proper sibling tabs — spawning them as unparented windows here
        # would leave them invisible (never added to a tab widget or shown).
        BrowserWindow._pending_restore_links = restored_links

    @classmethod
    def _take_restorable_session(cls, session_key) -> list:
        # Transient windows have no project scope and never restore; each
        # project restores only once per process.
        if session_key is None or session_key in cls._restored_keys:
            return []
        cls._restored_keys.add(session_key)
        try:
            data = json.loads(_SESSION_FILE.read_text())
            projects = data.get("projects", {}) if isinstance(data, dict) else {}
            return [u for u in projects.get(str(session_key), []) if u]
        except Exception:
            return []

    @classmethod
    def pop_pending_restore_links(cls) -> list:
        """Return and clear any restored URLs not claimed by the first window."""
        links, cls._pending_restore_links = cls._pending_restore_links, []
        return links

    @classmethod
    def _save_session(cls) -> None:
        try:
            # Preserve the sessions of projects that aren't currently open …
            try:
                data = json.loads(_SESSION_FILE.read_text())
                projects = data.get("projects", {}) if isinstance(data, dict) else {}
            except Exception:
                projects = {}
            # … then overwrite entries for every project that currently has open
            # tabs with its live set of URLs (grouped by project key). Transient
            # windows (session_key is None) are never persisted.
            current: dict = {}
            for w in cls._instances:
                if w.session_key is None or not w.browser.url().isValid():
                    continue
                url = w.browser.url().toString()
                if url:
                    current.setdefault(str(w.session_key), []).append(url)
            for key, urls in current.items():
                projects[key] = urls
            _SESSION_FILE.parent.mkdir(parents=True, exist_ok=True)
            _SESSION_FILE.write_text(json.dumps({"projects": projects}))
        except Exception:
            pass

    def closeEvent(self, event) -> None:
        try:
            BrowserWindow._instances.remove(self)
        except ValueError:
            pass
        BrowserWindow._save_session()
        super().closeEvent(event)

    def trust_certificate(self):
        with open(self.certificate_file, "rb") as cert_file:
            cert_data = cert_file.read()
        self.certificate = QSslCertificate(cert_data)
        self.ssl_config = QSslConfiguration.defaultConfiguration()
        self.ssl_config.addCaCertificate(self.certificate)
        QSslConfiguration.setDefaultConfiguration(self.ssl_config)

    def browserCertificateError(self, error: QWebEngineCertificateError):
        self._pending_cert_errors.append(error)  # prevent GC before Qt reads the decision
        error.acceptCertificate()

    def setupProfile(self):
        self.profile = QWebEngineProfile.defaultProfile()
        self.profile.setPersistentCookiesPolicy(QWebEngineProfile.AllowPersistentCookies)
        _ui = load_ui_settings()
        _browser = _ui.get("browser_engine", "Chrome")
        _ua = _BROWSER_UA.get(_browser, _BROWSER_UA["Chrome"])
        self.profile.setHttpUserAgent(_ua)
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
        self._pending_cert_errors.clear()

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
        BrowserWindow._save_session()

    def AddUrlHandler(self):
        self.urlLabel = QLabel()
        self.urlLabel.setText("URL")
        self.urlText = QLineEdit()
        self.urlText.setObjectName("urlText")
        self.urlText.setPlaceholderText("Enter URL…")
        self.searchButton = QPushButton()
        self.searchButton.setText("Go")
        self.searchButton.setObjectName("searchButton")
        self.searchButton.setMinimumWidth(60)
        self.clearButton = HoverButton("✕", "clear the search area")
        self.clearButton.setObjectName("clearButton")
        self.clearButton.setFixedWidth(34)
        self.clearButton.clicked.connect(self.urlTextClear)
        self.searchButton.clicked.connect(self.handleSearchButton)
        self.urlText.returnPressed.connect(self.handleSearchButton)
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