import json
import os
from pathlib import Path

from PySide6 import QtWidgets, QtGui
from PySide6.QtCore import Qt, QPoint
from PySide6.QtNetwork import QNetworkProxy, QNetworkProxyFactory
from PySide6.QtWidgets import (
    QStackedWidget, QFrame, QVBoxLayout, QHBoxLayout, QFormLayout,
    QPushButton, QLabel, QWidget, QLineEdit, QScrollArea, QTextEdit,
    QSizePolicy, QMenu,
)

from awe_net.wappy import find_techs
from config.config import ROOT_CERT_FILE
from gui.browserWindow import BrowserWindow
from gui.certSetupDialog import CertSetupDialog
from gui.dockerManagerWindow import DockerManagerWindow
from gui.pipelineWindow import PipelineWindow
from gui.resultsWindow import ResultsWindow
from gui.leftDock import LeftDock
from gui.networkWindow import NetworkWindow
from gui.networkGraph import NetworkPage


# ── Nav definitions ───────────────────────────────────────────────────────────

_NAV = [
    ("◉",  "Browser",   "#89B4FA"),  # 0
    ("◎",  "Target",    "#CBA6F7"),  # 1
    ("⚡",  "Pipeline",  "#A6E3A1"),  # 2
    ("⬡",  "Docker",    "#89DCEB"),  # 3
    ("◈",  "Results",   "#FAB387"),  # 4
    ("⊗",  "Network",   "#94E2D5"),  # 5
    ("✎",  "Notes",     "#F38BA8"),  # 6
    ("⚙",  "Settings",  "#9399B2"),  # 7
]

_NAV_W = 58


# ── Activity-bar button ───────────────────────────────────────────────────────

class _NavButton(QPushButton):
    def __init__(self, icon: str, label: str, accent: str, parent=None):
        super().__init__(parent)
        self._accent = accent
        vb = QVBoxLayout(self)
        vb.setContentsMargins(0, 8, 0, 8)
        vb.setSpacing(2)

        self._icon_lbl = QLabel(icon)
        self._icon_lbl.setAlignment(Qt.AlignCenter)
        self._icon_lbl.setStyleSheet("font-size:18px; background:transparent; color:#6C7086;")
        vb.addWidget(self._icon_lbl)

        self._txt_lbl = QLabel(label)
        self._txt_lbl.setAlignment(Qt.AlignCenter)
        self._txt_lbl.setStyleSheet("font-size:8px; background:transparent; color:#6C7086;")
        vb.addWidget(self._txt_lbl)

        self.setFlat(True)
        self.setFixedWidth(_NAV_W)
        self.setMinimumHeight(56)
        self._set_active(False)

    def _set_active(self, active: bool):
        color = self._accent if active else "#6C7086"
        border = f"border-left:3px solid {self._accent};" if active else "border-left:3px solid transparent;"
        self.setStyleSheet(f"QPushButton {{ background:{'#1E1E2E' if active else 'transparent'}; border:none; {border} }}")
        self._icon_lbl.setStyleSheet(f"font-size:18px; background:transparent; color:{color};")
        self._txt_lbl.setStyleSheet(f"font-size:8px;  background:transparent; color:{color};")

    def set_active(self, active: bool):
        self._set_active(active)


# ── Section card helper (for settings page) ───────────────────────────────────

def _card(title: str, accent: str = "#9399B2") -> tuple[QFrame, QVBoxLayout]:
    card = QFrame()
    card.setStyleSheet(f"""
        QFrame#settingsCard {{
            background: #1E1E2E;
            border: 1px solid #313244;
            border-radius: 6px;
            border-left: 3px solid {accent};
        }}
        QLabel {{
            color: #CDD6F4;
            background: transparent;
            border: none;
            font-size: 11px;
        }}
        QPushButton {{
            background: #313244;
            color: #CDD6F4;
            border: 1px solid #45475A;
            border-radius: 5px;
            padding: 6px 16px;
            font-size: 11px;
            min-height: 28px;
            text-align: center;
        }}
        QPushButton:hover {{
            background: #45475A;
            border-color: #89B4FA;
            color: #CDD6F4;
        }}
        QPushButton:pressed {{
            background: #585B70;
            color: #CDD6F4;
        }}
        QLineEdit {{
            background: #181825;
            color: #CDD6F4;
            border: 1px solid #45475A;
            border-radius: 4px;
            padding: 4px 8px;
            font-size: 11px;
            min-height: 26px;
        }}
        QLineEdit:focus {{
            border-color: #89B4FA;
        }}
    """)
    card.setObjectName("settingsCard")
    vb = QVBoxLayout(card)
    vb.setContentsMargins(16, 14, 16, 16)
    vb.setSpacing(10)
    hdr = QLabel(title.upper())
    hdr.setStyleSheet(f"color:{accent}; font-size:9px; letter-spacing:1.5px; "
                      "background:transparent; border:none; font-weight:bold;")
    vb.addWidget(hdr)

    div = QFrame()
    div.setFrameShape(QFrame.HLine)
    div.setFixedHeight(1)
    div.setStyleSheet(f"background:{accent}; border:none; opacity:0.3;")
    vb.addWidget(div)

    return card, vb


class TargetWindow(QtWidgets.QMainWindow):
    def __init__(self, project_dir_path: str, proxy_port, top_parent, index):
        super().__init__()
        self.projectDirPath    = project_dir_path
        self.projectIndex      = index
        self.topParent         = top_parent
        self.proxy_port        = proxy_port
        self.threads           = []
        self.proxy_status      = False
        self.rootCACertificate = None
        self.main_server_name  = None
        self.target_url        = ""
        self.proxy             = QNetworkProxy()
        self._nav_btns: list[_NavButton] = []

        self.getMainSeverName()
        self.setObjectName(self.projectDirPath)
        self.setWindowTitle(self.main_server_name or os.path.basename(project_dir_path))
        self.setMenuBar(None)   # no menu bar at all

        # ── Root: nav bar | stacked content ──────────────────────────────────
        root = QWidget()
        self.setCentralWidget(root)
        root_row = QHBoxLayout(root)
        root_row.setContentsMargins(0, 0, 0, 0)
        root_row.setSpacing(0)

        root_row.addWidget(self._build_nav_bar())

        div = QFrame()
        div.setFrameShape(QFrame.VLine)
        div.setStyleSheet("color:#313244; background:#313244;")
        div.setFixedWidth(1)
        root_row.addWidget(div)

        self._stack = QStackedWidget()
        root_row.addWidget(self._stack, stretch=1)

        # Pages — order must match _NAV
        self._stack.addWidget(self._build_browser_page())   # 0 Browser
        self._stack.addWidget(self._build_target_page())    # 1 Target
        self._stack.addWidget(self._build_pipeline_page())  # 2 Pipeline
        self._stack.addWidget(self._build_docker_page())    # 3 Docker
        self._stack.addWidget(self._build_results_page())   # 4 Results
        self._stack.addWidget(self._build_network_page())   # 5 Network
        self._stack.addWidget(self._build_notes_page())     # 6 Notes
        self._stack.addWidget(self._build_settings_page())  # 7 Settings

        self._switch_page(0)
        self.topParent.newProjectCreated.emit(self)

    # ── Nav bar ───────────────────────────────────────────────────────────────

    def _build_nav_bar(self) -> QWidget:
        bar = QWidget()
        bar.setFixedWidth(_NAV_W)
        bar.setStyleSheet("background:#181825;")
        vb = QVBoxLayout(bar)
        vb.setContentsMargins(0, 4, 0, 4)
        vb.setSpacing(0)

        for i, (icon, label, accent) in enumerate(_NAV):
            btn = _NavButton(icon, label, accent)
            btn.setToolTip(label)
            btn.clicked.connect(lambda _, idx=i: self._switch_page(idx))
            vb.addWidget(btn)
            self._nav_btns.append(btn)

        vb.addStretch()
        return bar

    def _switch_page(self, index: int):
        self._stack.setCurrentIndex(index)
        for i, btn in enumerate(self._nav_btns):
            btn.set_active(i == index)

    # ── Pages ─────────────────────────────────────────────────────────────────

    def _build_browser_page(self) -> QWidget:
        page = QWidget()
        vb = QVBoxLayout(page)
        vb.setContentsMargins(0, 0, 0, 0)
        vb.setSpacing(0)

        self.browserTabWidget = QtWidgets.QTabWidget()
        self.browserTabWidget.setTabsClosable(True)
        self.browserTabWidget.tabCloseRequested.connect(self._close_browser_tab_by_index)

        # Context menu on the tab bar
        tb = self.browserTabWidget.tabBar()
        tb.setContextMenuPolicy(Qt.CustomContextMenu)
        tb.customContextMenuRequested.connect(self._browser_tab_context_menu)

        vb.addWidget(self.browserTabWidget)
        self.openNewBrowserTab()
        return page

    def _build_target_page(self) -> QWidget:
        self._leftDock = LeftDock(
            self, self.projectDirPath,
            parent=self, top_parent=self.topParent,
            embed=True,
        )
        self._leftDock.openLinkInBrw.connect(self.openNewBrowserTab)
        return self._leftDock.InitializeLeftDock()

    def _build_pipeline_page(self) -> QWidget:
        self._pipelineWindow = PipelineWindow(
            project_dir=self.projectDirPath, parent=self
        )
        return self._pipelineWindow

    def _build_docker_page(self) -> QWidget:
        self._dockerManager = DockerManagerWindow(
            parent=self, default_output_dir=self.projectDirPath
        )
        return self._dockerManager

    def _build_results_page(self) -> QWidget:
        self._resultsWindow = ResultsWindow(
            output_dir=self.projectDirPath, parent=self
        )
        return self._resultsWindow

    def _build_network_page(self) -> QWidget:
        self._networkPage = NetworkPage(
            project_dir=self.projectDirPath,
            target=self.main_server_name or "",
            parent=self,
        )
        return self._networkPage

    def _build_notes_page(self) -> QWidget:
        from PySide6.QtGui import QFont
        page = QWidget()
        vb = QVBoxLayout(page)
        vb.setContentsMargins(8, 4, 8, 8)
        vb.setSpacing(0)
        hdr = QLabel("Notes")
        hdr.setStyleSheet("color:#6C7086; font-size:10px; padding:2px 0;")
        vb.addWidget(hdr)
        self._notesEdit = QTextEdit()
        self._notesEdit.setFont(QFont("Cascadia Code", 10))
        self._notesEdit.setPlaceholderText(f"Notes for {self.main_server_name}…")
        self._notesEdit.setStyleSheet("""
            QTextEdit { background:#1E1E2E; color:#CDD6F4; border:none; padding:8px; }
        """)
        vb.addWidget(self._notesEdit)
        self._load_notes()
        self._notesEdit.textChanged.connect(self._save_notes)
        return page

    def _build_settings_page(self) -> QWidget:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setStyleSheet("""
            QScrollArea { background:#181825; border:none; }
            QScrollBar:vertical { background:#181825; width:8px; border:none; }
            QScrollBar::handle:vertical { background:#313244; border-radius:4px; min-height:20px; }
        """)

        body = QWidget()
        body.setStyleSheet("background:#181825;")
        vb = QVBoxLayout(body)
        vb.setContentsMargins(24, 20, 24, 24)
        vb.setSpacing(16)

        # ── Page header ───────────────────────────────────────────────────────
        hrow = QHBoxLayout()
        hrow.setSpacing(10)
        icon_lbl = QLabel("⚙")
        icon_lbl.setStyleSheet("color:#9399B2; font-size:22px; background:transparent;")
        hrow.addWidget(icon_lbl)
        title_lbl = QLabel(f"Settings")
        title_lbl.setStyleSheet("color:#CDD6F4; font-size:15px; font-weight:bold; background:transparent;")
        hrow.addWidget(title_lbl)
        hrow.addStretch()
        target_lbl = QLabel(self.main_server_name or "")
        target_lbl.setStyleSheet("color:#6C7086; font-size:11px; background:transparent;")
        hrow.addWidget(target_lbl)
        vb.addLayout(hrow)

        sep = QFrame(); sep.setFrameShape(QFrame.HLine)
        sep.setStyleSheet("background:#313244; border:none;"); sep.setFixedHeight(1)
        vb.addWidget(sep)

        # ── Browser card ──────────────────────────────────────────────────────
        br_card, br_vb = _card("Browser", "#CBA6F7")

        br_note = QLabel("Quick actions for the embedded browser.")
        br_note.setWordWrap(True)
        br_note.setStyleSheet("color:#6C7086; font-size:10px; background:transparent; border:none;")
        br_vb.addWidget(br_note)

        br_row = QHBoxLayout()
        br_row.setSpacing(8)

        new_tab_btn = QPushButton("◉  Open New Tab")
        new_tab_btn.setMinimumHeight(34)
        new_tab_btn.clicked.connect(self.openNewBrowserTab)
        br_row.addWidget(new_tab_btn)

        detect_btn = QPushButton("◈  Detect Technologies")
        detect_btn.setMinimumHeight(34)
        detect_btn.clicked.connect(self.runWappalzer)
        br_row.addWidget(detect_btn)

        net_btn = QPushButton("⊗  Network")
        net_btn.setMinimumHeight(34)
        net_btn.clicked.connect(lambda: self._switch_page(5))
        br_row.addWidget(net_btn)

        br_vb.addLayout(br_row)
        vb.addWidget(br_card)

        # ── Proxy card ────────────────────────────────────────────────────────
        proxy_card, proxy_vb = _card("Proxy", "#89B4FA")

        self._proxyStatusLbl = QLabel()
        proxy_vb.addWidget(self._proxyStatusLbl)

        # Host / port row
        field_row = QHBoxLayout()
        field_row.setSpacing(12)

        host_col = QVBoxLayout()
        host_col.setSpacing(4)
        host_lbl = QLabel("Host")
        host_lbl.setStyleSheet("color:#6C7086; font-size:10px; background:transparent; border:none;")
        host_col.addWidget(host_lbl)
        self._proxyHostEdit = QLineEdit("127.0.0.1")
        host_col.addWidget(self._proxyHostEdit)
        field_row.addLayout(host_col, stretch=3)

        port_col = QVBoxLayout()
        port_col.setSpacing(4)
        port_lbl = QLabel("Port")
        port_lbl.setStyleSheet("color:#6C7086; font-size:10px; background:transparent; border:none;")
        port_col.addWidget(port_lbl)
        self._proxyPortEdit = QLineEdit(str(self.proxy_port))
        port_col.addWidget(self._proxyPortEdit)
        field_row.addLayout(port_col, stretch=1)

        proxy_vb.addLayout(field_row)

        self._proxyToggleBtn = QPushButton("Enable Proxy")
        self._proxyToggleBtn.setMinimumHeight(34)
        self._proxyToggleBtn.clicked.connect(self._toggle_proxy_from_settings)
        proxy_vb.addWidget(self._proxyToggleBtn)

        vb.addWidget(proxy_card)
        self._refresh_proxy_status()

        # ── Certificate card ──────────────────────────────────────────────────
        cert_card, cert_vb = _card("Certificate", "#A6E3A1")

        self._certStatusLbl = QLabel()
        cert_vb.addWidget(self._certStatusLbl)

        cert_note = QLabel(
            "AWE uses a local CA certificate to intercept HTTPS traffic. "
            "Generate it once, then trust it in your OS and browser."
        )
        cert_note.setWordWrap(True)
        cert_note.setStyleSheet("color:#6C7086; font-size:10px; background:transparent; border:none;")
        cert_vb.addWidget(cert_note)

        cert_btn = QPushButton("🔒  Open Certificate Setup…")
        cert_btn.setMinimumHeight(34)
        cert_btn.clicked.connect(self.OpenCertSetup)
        cert_vb.addWidget(cert_btn)

        vb.addWidget(cert_card)
        self._refresh_cert_status()

        vb.addStretch()
        scroll.setWidget(body)
        return scroll

    # ── Browser tab context menu ──────────────────────────────────────────────

    def _browser_tab_context_menu(self, pos: QPoint):
        menu = QMenu(self)
        menu.setStyleSheet("""
            QMenu {
                background:#1E1E2E; color:#CDD6F4;
                border:1px solid #313244; border-radius:4px;
            }
            QMenu::item:selected { background:#313244; }
            QMenu::separator { background:#313244; height:1px; margin:2px 8px; }
        """)

        new_act   = menu.addAction("◉  New Tab")
        close_act = menu.addAction("✕  Close Tab")
        menu.addSeparator()

        proxy_label = "⊘  Disable Proxy" if self.proxy_status else "⚡  Enable Proxy"
        proxy_act   = menu.addAction(proxy_label)
        cert_act    = menu.addAction("🔒  Certificate Setup…")
        menu.addSeparator()

        tech_act    = menu.addAction("◈  Detect Technologies")
        net_act     = menu.addAction("⊗  Network Monitor")

        chosen = menu.exec(self.browserTabWidget.tabBar().mapToGlobal(pos))
        if chosen == new_act:
            self.openNewBrowserTab()
        elif chosen == close_act:
            self.closeBrowserTab()
        elif chosen == proxy_act:
            self.HandleProxy()
        elif chosen == cert_act:
            self.OpenCertSetup()
        elif chosen == tech_act:
            self.runWappalzer()
        elif chosen == net_act:
            self.OpenNetworkWindow()

    # ── Status helpers ────────────────────────────────────────────────────────

    def _refresh_cert_status(self):
        exists = Path(ROOT_CERT_FILE).exists()
        dot    = "●" if exists else "○"
        color  = "#A6E3A1" if exists else "#F38BA8"
        text   = "Installed" if exists else "Not installed"
        self._certStatusLbl.setText(
            f"<span style='color:{color};'>{dot}</span>"
            f"<span style='color:#CDD6F4;'>&nbsp; {text}</span>"
        )

    def _refresh_proxy_status(self):
        dot   = "●" if self.proxy_status else "○"
        color = "#A6E3A1" if self.proxy_status else "#F38BA8"
        text  = f"Enabled — {self._proxyHostEdit.text()}:{self._proxyPortEdit.text()}" \
                if self.proxy_status else "Disabled"
        self._proxyStatusLbl.setText(
            f"<span style='color:{color};'>{dot}</span>"
            f"<span style='color:#CDD6F4;'>&nbsp; {text}</span>"
        )
        self._proxyToggleBtn.setText("Disable Proxy" if self.proxy_status else "Enable Proxy")

    def _toggle_proxy_from_settings(self):
        try:
            self.proxy_port = int(self._proxyPortEdit.text())
        except ValueError:
            self._proxyPortEdit.setStyleSheet(
                "QLineEdit { border:1px solid #F38BA8; background:#181825; "
                "color:#CDD6F4; border-radius:4px; padding:2px 6px; }")
            return
        self.HandleProxy()
        self._refresh_proxy_status()

    # ── Public API ────────────────────────────────────────────────────────────

    def OpenPipelineWindow(self):
        self._switch_page(2)

    def OpenDockerManager(self):
        self._switch_page(3)

    def OpenResultsWindow(self):
        self._switch_page(4)

    def OpenNetworkWindow(self):
        self._switch_page(5)

    def OpenTestTargetWindow(self):
        self._switch_page(5)   # redirects to Network (Tools removed)

    def OpenCertSetup(self):
        dlg = CertSetupDialog(self)
        dlg.exec()
        self._refresh_cert_status()

    # ── Browser ───────────────────────────────────────────────────────────────

    def openNewBrowserTab(self, link=None):
        tab_name = "new"
        bw = None
        try:
            if isinstance(link, bool) or link is None:
                bw = BrowserWindow("google.com")
            else:
                bw = BrowserWindow(link)
                tab_name = link.split("//")[-1].split("/")[0].split(".")[0] or "new"
        except Exception:
            bw = BrowserWindow("google.com")
        if bw:
            self.browserTabWidget.addTab(bw, tab_name)
            self.browserTabWidget.setCurrentWidget(bw)
            self._switch_page(0)

    def _close_browser_tab_by_index(self, index: int):
        if index > 0:
            self.browserTabWidget.removeTab(index)

    def closeBrowserTab(self):
        self._close_browser_tab_by_index(self.browserTabWidget.currentIndex())

    def runWappalzer(self):
        try:
            url  = self.browserTabWidget.currentWidget().browser.url().url()
            data = find_techs(url)
            from PySide6.QtWidgets import QDialog, QTextBrowser
            dlg = QDialog(self)
            dlg.setWindowTitle("Detected Technologies")
            dlg.resize(500, 400)
            tb = QTextBrowser(dlg)
            tb.setText(data)
            QVBoxLayout(dlg).addWidget(tb)
            dlg.exec()
        except Exception:
            pass

    def showdevTools(self):
        pass

    # ── Proxy ─────────────────────────────────────────────────────────────────

    def HandleProxy(self):
        if not self.proxy_status:
            if not Path(ROOT_CERT_FILE).exists():
                self.OpenCertSetup()
                if not Path(ROOT_CERT_FILE).exists():
                    return
            self.proxy.setType(QNetworkProxy.HttpProxy)
            self.proxy.setHostName("127.0.0.1")
            self.proxy.setPort(self.proxy_port)
            QNetworkProxy.setApplicationProxy(self.proxy)
            self.proxy_status = True
        else:
            QNetworkProxyFactory.setUseSystemConfiguration(True)
            self.proxy_status = False

    def enableProxy(self, use_default=False):
        self.proxy.setType(QNetworkProxy.HttpProxy)
        self.proxy.setHostName("127.0.0.1")
        self.proxy.setPort(self.proxy_port)
        QNetworkProxy.setApplicationProxy(self.proxy)

    # ── Notes ─────────────────────────────────────────────────────────────────

    def _notes_path(self) -> str:
        return os.path.join(self.projectDirPath, "notes.md")

    def _load_notes(self):
        p = self._notes_path()
        if os.path.exists(p):
            try:
                with open(p) as f:
                    self._notesEdit.setPlainText(f.read())
            except Exception:
                pass

    def _save_notes(self):
        try:
            with open(self._notes_path(), "w") as f:
                f.write(self._notesEdit.toPlainText())
        except Exception:
            pass

    # ── Project metadata ──────────────────────────────────────────────────────

    def getMainSeverName(self):
        meta_path = os.path.join(self.projectDirPath, "project.json")
        if os.path.exists(meta_path):
            try:
                with open(meta_path) as fh:
                    meta = json.load(fh)
                self.main_server_name = meta.get("target") or meta.get("target_url") or ""
                self.target_url = meta.get("target_url", "")
                return
            except Exception:
                pass
        self.main_server_name = self.projectDirPath.rstrip("/").split("/")[-1]
        self.target_url = ""

    def closeEvent(self, event: QtGui.QCloseEvent) -> None:
        self.topParent.projectClosed.emit(self, self.projectIndex)
        return super().closeEvent(event)

    # ── Legacy stubs ──────────────────────────────────────────────────────────

    def AddTopMenu(self):   pass
    def ViewTarget(self):   self._switch_page(1)
    def ViewTerminal(self): pass
    def ViewNotepad(self):  self._switch_page(6)  # Notes
