import json
import os
from pathlib import Path

from PySide6 import QtWidgets, QtGui
from PySide6.QtCore import Qt, QPoint, QTimer
from PySide6.QtGui import QFont
from PySide6.QtNetwork import QNetworkProxy, QNetworkProxyFactory
from PySide6.QtWidgets import (
    QStackedWidget, QFrame, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QWidget, QLineEdit, QScrollArea, QTextEdit,
    QMenu, QApplication,
)

from awe_net.tech_detector import find_techs
from config.config import ROOT_CERT_FILE
from database.repository import AweRepository
from gui.browserWindow import BrowserWindow
from gui.certSetupDialog import CertSetupDialog
from gui.dockerManagerWindow import DockerManagerWindow
from gui.pipelineWindow import PipelineWindow
from gui.resultsWindow import ResultsWindow
from gui.targetInfoPanel import TargetInfoPanel
from gui.networkGraph import NetworkPage
from gui.httpHistory import HttpHistoryPage
from gui.interceptPage import InterceptPage
from gui.intruder import IntruderPage
from gui.repeater import RepeaterPage
from gui.wsPage import WebSocketPage
from gui.scopeEditor import ScopeEditorWidget
from gui.siteMapWindow import SiteMapPage
from proxy.traffic_extractor import _ExtractWorker
from gui.appearance import load_ui_settings, apply_appearance


# ── Minimal card helper (used by the Scope page) ─────────────────────────────

def _card(title: str, accent: str = "#9399B2") -> tuple:
    card = QFrame()
    card.setObjectName("scopeCard")
    card.setStyleSheet(f"""
        QFrame#scopeCard {{
            background: #1E1E2E;
            border: 1px solid #313244;
            border-radius: 6px;
            border-left: 3px solid {accent};
        }}
    """)
    vb = QVBoxLayout(card)
    vb.setContentsMargins(16, 14, 16, 16)
    vb.setSpacing(10)
    hdr = QLabel(title.upper())
    hdr.setStyleSheet(
        f"color:{accent}; font-size:9px; letter-spacing:1.5px;"
        " background:transparent; border:none; font-weight:bold;"
    )
    vb.addWidget(hdr)
    div = QFrame()
    div.setFrameShape(QFrame.HLine)
    div.setFixedHeight(1)
    div.setStyleSheet(f"background:{accent}; border:none;")
    vb.addWidget(div)
    return card, vb


# ── Nav definitions ───────────────────────────────────────────────────────────
# Each entry: (glyph_or_None, label, accent, icon_path_or_None)
# If icon_path is set it takes priority over the glyph.

_ICONS = "/home/mak-unipod/Documents/AWE/resources/icons"

_NAV = [
    ("◉",  "Browser",    "#89B4FA", f"{_ICONS}/browser.png"),     # 0
    ("◎",  "Target",     "#CBA6F7", f"{_ICONS}/target.png"),      # 1
    ("⚡",  "Pipeline",   "#A6E3A1", f"{_ICONS}/pipeline.png"),    # 2
    ("⬡",  "Docker",     "#89DCEB", f"{_ICONS}/docker.png"),      # 3
    ("◈",  "Results",    "#FAB387", f"{_ICONS}/results.png"),     # 4
    ("⊗",  "Network",    "#94E2D5", f"{_ICONS}/network.png"),     # 5
    ("◫",  "SiteMap",    "#89DCEB", f"{_ICONS}/sitemap.png"),     # 6
    ("⊟",  "History",    "#F9E2AF", f"{_ICONS}/http.png"),        # 7
    ("⊕",  "Intercept",  "#F9E2AF", f"{_ICONS}/intercept.png"),   # 8
    ("↻",  "Repeater",   "#F5C2E7", f"{_ICONS}/repeater.png"),    # 9
    ("⊛",  "Intruder",   "#EE99A0", f"{_ICONS}/intruder.png"),    # 10
    ("⇄",  "WebSockets", "#94E2D5", f"{_ICONS}/websocket.png"),   # 11
    ("✎",  "Notes",      "#F38BA8", f"{_ICONS}/notes.png"),       # 12
    ("⚙",  "Settings",   "#9399B2", f"{_ICONS}/settings-512.png"),# 13
]

_NAV_W = 58


# ── Activity-bar button ───────────────────────────────────────────────────────

class _NavButton(QPushButton):
    def __init__(self, glyph: str, label: str, accent: str,
                 icon_path: str | None = None, parent=None):
        super().__init__(parent)
        self._accent = accent
        self._has_icon = False

        vb = QVBoxLayout(self)
        vb.setContentsMargins(0, 6, 0, 6)
        vb.setSpacing(4)
        vb.setAlignment(Qt.AlignCenter)

        # Try to load the image icon first
        if icon_path:
            from PySide6.QtGui import QPixmap
            px = QPixmap(icon_path)
            if not px.isNull():
                self._has_icon = True
                self._icon_lbl = QLabel()
                self._icon_lbl.setAlignment(Qt.AlignCenter)
                self._icon_lbl.setFixedSize(24, 24)
                self._px_orig = px
                self._icon_lbl.setPixmap(
                    px.scaled(24, 24, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                )
                self._icon_lbl.setStyleSheet("background:transparent;")
                vb.addWidget(self._icon_lbl, alignment=Qt.AlignHCenter)

        if not self._has_icon:
            # Fall back to Unicode glyph
            self._icon_lbl = QLabel(glyph)
            self._icon_lbl.setAlignment(Qt.AlignCenter)
            self._icon_lbl.setFixedHeight(24)
            self._icon_lbl.setStyleSheet("font-size:18px; background:transparent; color:#6C7086;")
            vb.addWidget(self._icon_lbl)

        self._txt_lbl = None  # labels removed; tooltip carries the name

        self.setFlat(True)
        self.setFixedWidth(_NAV_W)
        self.setFixedHeight(44)
        self._set_active(False)

    def _set_active(self, active: bool):
        color = self._accent if active else "#6C7086"
        border = (f"border-left:3px solid {self._accent};"
                  if active else "border-left:3px solid transparent;")
        self.setStyleSheet(
            f"QPushButton {{ background:{'#1E1E2E' if active else 'transparent'};"
            f" border:none; {border} }}"
        )
        if self._has_icon:
            # Tint the pixmap: full color when active, grey when inactive
            from PySide6.QtGui import QPixmap, QPainter, QColor
            from PySide6.QtCore import QSize
            tint = QColor(self._accent if active else "#6C7086")
            src = self._px_orig.scaled(22, 22, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            result = QPixmap(src.size())
            result.fill(Qt.transparent)
            painter = QPainter(result)
            painter.drawPixmap(0, 0, src)
            painter.setCompositionMode(QPainter.CompositionMode_SourceIn)
            painter.fillRect(result.rect(), tint)
            painter.end()
            self._icon_lbl.setPixmap(result)
        else:
            self._icon_lbl.setStyleSheet(
                f"font-size:18px; background:transparent; color:{color};"
            )

    def set_active(self, active: bool):
        self._set_active(active)




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

        # Per-project repository (MongoDB) — used by Scope + SiteMap pages
        try:
            self._repo = AweRepository(project_dir=self.projectDirPath)
        except Exception:
            self._repo = None

        # Apply persisted font / theme on first open
        _s = load_ui_settings()
        apply_appearance(
            theme_name=_s.get("theme"),
            font_family=_s.get("font_family"),
            font_size=_s.get("font_size"),
        )

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

        # Debounce timer must exist before _build_sitemap_page() connects to it
        self._debounce_timer = QTimer(self)
        self._debounce_timer.setSingleShot(True)
        self._debounce_timer.setInterval(60_000)
        self._debounce_timer.timeout.connect(self._sync_proxy_traffic)

        # Pages — order must match _NAV
        # NOTE: _build_target_page() (index 1) also creates self._scopeEditor
        # via its embedded Scope tab.  All signal wiring happens in
        # _wire_scope_signals() called below.
        self._stack.addWidget(self._build_browser_page())    # 0 Browser
        self._stack.addWidget(self._build_target_page())     # 1 Target (includes Scope tab)
        self._stack.addWidget(self._build_pipeline_page())   # 2 Pipeline
        self._stack.addWidget(self._build_docker_page())     # 3 Docker
        self._stack.addWidget(self._build_results_page())    # 4 Results
        self._stack.addWidget(self._build_network_page())    # 5 Network
        self._stack.addWidget(self._build_sitemap_page())    # 6 SiteMap
        self._stack.addWidget(self._build_history_page())    # 7 History
        self._stack.addWidget(self._build_intercept_page())  # 8 Intercept
        self._stack.addWidget(self._build_repeater_page())   # 9 Repeater
        self._stack.addWidget(self._build_intruder_page())   # 10 Intruder
        self._stack.addWidget(self._build_ws_page())         # 11 WebSockets
        self._stack.addWidget(self._build_notes_page())      # 12 Notes
        self._stack.addWidget(self._build_settings_page())   # 13 Settings

        # Wire scope_changed → all consumer pages now that every page exists.
        # Also push the already-loaded scope into pages so their first render
        # respects scope, not just future saves.
        self._wire_scope_signals()

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

        for i, (glyph, label, accent, icon_path) in enumerate(_NAV):
            btn = _NavButton(glyph, label, accent, icon_path)
            btn.setToolTip(label)
            btn.clicked.connect(lambda _, idx=i: self._switch_page(idx))
            vb.addWidget(btn)
            self._nav_btns.append(btn)
            # thin separator after every button (inset 10px each side)
            sep_wrap = QWidget()
            sep_wrap.setFixedHeight(1)
            sep_layout = QHBoxLayout(sep_wrap)
            sep_layout.setContentsMargins(10, 0, 10, 0)
            sep_layout.setSpacing(0)
            sep = QFrame()
            sep.setFrameShape(QFrame.HLine)
            sep.setFixedHeight(1)
            sep.setStyleSheet("background:#313244; border:none;")
            sep_layout.addWidget(sep)
            vb.addWidget(sep_wrap)

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

        _newTabBtn = QPushButton("+")
        _newTabBtn.setObjectName("newBrowserTabButton")
        _newTabBtn.setFixedSize(28, 28)
        _newTabBtn.setToolTip("New tab")
        _newTabBtn.setStyleSheet("""
            QPushButton {
                color: #CDD6F4;
                background: transparent;
                border: 1px solid #45475A;
                border-radius: 4px;
                font-size: 16px;
                font-weight: bold;
                padding: 0px;
                min-width: 0px;
            }
            QPushButton:hover {
                background: #313244;
                border-color: #89B4FA;
                color: #89B4FA;
            }
            QPushButton:pressed {
                background: #45475A;
            }
        """)
        _newTabBtn.clicked.connect(self.openNewBrowserTab)
        self.browserTabWidget.setCornerWidget(_newTabBtn, Qt.TopRightCorner)

        # Context menu on the tab bar
        tb = self.browserTabWidget.tabBar()
        tb.setContextMenuPolicy(Qt.CustomContextMenu)
        tb.customContextMenuRequested.connect(self._browser_tab_context_menu)

        vb.addWidget(self.browserTabWidget)
        self.openNewBrowserTab()
        return page

    def _build_target_page(self) -> QWidget:
        from PySide6.QtWidgets import QTabWidget as _QTabWidget
        self._infoPanel = TargetInfoPanel(
            self, self.projectDirPath,
            parent=self, top_parent=self.topParent,
            embed=True,
        )
        self._infoPanel.openLinkInBrw.connect(self.openNewBrowserTab)
        info_widget = self._infoPanel.widget()

        # ── Scope tab content ─────────────────────────────────────────────────
        scope_page = QWidget()
        scope_root = QVBoxLayout(scope_page)
        scope_root.setContentsMargins(24, 20, 24, 24)
        scope_root.setSpacing(16)

        card, card_vb = _card("Project Scope", "#A6E3A1")
        self._scopeEditor = ScopeEditorWidget(repository=self._repo, parent=card)
        card_vb.addWidget(self._scopeEditor)
        scope_root.addWidget(card, stretch=1)

        scope_scroll = QScrollArea()
        scope_scroll.setWidgetResizable(True)
        scope_scroll.setFrameShape(QFrame.NoFrame)
        scope_scroll.setStyleSheet(
            "QScrollArea{background:#181825;border:none;}"
            "QScrollBar:vertical{background:#181825;width:8px;border:none;}"
            "QScrollBar::handle:vertical{background:#313244;border-radius:4px;min-height:20px;}"
        )
        scope_scroll.setWidget(scope_page)

        # ── Combine into a tabbed container ───────────────────────────────────
        tabs = _QTabWidget()
        tabs.setStyleSheet("""
            QTabWidget::pane {
                border: none;
                background: #1E1E2E;
            }
            QTabBar::tab {
                background: #181825;
                color: #6C7086;
                border: none;
                border-bottom: 2px solid transparent;
                padding: 6px 18px;
                font-size: 9px;
            }
            QTabBar::tab:selected {
                color: #CDD6F4;
                border-bottom: 2px solid #CBA6F7;
                background: #1E1E2E;
            }
            QTabBar::tab:hover:!selected {
                color: #CDD6F4;
                background: #313244;
            }
        """)
        tabs.addTab(info_widget, "Target")
        tabs.addTab(scope_scroll,     "Scope")
        return tabs

    def _build_pipeline_page(self) -> QWidget:
        self._pipelineWindow = PipelineWindow(
            project_dir=self.projectDirPath,
            target=self.main_server_name or "",
            parent=self,
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
            proxy_col=self._get_proxy_col(),
            parent=self,
        )
        self._networkPage.send_to_repeater.connect(self._send_to_repeater)
        return self._networkPage

    def _wire_scope_signals(self) -> None:
        """Connect ScopeEditorWidget.scope_changed to all consumer pages and
        push the already-loaded scope so the first render respects scope.

        Called once after all pages have been built, so self._scopeEditor and
        every page attribute are guaranteed to exist.
        """
        initial = self._scopeEditor.current_config()

        # Network graph — apply scope immediately so the initial load filters
        self._networkPage.on_scope_changed(initial)
        self._scopeEditor.scope_changed.connect(self._networkPage.on_scope_changed)

        # SiteMap and History — they load their own scope from DB in __init__,
        # but we still connect so future saves propagate live.
        self._scopeEditor.scope_changed.connect(self._siteMapPage.on_scope_changed)
        self._scopeEditor.scope_changed.connect(self._historyPage.on_scope_changed)

        # WebSockets — push initial scope and connect for live updates.
        self._wsPage.on_scope_changed(initial)
        self._scopeEditor.scope_changed.connect(self._wsPage.on_scope_changed)

    def _get_proxy_col(self):
        """Return the global proxy traffic MongoDB collection, or None on error."""
        try:
            from database.mongo import get_proxy_traffic_db
            return get_proxy_traffic_db().traffic
        except Exception:
            return None

    def _build_sitemap_page(self) -> QWidget:
        self._siteMapPage = SiteMapPage(
            project_dir=self.projectDirPath,
            target_host=self.main_server_name or "",
            proxy_col=self._get_proxy_col(),
            repository=self._repo,
            parent=self,
        )
        self._siteMapPage.send_to_repeater.connect(self._send_to_repeater)
        self._siteMapPage.send_to_intruder.connect(self._send_to_intruder)
        self._siteMapPage.sync_requested.connect(self._sync_proxy_traffic)
        self._siteMapPage.traffic_changed.connect(self._debounce_timer.start)
        return self._siteMapPage

    def _build_history_page(self) -> QWidget:
        self._historyPage = HttpHistoryPage(
            proxy_col=self._get_proxy_col(),
            repository=self._repo,
            parent=self,
        )
        self._historyPage.send_to_repeater.connect(self._send_to_repeater)
        self._historyPage.send_to_intruder.connect(self._send_to_intruder)
        self._historyPage.send_to_websocket.connect(self._send_to_websocket)
        self._historyPage.traffic_changed.connect(self._debounce_timer.start)
        return self._historyPage

    def _build_repeater_page(self) -> QWidget:
        self._repeaterPage = RepeaterPage(
            proxy_port=self.proxy_port,
            parent=self,
        )
        self._repeaterPage.send_to_intruder.connect(self._send_to_intruder)
        return self._repeaterPage

    def _build_intruder_page(self) -> QWidget:
        self._intruderPage = IntruderPage(
            proxy_port=self.proxy_port,
            project_dir=self.projectDirPath,
            parent=self,
        )
        self._intruderPage.send_to_repeater.connect(self._send_to_repeater)
        return self._intruderPage

    def _build_intercept_page(self) -> QWidget:
        self._interceptPage = InterceptPage(
            proxy_port=self.proxy_port,
            parent=self,
        )
        return self._interceptPage

    def _build_ws_page(self) -> QWidget:
        self._wsPage = WebSocketPage(
            proxy_port=self.proxy_port,
            parent=self,
        )
        return self._wsPage

    def _send_to_repeater(self, request_text: str) -> None:
        self._repeaterPage.add_tab(request_text)
        self._switch_page(9)   # Repeater is at index 9 in _NAV

    def _send_to_intruder(self, request_text: str) -> None:
        self._intruderPage.load_request(request_text)
        self._switch_page(10)  # Intruder is at index 10 in _NAV

    def _send_to_websocket(self, host: str, path: str) -> None:
        self._wsPage.load_connection(host, path)
        self._switch_page(11)  # WebSockets is at index 11 in _NAV

    def OpenIntruderWindow(self):
        self._switch_page(10)

    def OpenWebSocketWindow(self):
        self._switch_page(11)

    def OpenInterceptWindow(self):
        self._switch_page(8)

    def _sync_proxy_traffic(self) -> None:
        """Extract data from proxy traffic DB and upsert into project results."""
        if not self._repo:
            return
        col    = self._get_proxy_col()
        scope  = self._scopeEditor.current_config() if hasattr(self, "_scopeEditor") else None
        target = self.main_server_name or ""
        self._extractWorker = _ExtractWorker(col, scope, parent=self)
        self._extractWorker.done.connect(lambda results: self._on_extract_done(results, target))
        self._extractWorker.error.connect(
            lambda msg: __import__("logging").getLogger(__name__).warning(
                "proxy traffic extraction error: %s", msg
            )
        )
        self._extractWorker.start()

    def _on_extract_done(self, results: dict, target: str) -> None:
        if not self._repo:
            return
        try:
            session_id = self._repo.get_or_create_proxy_session(target)
            run_id     = self._repo.get_proxy_tool_run_id(session_id)
            for category, items in results.items():
                if items:
                    self._repo.upsert_results(session_id, run_id, category, items)
        except Exception:
            import logging
            logging.getLogger(__name__).exception("upsert proxy results failed")
            return
        if hasattr(self, "_networkPage"):
            self._networkPage.refresh()

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
        """Settings page — delegates to the unified SettingsWidget."""
        from gui.settingsWindow import SettingsWidget
        self._settingsWidget = SettingsWidget(
            project_dir=self.projectDirPath,
            mongo_uri="mongodb://localhost:27017",
            proxy_port=self.proxy_port,
            proxy_status=self.proxy_status,
            target_window=self,
            parent=self,
        )
        return self._settingsWidget

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
    def ViewNotepad(self):  self._switch_page(12)  # Notes at 12
