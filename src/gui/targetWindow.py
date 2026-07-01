import json
import logging
import os
from enum import IntEnum
from pathlib import Path

from PySide6 import QtWidgets, QtGui
from PySide6.QtCore import Qt, QPoint, QTimer
from PySide6.QtNetwork import QNetworkProxy, QNetworkProxyFactory
from PySide6.QtWidgets import (
    QStackedWidget, QFrame, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QWidget, QLineEdit, QScrollArea, QTextEdit,
    QMenu, QApplication,
)

from awe_net.tech_detector import find_techs
from config.config import ROOT_CERT_FILE, RUNDIR
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
from gui.decoder_page import DecoderPage
from gui.comparer import ComparerPage
from gui.jwt_page import JwtPage
from gui.graphql_page import GraphqlPage
from gui.session_manager import SessionManagerWidget
from gui.testing_methodology import TestingMethodologyWidget
from proxy.traffic_extractor import _ExtractWorker
from gui.appearance import load_ui_settings, apply_appearance
from gui.palette import (
    BASE, MANTLE, CRUST, SURFACE0, SURFACE1, OVERLAY0, OVERLAY2,
    TEXT, SUBTEXT1, BLUE, MAUVE, GREEN, RED, YELLOW, PEACH, TEAL, SKY, PINK,
    SCROLLBAR_V, SCROLLBAR_V_THIN, TAB_BAR,
)

log = logging.getLogger(__name__)

# ── Minimal card helper (used by the Scope page) ─────────────────────────────

def _card(title: str, accent: str = OVERLAY2) -> tuple:
    card = QFrame()
    card.setObjectName("scopeCard")
    card.setStyleSheet(f"""
        QFrame#scopeCard {{
            background: {BASE};
            border: 1px solid {SURFACE0};
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

_ICONS = os.path.join(RUNDIR, "resources", "icons")

_NAV = [
    ("◉",  "Browser",    BLUE,     f"{_ICONS}/browser.png"),     # Page.BROWSER
    ("◎",  "Target",     MAUVE,    f"{_ICONS}/target.png"),      # Page.TARGET
    ("⚡",  "Pipeline",   GREEN,    f"{_ICONS}/pipeline.png"),    # Page.PIPELINE
    ("⬡",  "Docker",     SKY,      f"{_ICONS}/docker.png"),      # Page.DOCKER
    ("◈",  "Results",    PEACH,    f"{_ICONS}/results.png"),     # Page.RESULTS
    ("⊗",  "Network",    TEAL,     f"{_ICONS}/network.png"),     # Page.NETWORK
    ("◫",  "SiteMap",    SKY,      f"{_ICONS}/sitemap.png"),     # Page.SITEMAP
    ("⊟",  "History",    YELLOW,   f"{_ICONS}/http.png"),        # Page.HISTORY
    ("⊕",  "Intercept",  YELLOW,   f"{_ICONS}/intercept.png"),   # Page.INTERCEPT
    ("↻",  "Repeater",   PINK,f"{_ICONS}/repeater.png"),    # Page.REPEATER  (Pink)
    ("⊛",  "Intruder",   "#EE99A0",f"{_ICONS}/intruder.png"),    # Page.INTRUDER  (custom rose)
    ("⇄",  "WebSockets", TEAL,     f"{_ICONS}/websocket.png"),   # Page.WEBSOCKETS
    ("⊞",  "Decoder",    TEAL,     f"{_ICONS}/encoding.png"),    # Page.DECODER
    ("⇌",  "Comparer",   PINK,f"{_ICONS}/comparer.png"),    # Page.COMPARER  (Pink)
    ("⚿",  "JWT",        PEACH,    f"{_ICONS}/jwt.png"),         # Page.JWT
    ("⬡",  "GraphQL",    TEAL,     f"{_ICONS}/graphql.png"),     # Page.GRAPHQL
    ("⚙",  "Settings",   OVERLAY2, f"{_ICONS}/settings-512.png"),# Page.SETTINGS
]

_NAV_W = 58


class Page(IntEnum):
    BROWSER    = 0
    TARGET     = 1
    PIPELINE   = 2
    DOCKER     = 3
    RESULTS    = 4
    NETWORK    = 5
    SITEMAP    = 6
    HISTORY    = 7
    INTERCEPT  = 8
    REPEATER   = 9
    INTRUDER   = 10
    WEBSOCKETS = 11
    DECODER    = 12
    COMPARER   = 13
    JWT        = 14
    GRAPHQL    = 15
    SETTINGS   = 16


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
            self._icon_lbl.setStyleSheet(f"font-size:18px; background:transparent; color:{OVERLAY0};")
            vb.addWidget(self._icon_lbl)

        self._txt_lbl = None  # labels removed; tooltip carries the name

        self.setFlat(True)
        self.setFixedWidth(_NAV_W)
        self.setFixedHeight(44)
        self._set_active(False)

    def _set_active(self, active: bool):
        color = self._accent if active else OVERLAY0
        border = (f"border-left:3px solid {self._accent};"
                  if active else "border-left:3px solid transparent;")
        self.setStyleSheet(
            f"QPushButton {{ background:{BASE if active else 'transparent'};"
            f" border:none; {border} }}"
        )
        if self._has_icon:
            # Tint the pixmap: full color when active, grey when inactive
            from PySide6.QtGui import QPixmap, QPainter, QColor
            from PySide6.QtCore import QSize
            tint = QColor(self._accent if active else OVERLAY0)
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
                f"font-size:18px; background:transparent; color:{color};"  # color is already a palette value
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
        div.setStyleSheet(f"color:{SURFACE0}; background:{SURFACE0};")
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
        def _add(name: str, builder):
            log.info("Loading page: %s", name)
            self._stack.addWidget(builder())

        _add("Browser",    self._build_browser_page)    # 0
        _add("Target",     self._build_target_page)     # 1
        _add("Pipeline",   self._build_pipeline_page)   # 2
        _add("Docker",     self._build_docker_page)     # 3
        _add("Results",    self._build_results_page)    # 4
        _add("Network",    self._build_network_page)    # 5
        _add("SiteMap",    self._build_sitemap_page)    # 6
        _add("History",    self._build_history_page)    # 7
        _add("Intercept",  self._build_intercept_page)  # 8
        _add("Repeater",   self._build_repeater_page)   # 9
        _add("Intruder",   self._build_intruder_page)   # 10
        _add("WebSockets", self._build_ws_page)          # 11
        _add("Decoder",    self._build_decoder_page)    # 12
        _add("Comparer",   self._build_comparer_page)   # 13
        _add("JWT",        self._build_jwt_page)        # 14
        _add("GraphQL",    self._build_graphql_page)    # 15
        _add("Settings",   self._build_settings_page)   # 16

        # Wire scope_changed → all consumer pages now that every page exists.
        # Also push the already-loaded scope into pages so their first render
        # respects scope, not just future saves.
        self._wire_scope_signals()

        self._switch_page(Page.TARGET)
        self.topParent.newProjectCreated.emit(self)

    # ── Nav bar ───────────────────────────────────────────────────────────────

    def _build_nav_bar(self) -> QWidget:
        outer = QWidget()
        outer.setFixedWidth(_NAV_W)
        outer.setStyleSheet(f"background:{MANTLE};")
        outer_vb = QVBoxLayout(outer)
        outer_vb.setContentsMargins(0, 0, 0, 0)
        outer_vb.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll.setStyleSheet(
            f"QScrollArea {{ background:{MANTLE}; border:none; }}"
            + SCROLLBAR_V_THIN
        )

        inner = QWidget()
        inner.setStyleSheet(f"background:{MANTLE};")
        vb = QVBoxLayout(inner)
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
            sep.setStyleSheet(f"background:{SURFACE0}; border:none;")
            sep_layout.addWidget(sep)
            vb.addWidget(sep_wrap)

        vb.addStretch()
        scroll.setWidget(inner)
        outer_vb.addWidget(scroll)
        return outer

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
        _newTabBtn.setStyleSheet(f"""
            QPushButton {{
                color: {TEXT};
                background: transparent;
                border: 1px solid {SURFACE1};
                border-radius: 4px;
                font-size: 16px;
                font-weight: bold;
                padding: 0px;
                min-width: 0px;
            }}
            QPushButton:hover {{
                background: {SURFACE0};
                border-color: {BLUE};
                color: {BLUE};
            }}
            QPushButton:pressed {{
                background: {SURFACE1};
            }}
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

        card, card_vb = _card("Project Scope", GREEN)
        self._scopeEditor = ScopeEditorWidget(repository=self._repo, parent=card)
        card_vb.addWidget(self._scopeEditor)
        scope_root.addWidget(card, stretch=1)

        scope_scroll = QScrollArea()
        scope_scroll.setWidgetResizable(True)
        scope_scroll.setFrameShape(QFrame.NoFrame)
        scope_scroll.setStyleSheet(
            f"QScrollArea{{background:{MANTLE};border:none;}}"
            + SCROLLBAR_V
        )
        scope_scroll.setWidget(scope_page)

        # ── Combine into a tabbed container ───────────────────────────────────
        tabs = _QTabWidget()
        tabs.setStyleSheet(TAB_BAR)
        self._sessionManager = SessionManagerWidget(repo=self._repo, parent=self)
        self._sessionManager.sessions_changed.connect(self._on_sessions_changed)

        # ── Notes tab ─────────────────────────────────────────────────────────
        notes_widget = self._build_notes_widget()

        # ── Testing Flow tab ──────────────────────────────────────────────────
        self._methodologyWidget = TestingMethodologyWidget(
            project_dir=self.projectDirPath, repo=self._repo, parent=self
        )

        tabs.addTab(info_widget,                "Target")
        tabs.addTab(scope_scroll,               "Scope")
        tabs.addTab(self._sessionManager,       "Sessions")
        tabs.addTab(self._methodologyWidget,    "Testing Flow")
        tabs.addTab(notes_widget,               "Notes")
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

        # Sitemap context-menu scope actions → reload editor UI + broadcast.
        self._siteMapPage.scope_modified.connect(self._on_sitemap_scope_modified)

    def _on_sitemap_scope_modified(self, cfg) -> None:
        """Sitemap pushed a scope change; reload the editor and notify all consumers."""
        self._scopeEditor.load()
        self._networkPage.on_scope_changed(cfg)
        self._historyPage.on_scope_changed(cfg)
        self._wsPage.on_scope_changed(cfg)

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
        self._siteMapPage.send_to_decoder.connect(self._send_to_decoder)
        self._siteMapPage.send_to_comparer_left.connect(self._send_to_comparer_left)
        self._siteMapPage.send_to_comparer_right.connect(self._send_to_comparer_right)
        self._siteMapPage.send_to_jwt.connect(self._send_to_jwt)
        self._siteMapPage.send_to_graphql.connect(self._send_to_graphql)
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
        self._historyPage.send_to_decoder.connect(self._send_to_decoder)
        self._historyPage.send_to_comparer_left.connect(self._send_to_comparer_left)
        self._historyPage.send_to_comparer_right.connect(self._send_to_comparer_right)
        self._historyPage.send_to_jwt.connect(self._send_to_jwt)
        self._historyPage.send_to_graphql.connect(self._send_to_graphql)
        self._historyPage.traffic_changed.connect(self._debounce_timer.start)
        return self._historyPage

    def _build_repeater_page(self) -> QWidget:
        self._repeaterPage = RepeaterPage(
            proxy_port=self.proxy_port,
            repository=self._repo,
            parent=self,
        )
        self._repeaterPage.send_to_intruder.connect(self._send_to_intruder)
        self._repeaterPage.send_to_decoder.connect(self._send_to_decoder)
        self._repeaterPage.send_to_comparer_left.connect(self._send_to_comparer_left)
        self._repeaterPage.send_to_comparer_right.connect(self._send_to_comparer_right)
        self._repeaterPage.send_to_jwt.connect(self._send_to_jwt)
        self._repeaterPage.send_to_graphql.connect(self._send_to_graphql)
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

    def _build_decoder_page(self) -> QWidget:
        self._decoderPage = DecoderPage(repository=self._repo, parent=self)
        return self._decoderPage

    def _build_comparer_page(self) -> QWidget:
        self._comparerPage = ComparerPage(repository=self._repo, parent=self)
        return self._comparerPage

    def _build_jwt_page(self) -> QWidget:
        self._jwtPage = JwtPage(repository=self._repo, parent=self)
        return self._jwtPage

    def _build_graphql_page(self) -> QWidget:
        self._graphqlPage = GraphqlPage(
            repository=self._repo,
            proxy_port=self.proxy_port,
            parent=self,
        )
        self._graphqlPage.send_to_repeater.connect(self._send_to_repeater)
        return self._graphqlPage

    def _send_to_repeater(self, request_text: str) -> None:
        self._repeaterPage.add_tab(request_text)
        self._switch_page(Page.REPEATER)

    def _send_to_intruder(self, request_text: str) -> None:
        self._intruderPage.load_request(request_text)
        self._switch_page(Page.INTRUDER)

    def _send_to_websocket(self, host: str, path: str) -> None:
        self._wsPage.load_connection(host, path)
        self._switch_page(Page.WEBSOCKETS)

    def _send_to_decoder(self, text: str) -> None:
        self._decoderPage.load_text(text)
        self._switch_page(Page.DECODER)

    def _send_to_comparer_left(self, text: str) -> None:
        self._comparerPage.load_left(text)
        self._switch_page(Page.COMPARER)

    def _send_to_comparer_right(self, text: str) -> None:
        self._comparerPage.load_right(text)
        self._switch_page(Page.COMPARER)

    def _send_to_jwt(self, token: str) -> None:
        self._jwtPage.load_token(token)
        self._switch_page(Page.JWT)

    def _send_to_graphql(self, raw: str) -> None:
        self._graphqlPage.load_request(raw)
        self._switch_page(Page.GRAPHQL)

    def _on_sessions_changed(self) -> None:
        if hasattr(self, '_repeaterPage'):
            self._repeaterPage.refresh_sessions()
        if hasattr(self, '_intruderPage'):
            self._intruderPage.refresh_sessions()

    def OpenIntruderWindow(self):
        self._switch_page(Page.INTRUDER)

    def OpenWebSocketWindow(self):
        self._switch_page(Page.WEBSOCKETS)

    def OpenInterceptWindow(self):
        self._switch_page(Page.INTERCEPT)

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

    def _build_notes_widget(self) -> QWidget:
        page = QWidget()
        vb = QVBoxLayout(page)
        vb.setContentsMargins(0, 0, 0, 0)
        vb.setSpacing(0)
        self._notesEdit = QTextEdit()
        self._notesEdit.setPlaceholderText(f"Notes for {self.main_server_name}…")
        self._notesEdit.setStyleSheet(f"""
            QTextEdit {{
                background:{BASE}; color:{TEXT};
                border:none; padding:12px;
            }}
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
        menu.setStyleSheet(f"""
            QMenu {{
                background:{BASE}; color:{TEXT};
                border:1px solid {SURFACE0}; border-radius:4px;
            }}
            QMenu::item:selected {{ background:{SURFACE0}; }}
            QMenu::separator {{ background:{SURFACE0}; height:1px; margin:2px 8px; }}
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
        self._switch_page(Page.PIPELINE)

    def OpenDockerManager(self):
        self._switch_page(Page.DOCKER)

    def OpenResultsWindow(self):
        self._switch_page(Page.RESULTS)

    def OpenNetworkWindow(self):
        self._switch_page(Page.NETWORK)

    def OpenTestTargetWindow(self):
        self._switch_page(Page.NETWORK)

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
            self._switch_page(Page.BROWSER)

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
            log.warning("Tech detection display failed", exc_info=True)

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
                log.warning("Failed to load notes from %s", p, exc_info=True)

    def _save_notes(self):
        try:
            with open(self._notes_path(), "w") as f:
                f.write(self._notesEdit.toPlainText())
        except Exception:
            log.warning("Failed to save notes to %s", self._notes_path(), exc_info=True)

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
                log.warning("Failed to load project.json from %s", meta_path, exc_info=True)
        self.main_server_name = self.projectDirPath.rstrip("/").split("/")[-1]
        self.target_url = ""

    def closeEvent(self, event: QtGui.QCloseEvent) -> None:
        self.topParent.projectClosed.emit(self, self.projectIndex)
        return super().closeEvent(event)

    # ── Legacy stubs ──────────────────────────────────────────────────────────

    def AddTopMenu(self):   pass
    def ViewTarget(self):   self._switch_page(Page.TARGET)
    def ViewTerminal(self): pass
    def ViewNotepad(self):  self._switch_page(Page.TARGET)
