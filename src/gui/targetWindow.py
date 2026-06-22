import json
import os
from pathlib import Path

from PySide6 import QtWidgets, QtGui
from PySide6.QtCore import Qt, QPoint, QTimer
from PySide6.QtGui import QFont, QFontDatabase
from PySide6.QtNetwork import QNetworkProxy, QNetworkProxyFactory
from PySide6.QtWidgets import (
    QStackedWidget, QFrame, QVBoxLayout, QHBoxLayout, QFormLayout,
    QPushButton, QLabel, QWidget, QLineEdit, QScrollArea, QTextEdit,
    QSizePolicy, QMenu, QComboBox, QSpinBox, QApplication,
)

from awe_net.wappy import find_techs
from config.config import ROOT_CERT_FILE
from database.repository import AweRepository
from gui.browserWindow import BrowserWindow
from gui.certSetupDialog import CertSetupDialog
from gui.dockerManagerWindow import DockerManagerWindow
from gui.pipelineWindow import PipelineWindow
from gui.resultsWindow import ResultsWindow
from gui.leftDock import LeftDock
from gui.networkWindow import NetworkWindow
from gui.networkGraph import NetworkPage
from gui.httpHistory import HttpHistoryPage
from gui.repeater import RepeaterPage
from gui.scopeEditor import ScopeEditorWidget
from gui.siteMapWindow import SiteMapPage
from proxy.traffic_extractor import _ExtractWorker


# ── App-level settings persistence ───────────────────────────────────────────

_SETTINGS_FILE = Path(os.path.expanduser("~")) / ".config" / "awe" / "ui_settings.json"

_THEMES: dict[str, dict] = {
    "Catppuccin Mocha": {
        "base":    "#1E1E2E",
        "mantle":  "#181825",
        "surface": "#313244",
        "overlay": "#45475A",
        "text":    "#CDD6F4",
        "subtext": "#BAC2DE",
        "accent":  "#CBA6F7",
        "accent2": "#89B4FA",
        "green":   "#A6E3A1",
        "red":     "#F38BA8",
        "yellow":  "#F9E2AF",
        "peach":   "#FAB387",
    },
    "Catppuccin Macchiato": {
        "base":    "#1E2030",
        "mantle":  "#181926",
        "surface": "#363A4F",
        "overlay": "#494D64",
        "text":    "#CAD3F5",
        "subtext": "#B8C0E0",
        "accent":  "#C6A0F6",
        "accent2": "#8AADF4",
        "green":   "#A6DA95",
        "red":     "#ED8796",
        "yellow":  "#EED49F",
        "peach":   "#F5A97F",
    },
    "Catppuccin Frappe": {
        "base":    "#303446",
        "mantle":  "#292C3C",
        "surface": "#414559",
        "overlay": "#51576D",
        "text":    "#C6D0F5",
        "subtext": "#B5BFE2",
        "accent":  "#CA9EE6",
        "accent2": "#8CAAEE",
        "green":   "#A6D189",
        "red":     "#E78284",
        "yellow":  "#E5C890",
        "peach":   "#EF9F76",
    },
    "Catppuccin Latte": {
        "base":    "#EFF1F5",
        "mantle":  "#E6E9EF",
        "surface": "#CCD0DA",
        "overlay": "#ACB0BE",
        "text":    "#4C4F69",
        "subtext": "#5C5F77",
        "accent":  "#8839EF",
        "accent2": "#1E66F5",
        "green":   "#40A02B",
        "red":     "#D20F39",
        "yellow":  "#DF8E1D",
        "peach":   "#FE640B",
    },
}

_MONO_FONTS = [
    "Cascadia Code", "JetBrains Mono", "Fira Code",
    "Hack", "Inconsolata", "Source Code Pro",
    "Ubuntu Mono", "DejaVu Sans Mono", "Monospace",
]


def _load_ui_settings() -> dict:
    try:
        return json.loads(_SETTINGS_FILE.read_text())
    except Exception:
        return {}


def _save_ui_settings(data: dict):
    _SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    _SETTINGS_FILE.write_text(json.dumps(data, indent=2))


# Current appearance state — updated by _apply_appearance()
_app_state: dict = {"theme": "Catppuccin Mocha", "font_family": "Monospace", "font_size": 10}


def _apply_appearance(theme_name: str | None = None,
                      font_family: str | None = None,
                      font_size: int | None = None):
    """Apply theme colours and font together in a single stylesheet.

    Font must live inside the stylesheet's QWidget rule — calling
    QApplication.setFont() alone cannot override widgets styled via CSS.
    """
    if theme_name   is not None: _app_state["theme"]       = theme_name
    if font_family  is not None: _app_state["font_family"] = font_family
    if font_size    is not None: _app_state["font_size"]   = font_size

    t   = _THEMES.get(_app_state["theme"], _THEMES["Catppuccin Mocha"])
    fam = _app_state["font_family"]
    sz  = _app_state["font_size"]

    # Keep QApplication font in sync so native dialogs / tooltips also update
    QApplication.instance().setFont(QFont(fam, sz))

    QApplication.instance().setStyleSheet(f"""
        QWidget          {{ background:{t['base']}; color:{t['text']};
                            font-family:'{fam}'; font-size:{sz}pt; }}
        QMainWindow      {{ background:{t['mantle']}; }}
        QFrame           {{ border:none; }}
        QScrollBar:vertical   {{ background:{t['mantle']}; width:8px; border:none; }}
        QScrollBar::handle:vertical {{ background:{t['surface']}; border-radius:4px; min-height:20px; }}
        QScrollBar:horizontal {{ background:{t['mantle']}; height:8px; border:none; }}
        QScrollBar::handle:horizontal {{ background:{t['surface']}; border-radius:4px; min-width:20px; }}
        QScrollBar::add-line, QScrollBar::sub-line {{ width:0; height:0; }}
        QTabWidget::pane {{ border:1px solid {t['surface']}; background:{t['base']}; }}
        QTabBar::tab      {{ background:{t['mantle']}; color:{t['subtext']};
                             padding:6px 14px; border:none; border-radius:4px 4px 0 0; }}
        QTabBar::tab:selected {{ background:{t['surface']}; color:{t['text']}; }}
        QTabBar::tab:hover    {{ background:{t['overlay']}; color:{t['text']}; }}
        QPushButton  {{ background:{t['surface']}; color:{t['text']};
                        border:1px solid {t['overlay']}; border-radius:5px;
                        padding:5px 14px; min-height:26px; }}
        QPushButton:hover {{ background:{t['overlay']}; border-color:{t['accent2']}; }}
        QPushButton:pressed {{ background:{t['mantle']}; }}
        QLineEdit, QComboBox, QTextEdit, QSpinBox {{
            background:{t['mantle']}; color:{t['text']};
            border:1px solid {t['overlay']}; border-radius:4px;
            padding:3px 8px; }}
        QLineEdit:focus, QComboBox:focus, QTextEdit:focus, QSpinBox:focus {{
            border-color:{t['accent2']}; }}
        QTableWidget  {{ background:{t['base']}; gridline-color:{t['surface']};
                         alternate-background-color:{t['mantle']}; }}
        QHeaderView::section {{ background:{t['surface']}; color:{t['subtext']};
                                 border:none; padding:4px 8px; }}
        QTreeView, QListView {{ background:{t['base']}; alternate-background-color:{t['mantle']}; }}
        QToolTip  {{ background:{t['surface']}; color:{t['text']};
                     border:1px solid {t['overlay']}; border-radius:4px; padding:4px; }}
        QSplitter::handle {{ background:{t['surface']}; }}
        QMenu     {{ background:{t['mantle']}; color:{t['text']};
                     border:1px solid {t['surface']}; border-radius:6px; padding:4px; }}
        QMenu::item:selected {{ background:{t['surface']}; border-radius:3px; }}
        QMenu::separator {{ background:{t['surface']}; height:1px; margin:4px 6px; }}
    """)


# ── Nav definitions ───────────────────────────────────────────────────────────

_NAV = [
    ("◉",  "Browser",   "#89B4FA"),  # 0
    ("◎",  "Target",    "#CBA6F7"),  # 1
    ("⚡",  "Pipeline",  "#A6E3A1"),  # 2
    ("⬡",  "Docker",    "#89DCEB"),  # 3
    ("◈",  "Results",   "#FAB387"),  # 4
    ("⊗",  "Network",   "#94E2D5"),  # 5
    ("◎",  "Scope",     "#A6E3A1"),  # 6
    ("◫",  "SiteMap",   "#89DCEB"),  # 7
    ("⊟",  "History",   "#F9E2AF"),  # 8
    ("↻",  "Repeater",  "#F5C2E7"),  # 9
    ("✎",  "Notes",     "#F38BA8"),  # 10
    ("⚙",  "Settings",  "#9399B2"),  # 11
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

        # Per-project repository (MongoDB) — used by Scope + SiteMap pages
        try:
            self._repo = AweRepository(project_dir=self.projectDirPath)
        except Exception:
            self._repo = None

        # Apply persisted font / theme on first open
        _s = _load_ui_settings()
        _apply_appearance(
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
        self._stack.addWidget(self._build_browser_page())    # 0 Browser
        self._stack.addWidget(self._build_target_page())    # 1 Target
        self._stack.addWidget(self._build_pipeline_page())  # 2 Pipeline
        self._stack.addWidget(self._build_docker_page())    # 3 Docker
        self._stack.addWidget(self._build_results_page())   # 4 Results
        self._stack.addWidget(self._build_network_page())   # 5 Network
        self._stack.addWidget(self._build_scope_page())     # 6 Scope
        self._stack.addWidget(self._build_sitemap_page())   # 7 SiteMap
        self._stack.addWidget(self._build_history_page())   # 8 History
        self._stack.addWidget(self._build_repeater_page())  # 9 Repeater
        self._stack.addWidget(self._build_notes_page())     # 10 Notes
        self._stack.addWidget(self._build_settings_page())  # 11 Settings

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

    def _build_scope_page(self) -> QWidget:
        from pathlib import Path
        page = QWidget()
        root = QVBoxLayout(page)
        root.setContentsMargins(24, 20, 24, 24)
        root.setSpacing(16)

        # ── header ────────────────────────────────────────────────────────────
        hrow = QHBoxLayout()
        hrow.setSpacing(10)
        icon = QLabel("◎")
        icon.setStyleSheet("color:#A6E3A1; font-size:22px; background:transparent;")
        hrow.addWidget(icon)
        title = QLabel("Scope")
        title.setStyleSheet(
            "color:#CDD6F4; font-size:15px; font-weight:bold; background:transparent;"
        )
        hrow.addWidget(title)
        hrow.addStretch()
        target_lbl = QLabel(self.main_server_name or "")
        target_lbl.setStyleSheet("color:#6C7086; font-size:11px; background:transparent;")
        hrow.addWidget(target_lbl)
        root.addLayout(hrow)

        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setStyleSheet("background:#313244; border:none;")
        sep.setFixedHeight(1)
        root.addWidget(sep)

        # ── scope editor card ─────────────────────────────────────────────────
        card, card_vb = _card("Project Scope", "#A6E3A1")

        self._scopeEditor = ScopeEditorWidget(repository=self._repo, parent=card)
        card_vb.addWidget(self._scopeEditor)

        root.addWidget(card)
        root.addStretch()

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setStyleSheet(
            "QScrollArea{background:#181825; border:none;}"
            "QScrollBar:vertical{background:#181825; width:8px; border:none;}"
            "QScrollBar::handle:vertical{background:#313244; border-radius:4px; min-height:20px;}"
        )
        scroll.setWidget(page)
        return scroll

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
        if hasattr(self, "_scopeEditor"):
            self._scopeEditor.scope_changed.connect(self._siteMapPage.on_scope_changed)
        self._siteMapPage.send_to_repeater.connect(self._send_to_repeater)
        self._siteMapPage.sync_requested.connect(self._sync_proxy_traffic)
        self._siteMapPage.traffic_changed.connect(self._debounce_timer.start)
        return self._siteMapPage

    def _build_history_page(self) -> QWidget:
        self._historyPage = HttpHistoryPage(
            proxy_col=self._get_proxy_col(),
            repository=self._repo,
            parent=self,
        )
        if hasattr(self, "_scopeEditor"):
            self._scopeEditor.scope_changed.connect(self._historyPage.on_scope_changed)
        self._historyPage.send_to_repeater.connect(self._send_to_repeater)
        self._historyPage.traffic_changed.connect(self._debounce_timer.start)
        return self._historyPage

    def _build_repeater_page(self) -> QWidget:
        self._repeaterPage = RepeaterPage(
            proxy_port=self.proxy_port,
            parent=self,
        )
        return self._repeaterPage

    def _send_to_repeater(self, request_text: str) -> None:
        self._repeaterPage.add_tab(request_text)
        self._switch_page(9)   # Repeater is at index 9 in _NAV

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

        _saved = _load_ui_settings()

        # ── Font card ─────────────────────────────────────────────────────────
        font_card, font_vb = _card("Font", "#CBA6F7")

        db = QFontDatabase()
        available_families = set(db.families())
        font_choices = [f for f in _MONO_FONTS if f in available_families] or ["Monospace"]

        cur_font   = QApplication.instance().font()
        saved_fam  = _saved.get("font_family", cur_font.family())
        saved_size = _saved.get("font_size",   cur_font.pointSize() or 10)

        font_row = QHBoxLayout()
        font_row.setSpacing(12)

        fam_col = QVBoxLayout(); fam_col.setSpacing(4)
        fam_lbl = QLabel("Family")
        fam_lbl.setStyleSheet("color:#6C7086; font-size:10px; background:transparent; border:none;")
        fam_col.addWidget(fam_lbl)
        self._fontFamilyCombo = QComboBox()
        self._fontFamilyCombo.addItems(font_choices)
        if saved_fam in font_choices:
            self._fontFamilyCombo.setCurrentText(saved_fam)
        fam_col.addWidget(self._fontFamilyCombo)
        font_row.addLayout(fam_col, stretch=3)

        sz_col = QVBoxLayout(); sz_col.setSpacing(4)
        sz_lbl = QLabel("Size (pt)")
        sz_lbl.setStyleSheet("color:#6C7086; font-size:10px; background:transparent; border:none;")
        sz_col.addWidget(sz_lbl)
        self._fontSizeSpin = QSpinBox()
        self._fontSizeSpin.setRange(7, 20)
        self._fontSizeSpin.setValue(saved_size)
        sz_col.addWidget(self._fontSizeSpin)
        font_row.addLayout(sz_col, stretch=1)

        font_vb.addLayout(font_row)

        self._fontPreview = QLabel("The quick brown fox  |  AaBbCc 012 <>{}[]")
        self._fontPreview.setStyleSheet(
            f"color:#BAC2DE; font-family:'{saved_fam}'; font-size:{saved_size}pt; "
            "background:#11111B; padding:6px 10px; border-radius:4px; border:none;")
        font_vb.addWidget(self._fontPreview)

        def _update_font_preview():
            fam  = self._fontFamilyCombo.currentText()
            size = self._fontSizeSpin.value()
            self._fontPreview.setStyleSheet(
                f"color:#BAC2DE; font-family:'{fam}'; font-size:{size}pt; "
                "background:#11111B; padding:6px 10px; border-radius:4px; border:none;")

        self._fontFamilyCombo.currentTextChanged.connect(_update_font_preview)
        self._fontSizeSpin.valueChanged.connect(_update_font_preview)

        font_apply_btn = QPushButton("Apply Font")
        font_apply_btn.setMinimumHeight(34)

        def _apply_font_clicked():
            fam  = self._fontFamilyCombo.currentText()
            size = self._fontSizeSpin.value()
            _apply_appearance(font_family=fam, font_size=size)
            data = _load_ui_settings()
            data["font_family"] = fam
            data["font_size"]   = size
            _save_ui_settings(data)

        font_apply_btn.clicked.connect(_apply_font_clicked)
        font_vb.addWidget(font_apply_btn)
        vb.addWidget(font_card)

        # ── Theme card ────────────────────────────────────────────────────────
        theme_card, theme_vb = _card("Theme", "#F9E2AF")

        saved_theme = _saved.get("theme", "Catppuccin Mocha")

        th_lbl = QLabel("Color palette")
        th_lbl.setStyleSheet("color:#6C7086; font-size:10px; background:transparent; border:none;")
        theme_vb.addWidget(th_lbl)

        self._themeCombo = QComboBox()
        self._themeCombo.addItems(list(_THEMES.keys()))
        if saved_theme in _THEMES:
            self._themeCombo.setCurrentText(saved_theme)
        theme_vb.addWidget(self._themeCombo)

        # Swatch row – six colored dots previewing the palette
        self._swatchRow = QHBoxLayout()
        self._swatchRow.setSpacing(6)
        self._swatchLabels: list[QLabel] = []
        for _ in range(6):
            sw = QLabel("  ")
            sw.setFixedSize(28, 18)
            sw.setStyleSheet("border-radius:4px;")
            self._swatchLabels.append(sw)
            self._swatchRow.addWidget(sw)
        self._swatchRow.addStretch()
        theme_vb.addLayout(self._swatchRow)

        def _update_swatches(name: str):
            t = _THEMES.get(name, {})
            colors = [t.get("accent",""), t.get("accent2",""), t.get("green",""),
                      t.get("red",""),   t.get("yellow",""), t.get("peach","")]
            for sw, c in zip(self._swatchLabels, colors):
                sw.setStyleSheet(f"background:{c}; border-radius:4px; border:none;")

        _update_swatches(saved_theme)
        self._themeCombo.currentTextChanged.connect(_update_swatches)

        theme_apply_btn = QPushButton("Apply Theme")
        theme_apply_btn.setMinimumHeight(34)

        def _apply_theme_clicked():
            name = self._themeCombo.currentText()
            _apply_appearance(theme_name=name)
            data = _load_ui_settings()
            data["theme"] = name
            _save_ui_settings(data)

        theme_apply_btn.clicked.connect(_apply_theme_clicked)
        theme_vb.addWidget(theme_apply_btn)
        vb.addWidget(theme_card)

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

        # Apply-port button (aligned to bottom of the row, beside the port field)
        apply_col = QVBoxLayout()
        apply_col.setSpacing(4)
        apply_col.addWidget(QLabel(""))   # spacer label to match the row height
        self._proxyApplyBtn = QPushButton("Apply")
        self._proxyApplyBtn.setFixedHeight(28)
        self._proxyApplyBtn.setToolTip("Save port and restart proxy")
        self._proxyApplyBtn.clicked.connect(self._apply_proxy_port)
        apply_col.addWidget(self._proxyApplyBtn)
        field_row.addLayout(apply_col)

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

    def _apply_proxy_port(self):
        """Save the port from the field to settings and restart the global proxy."""
        raw = self._proxyPortEdit.text().strip()
        try:
            port = int(raw)
            if not (1 <= port <= 65535):
                raise ValueError
        except ValueError:
            self._proxyPortEdit.setStyleSheet(
                "QLineEdit { border:1px solid #F38BA8; background:#181825; "
                "color:#CDD6F4; border-radius:4px; padding:2px 6px; }")
            return

        self._proxyPortEdit.setStyleSheet("")   # clear any error highlight

        # Persist to shared settings file
        data = _load_ui_settings()
        data["proxy_port"] = port
        _save_ui_settings(data)

        # Restart the global proxy on the new port
        self.proxy_port = port
        try:
            self.topParent.startproxy()
            # Update the browser proxy config if it was already enabled
            if self.proxy_status:
                self.proxy.setPort(port)
                from PySide6.QtNetwork import QNetworkProxy
                QNetworkProxy.setApplicationProxy(self.proxy)
        except Exception:
            pass

        self._refresh_proxy_status()

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
