"""
Unified settings — embedded QWidget page (used in TargetWindow nav bar)
and a thin QDialog wrapper (used from PipelineWindow).

Tabs:
  Appearance | Proxy | Certificate | Match & Replace |
  API Keys | Tools | Scan | Tool Commands | Display
"""
from __future__ import annotations

import json
import uuid
from collections import defaultdict
from pathlib import Path

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QFontDatabase
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QDialog, QDialogButtonBox,
    QFrame, QHBoxLayout, QLabel, QLineEdit, QMenu,
    QPushButton, QScrollArea, QSpinBox, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QWidget, QTabWidget,
)

from containers.tool_registry import TOOL_REGISTRY
from database.settings_repository import DEFAULTS, Keys, SettingsRepository
from gui.appearance import (
    THEMES, MONO_FONTS,
    load_ui_settings, save_ui_settings, apply_appearance,
)
from gui.certSetupDialog import CertSetupWidget

# ── Palette constants ─────────────────────────────────────────────────────────
_BG      = "#1E1E2E"
_MANTLE  = "#181825"
_SURFACE = "#313244"
_DIM     = "#6C7086"
_TEXT    = "#CDD6F4"
_RED     = "#F38BA8"
_GREEN   = "#A6E3A1"

_BTN_RED = (
    "QPushButton{background:#3B1F1F;color:#F38BA8;"
    "border:1px solid #F38BA8;border-radius:4px;"
    "padding:0 12px;min-height:26px;font-size:9pt;}"
    "QPushButton:hover{background:#4D2A2A;}"
)
_BTN_MUTED = (
    "QPushButton{background:#313244;color:#6C7086;"
    "border:1px solid #45475A;border-radius:4px;"
    "min-height:26px;font-size:9pt;padding:0 8px;}"
    "QPushButton:hover{background:#45475A;color:#F38BA8;border-color:#F38BA8;}"
)


_BROWSER_UA = {
    "Chrome":  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Firefox": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
}

# ── Small layout helpers ──────────────────────────────────────────────────────

def _hline() -> QFrame:
    f = QFrame()
    f.setFrameShape(QFrame.HLine)
    f.setFixedHeight(1)
    f.setStyleSheet(f"background:{_SURFACE};border:none;")
    return f


def _section_label(text: str) -> QLabel:
    lbl = QLabel(text.upper())
    lbl.setStyleSheet(
        f"color:{_DIM};font-size:8pt;font-weight:bold;"
        "letter-spacing:0.8px;background:transparent;"
    )
    return lbl


def _hint_label(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setWordWrap(True)
    lbl.setStyleSheet(f"color:{_DIM};font-size:8pt;background:transparent;")
    return lbl


# ── Rules file ────────────────────────────────────────────────────────────────

def _rules_file() -> Path:
    return Path.home() / ".config" / "awe" / "proxy_rules.json"



class SettingsWidget(QWidget):
    """
    Embedded settings page — drop straight into a QStackedWidget.

    Parameters
    ----------
    project_dir : str
        Per-project directory (for SettingsRepository).
    mongo_uri : str
        MongoDB connection string.
    proxy_port : int
        Current proxy listen port (used to pre-populate the Proxy tab).
    proxy_status : bool
        Whether the proxy is currently enabled.
    target_window : optional
        The TargetWindow instance — used to call HandleProxy / OpenCertSetup /
        startproxy on the top-level parent.  May be None when opened standalone.
    """

    def __init__(
        self,
        project_dir: str,
        mongo_uri: str = "mongodb://localhost:27017",
        proxy_port: int = 8080,
        proxy_status: bool = False,
        target_window=None,
        parent=None,
    ):
        super().__init__(parent)
        self._project_dir   = project_dir
        self._proxy_port    = proxy_port
        self._proxy_status  = proxy_status
        self._target_window = target_window
        self._repo          = SettingsRepository(project_dir, mongo_uri)
        self._fields:     dict[str, QLineEdit] = {}
        self._cmd_fields: dict[str, QLineEdit] = {}

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        self._tabs = QTabWidget()
        self._tabs.addTab(self._build_appearance_tab(),   "Appearance")
        self._tabs.addTab(self._build_proxy_tab(),        "Proxy")
        self._tabs.addTab(self._build_api_tab(),          "API Keys")
        self._tabs.addTab(self._build_tools_tab(),        "Tools")
        self._tabs.addTab(self._build_scan_tab(),         "Scan")
        self._tabs.addTab(self._build_cmd_tab(),          "Tool Commands")
        root.addWidget(self._tabs, stretch=1)

        footer = QWidget()
        footer.setStyleSheet(f"background:{_MANTLE};border-top:1px solid {_SURFACE};")
        fl = QHBoxLayout(footer)
        fl.setContentsMargins(16, 10, 16, 10)
        fl.addStretch()
        self._saveBtn = QPushButton("Save")
        self._saveBtn.setMinimumWidth(90)
        self._saveBtn.setMinimumHeight(30)
        self._saveBtn.clicked.connect(self._save_with_feedback)
        fl.addWidget(self._saveBtn)
        root.addWidget(footer)

        self._load()

    # ── Appearance tab ────────────────────────────────────────────────────────

    def _build_appearance_tab(self) -> QWidget:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        body = QWidget()
        vb = QVBoxLayout(body)
        vb.setContentsMargins(28, 24, 28, 24)
        vb.setSpacing(0)

        _saved = load_ui_settings()

        # ── Font section ──────────────────────────────────────────────────────
        vb.addWidget(_section_label("Font"))
        vb.addSpacing(8)

        db = QFontDatabase()
        available = set(db.families())
        font_choices = [f for f in MONO_FONTS if f in available] or ["Monospace"]

        cur_font   = QApplication.instance().font()
        saved_fam  = _saved.get("font_family", cur_font.family())
        saved_size = _saved.get("font_size", cur_font.pointSize() or 10)

        font_row = QHBoxLayout()
        font_row.setSpacing(12)

        fam_col = QVBoxLayout(); fam_col.setSpacing(4)
        fam_col.addWidget(_hint_label("Family"))
        self._fontFamilyCombo = QComboBox()
        self._fontFamilyCombo.addItems(font_choices)
        if saved_fam in font_choices:
            self._fontFamilyCombo.setCurrentText(saved_fam)
        fam_col.addWidget(self._fontFamilyCombo)
        font_row.addLayout(fam_col, stretch=3)

        sz_col = QVBoxLayout(); sz_col.setSpacing(4)
        sz_col.addWidget(_hint_label("Size (pt)"))
        self._fontSizeSpin = QSpinBox()
        self._fontSizeSpin.setRange(7, 20)
        self._fontSizeSpin.setValue(saved_size)
        sz_col.addWidget(self._fontSizeSpin)
        font_row.addLayout(sz_col, stretch=1)

        vb.addLayout(font_row)
        vb.addSpacing(8)

        self._fontPreview = QLabel("The quick brown fox  |  AaBbCc 012 <>{}[]")
        self._fontPreview.setStyleSheet(
            f"color:#BAC2DE; font-family:'{saved_fam}'; font-size:{saved_size}pt;"
            " background:#11111B; padding:6px 10px; border-radius:4px; border:none;"
        )
        vb.addWidget(self._fontPreview)
        vb.addSpacing(8)

        def _update_font_preview():
            fam  = self._fontFamilyCombo.currentText()
            size = self._fontSizeSpin.value()
            self._fontPreview.setStyleSheet(
                f"color:#BAC2DE; font-family:'{fam}'; font-size:{size}pt;"
                " background:#11111B; padding:6px 10px; border-radius:4px; border:none;"
            )

        self._fontFamilyCombo.currentTextChanged.connect(_update_font_preview)
        self._fontSizeSpin.valueChanged.connect(_update_font_preview)

        font_apply_btn = QPushButton("Apply Font")
        font_apply_btn.clicked.connect(self._apply_font)
        vb.addWidget(font_apply_btn)
        vb.addSpacing(24)
        vb.addWidget(_hline())
        vb.addSpacing(24)

        # ── Theme section ─────────────────────────────────────────────────────
        vb.addWidget(_section_label("Theme"))
        vb.addSpacing(8)
        vb.addWidget(_hint_label("Color palette"))
        vb.addSpacing(4)

        saved_theme = _saved.get("theme", "Catppuccin Mocha")
        self._themeCombo = QComboBox()
        self._themeCombo.addItems(list(THEMES.keys()))
        if saved_theme in THEMES:
            self._themeCombo.setCurrentText(saved_theme)
        vb.addWidget(self._themeCombo)
        vb.addSpacing(8)

        swatch_row = QHBoxLayout(); swatch_row.setSpacing(6)
        self._swatchLabels: list[QLabel] = []
        for _ in range(6):
            sw = QLabel("  ")
            sw.setFixedSize(28, 18)
            sw.setStyleSheet("border-radius:4px;")
            self._swatchLabels.append(sw)
            swatch_row.addWidget(sw)
        swatch_row.addStretch()
        vb.addLayout(swatch_row)
        vb.addSpacing(8)

        def _update_swatches(name: str):
            t = THEMES.get(name, {})
            colors = [t.get("accent",""), t.get("accent2",""), t.get("green",""),
                      t.get("red",""),   t.get("yellow",""), t.get("peach","")]
            for sw, c in zip(self._swatchLabels, colors):
                sw.setStyleSheet(f"background:{c}; border-radius:4px; border:none;")

        _update_swatches(saved_theme)
        self._themeCombo.currentTextChanged.connect(_update_swatches)

        theme_apply_btn = QPushButton("Apply Theme")
        theme_apply_btn.clicked.connect(self._apply_theme)
        vb.addWidget(theme_apply_btn)
        vb.addSpacing(24)
        vb.addWidget(_hline())
        vb.addSpacing(24)

        # ── Browser section ───────────────────────────────────────────────────
        vb.addWidget(_section_label("Browser"))
        vb.addSpacing(8)
        vb.addWidget(_hint_label(
            "User-agent the embedded browser reports to websites. "
            "Changes apply immediately to all open tabs."
        ))
        vb.addSpacing(4)

        saved_browser = _saved.get("browser_engine", "Chrome")
        self._browserCombo = QComboBox()
        self._browserCombo.addItems(["Chrome", "Firefox"])
        if saved_browser in ("Chrome", "Firefox"):
            self._browserCombo.setCurrentText(saved_browser)
        vb.addWidget(self._browserCombo)
        vb.addSpacing(8)

        self._browserApplyBtn = QPushButton("Apply Browser")
        self._browserApplyBtn.clicked.connect(self._apply_browser)
        vb.addWidget(self._browserApplyBtn)
        vb.addSpacing(24)
        vb.addWidget(_hline())
        vb.addSpacing(24)

        # ── Editor font size ──────────────────────────────────────────────────
        vb.addWidget(_section_label("Code Editor Font Size"))
        vb.addSpacing(6)
        editor_font_edit = QLineEdit()
        editor_font_edit.setPlaceholderText(DEFAULTS[Keys.EDITOR_FONT_SIZE])
        self._fields[Keys.EDITOR_FONT_SIZE] = editor_font_edit
        vb.addWidget(editor_font_edit)
        vb.addSpacing(5)
        vb.addWidget(_hint_label(
            "Point size used in request / response editors and the WebSocket viewer. "
            "Reopen editors to apply."
        ))
        vb.addStretch()

        scroll.setWidget(body)
        return scroll

    def _apply_font(self):
        fam  = self._fontFamilyCombo.currentText()
        size = self._fontSizeSpin.value()
        apply_appearance(font_family=fam, font_size=size)
        data = load_ui_settings()
        data["font_family"] = fam
        data["font_size"]   = size
        save_ui_settings(data)

    def _apply_theme(self):
        name = self._themeCombo.currentText()
        apply_appearance(theme_name=name)
        data = load_ui_settings()
        data["theme"] = name
        save_ui_settings(data)

    def _apply_browser(self):
        from PySide6.QtWebEngineCore import QWebEngineProfile
        name = self._browserCombo.currentText()
        ua = _BROWSER_UA.get(name, _BROWSER_UA["Chrome"])
        QWebEngineProfile.defaultProfile().setHttpUserAgent(ua)
        data = load_ui_settings()
        data["browser_engine"] = name
        save_ui_settings(data)

        # Reload all open browser tabs so the new UA takes effect immediately
        if self._target_window and hasattr(self._target_window, "browserTabWidget"):
            tw = self._target_window.browserTabWidget
            for i in range(tw.count()):
                w = tw.widget(i)
                if hasattr(w, "browser"):
                    w.browser.reload()

        self._browserApplyBtn.setText(f"Applied — {name}")
        self._browserApplyBtn.setEnabled(False)
        QTimer.singleShot(1500, lambda: (
            self._browserApplyBtn.setText("Apply Browser"),
            self._browserApplyBtn.setEnabled(True),
        ))

    # ── Proxy tab (listen address + toggle + upstream + M&R + certificate) ──────

    def _build_proxy_tab(self) -> QWidget:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        body = QWidget()
        vb = QVBoxLayout(body)
        vb.setContentsMargins(28, 24, 28, 24)
        vb.setSpacing(0)

        # ── Status indicator ──────────────────────────────────────────────────
        self._proxyStatusLbl = QLabel()
        vb.addWidget(self._proxyStatusLbl)
        vb.addSpacing(12)

        # ── Listen address ────────────────────────────────────────────────────
        vb.addWidget(_section_label("Listen Address"))
        vb.addSpacing(6)
        field_row = QHBoxLayout(); field_row.setSpacing(12)

        host_col = QVBoxLayout(); host_col.setSpacing(4)
        host_col.addWidget(_hint_label("Host"))
        self._proxyHostEdit = QLineEdit("127.0.0.1")
        host_col.addWidget(self._proxyHostEdit)
        field_row.addLayout(host_col, stretch=3)

        port_col = QVBoxLayout(); port_col.setSpacing(4)
        port_col.addWidget(_hint_label("Port"))
        self._proxyPortEdit = QLineEdit(str(self._proxy_port))
        port_col.addWidget(self._proxyPortEdit)
        field_row.addLayout(port_col, stretch=1)

        apply_col = QVBoxLayout(); apply_col.setSpacing(4)
        apply_col.addWidget(QLabel(""))
        self._proxyApplyBtn = QPushButton("Apply")
        self._proxyApplyBtn.setFixedHeight(28)
        self._proxyApplyBtn.setToolTip("Save port and restart proxy")
        self._proxyApplyBtn.clicked.connect(self._apply_proxy_port)
        apply_col.addWidget(self._proxyApplyBtn)
        field_row.addLayout(apply_col)
        vb.addLayout(field_row)
        vb.addSpacing(12)

        self._proxyToggleBtn = QPushButton("Enable Proxy")
        self._proxyToggleBtn.setMinimumHeight(34)
        self._proxyToggleBtn.clicked.connect(self._toggle_proxy)
        vb.addWidget(self._proxyToggleBtn)
        vb.addSpacing(24)
        vb.addWidget(_hline())
        vb.addSpacing(24)

        # ── Upstream proxy ────────────────────────────────────────────────────
        vb.addWidget(_section_label("Upstream Proxy"))
        vb.addSpacing(6)
        vb.addWidget(_hint_label(
            "Route all proxy traffic through an upstream proxy (e.g. Tor, Burp, ZAP). "
            "Changes take effect after restarting the proxy."
        ))
        vb.addSpacing(8)

        self._upstreamEnable = QCheckBox("Enable upstream proxy")
        self._upstreamEnable.setStyleSheet("color:#CDD6F4; font-size:10px; background:transparent;")
        vb.addWidget(self._upstreamEnable)
        vb.addSpacing(6)

        up_row = QHBoxLayout(); up_row.setSpacing(6)
        self._upstreamUrlEdit = QLineEdit()
        self._upstreamUrlEdit.setPlaceholderText("http://127.0.0.1:9050")
        up_row.addWidget(self._upstreamUrlEdit, stretch=1)
        up_apply_btn = QPushButton("Apply")
        up_apply_btn.setFixedHeight(28)
        up_apply_btn.clicked.connect(self._apply_upstream_proxy)
        up_row.addWidget(up_apply_btn)
        vb.addLayout(up_row)

        _ups = load_ui_settings()
        _ups_url = _ups.get("upstream_proxy", "")
        self._upstreamEnable.setChecked(bool(_ups_url))
        self._upstreamUrlEdit.setText(_ups_url or "")
        vb.addSpacing(24)
        vb.addWidget(_hline())
        vb.addSpacing(24)

        # ── Match & Replace ───────────────────────────────────────────────────
        vb.addWidget(_section_label("Match & Replace"))
        vb.addSpacing(6)
        vb.addWidget(_hint_label(
            "Rules are applied to every proxied request and response in order. "
            "Pattern is a Python regex; replacement supports \\1 back-references. "
            "Changes apply immediately — no restart needed."
        ))
        vb.addSpacing(8)

        self._rulesTable = QTableWidget(0, 5)
        self._rulesTable.setHorizontalHeaderLabels(
            ["✓", "Applies To", "Pattern", "Replacement", "Comment"]
        )
        self._rulesTable.verticalHeader().setVisible(False)
        self._rulesTable.setColumnWidth(0, 28)
        self._rulesTable.setColumnWidth(1, 130)
        self._rulesTable.setColumnWidth(2, 180)
        self._rulesTable.setColumnWidth(3, 180)
        self._rulesTable.horizontalHeader().setStretchLastSection(True)
        self._rulesTable.setMinimumHeight(160)
        self._rulesTable.setEditTriggers(QTableWidget.NoEditTriggers)
        self._rulesTable.setContextMenuPolicy(Qt.CustomContextMenu)
        self._rulesTable.customContextMenuRequested.connect(self._rules_context_menu)
        vb.addWidget(self._rulesTable)
        vb.addSpacing(6)

        add_row = QHBoxLayout(); add_row.setSpacing(6)
        self._ruleMatchIn = QComboBox()
        self._ruleMatchIn.addItems([
            "request_headers", "request_body",
            "response_headers", "response_body", "url",
        ])
        self._ruleMatchIn.setFixedHeight(26)
        add_row.addWidget(self._ruleMatchIn)
        self._rulePattern = QLineEdit()
        self._rulePattern.setPlaceholderText("Pattern (regex)")
        self._rulePattern.setFixedHeight(26)
        add_row.addWidget(self._rulePattern, stretch=2)
        self._ruleReplace = QLineEdit()
        self._ruleReplace.setPlaceholderText("Replacement")
        self._ruleReplace.setFixedHeight(26)
        add_row.addWidget(self._ruleReplace, stretch=2)
        self._ruleComment = QLineEdit()
        self._ruleComment.setPlaceholderText("Comment (optional)")
        self._ruleComment.setFixedHeight(26)
        add_row.addWidget(self._ruleComment, stretch=1)
        add_btn = QPushButton("+ Add")
        add_btn.setFixedHeight(26)
        add_btn.clicked.connect(self._add_rule)
        add_row.addWidget(add_btn)
        vb.addLayout(add_row)
        vb.addSpacing(24)
        vb.addWidget(_hline())
        vb.addSpacing(24)

        # ── Certificate ───────────────────────────────────────────────────────
        vb.addWidget(_section_label("CA Certificate"))
        vb.addSpacing(8)
        vb.addWidget(CertSetupWidget())
        vb.addStretch()

        scroll.setWidget(body)
        self._load_rules()
        self._refresh_proxy_status()
        return scroll

    def _refresh_proxy_status(self):
        dot   = "●" if self._proxy_status else "○"
        color = _GREEN if self._proxy_status else _RED
        port  = self._proxyPortEdit.text() if hasattr(self, "_proxyPortEdit") else str(self._proxy_port)
        host  = self._proxyHostEdit.text() if hasattr(self, "_proxyHostEdit") else "127.0.0.1"
        text  = f"Enabled — {host}:{port}" if self._proxy_status else "Disabled"
        if hasattr(self, "_proxyStatusLbl"):
            self._proxyStatusLbl.setText(
                f"<span style='color:{color};'>{dot}</span>"
                f"<span style='color:#CDD6F4;'>&nbsp; {text}</span>"
            )
        if hasattr(self, "_proxyToggleBtn"):
            self._proxyToggleBtn.setText("Disable Proxy" if self._proxy_status else "Enable Proxy")

    def _apply_proxy_port(self):
        raw = self._proxyPortEdit.text().strip()
        try:
            port = int(raw)
            if not (1 <= port <= 65535):
                raise ValueError
        except ValueError:
            self._proxyPortEdit.setStyleSheet(
                "QLineEdit{border:1px solid #F38BA8;background:#181825;"
                "color:#CDD6F4;border-radius:4px;padding:2px 6px;}"
            )
            return
        self._proxyPortEdit.setStyleSheet("")
        self._proxy_port = port
        data = load_ui_settings()
        data["proxy_port"] = port
        save_ui_settings(data)
        if self._target_window:
            try:
                self._target_window.proxy_port = port
                self._target_window.topParent.startproxy()
                if self._target_window.proxy_status:
                    self._target_window.proxy.setPort(port)
                    from PySide6.QtNetwork import QNetworkProxy
                    QNetworkProxy.setApplicationProxy(self._target_window.proxy)
            except Exception:
                pass
        self._refresh_proxy_status()

    def _toggle_proxy(self):
        try:
            self._proxy_port = int(self._proxyPortEdit.text())
        except ValueError:
            self._proxyPortEdit.setStyleSheet(
                "QLineEdit{border:1px solid #F38BA8;background:#181825;"
                "color:#CDD6F4;border-radius:4px;padding:2px 6px;}"
            )
            return
        if self._target_window:
            self._target_window.proxy_port = self._proxy_port
            self._target_window.HandleProxy()
            self._proxy_status = self._target_window.proxy_status
        self._refresh_proxy_status()

    def _apply_upstream_proxy(self):
        enabled = self._upstreamEnable.isChecked()
        url     = self._upstreamUrlEdit.text().strip() if enabled else ""
        data    = load_ui_settings()
        data["upstream_proxy"] = url
        save_ui_settings(data)
        if self._target_window:
            try:
                self._target_window.topParent.startproxy()
            except Exception:
                pass

    def _load_rules(self):
        try:
            rules = json.loads(_rules_file().read_text())
        except Exception:
            rules = []
        self._rulesTable.setRowCount(0)
        for rule in rules:
            self._append_rule_row(rule)

    def _save_and_push_rules(self):
        rules = []
        for r in range(self._rulesTable.rowCount()):
            cb = self._rulesTable.cellWidget(r, 0)
            rules.append({
                "id":          self._rulesTable.item(r, 1).data(Qt.UserRole) or str(uuid.uuid4())[:8],
                "enabled":     cb.isChecked() if cb else True,
                "match_in":    self._rulesTable.item(r, 1).text(),
                "pattern":     self._rulesTable.item(r, 2).text(),
                "replacement": self._rulesTable.item(r, 3).text(),
                "comment":     self._rulesTable.item(r, 4).text() if self._rulesTable.item(r, 4) else "",
            })
        _rules_file().parent.mkdir(parents=True, exist_ok=True)
        _rules_file().write_text(json.dumps(rules, indent=2))
        try:
            from proxy._control import ControlClient
            from config.config import RUNDIR
            port_file = Path(RUNDIR) / "tmp" / "proxy_control.txt"
            port = int(port_file.read_text().strip())
            ControlClient(port).set_rules(rules)
        except Exception:
            pass

    def _append_rule_row(self, rule: dict):
        r = self._rulesTable.rowCount()
        self._rulesTable.insertRow(r)
        cb = QCheckBox()
        cb.setChecked(rule.get("enabled", True))
        cb.stateChanged.connect(lambda: self._save_and_push_rules())
        self._rulesTable.setCellWidget(r, 0, cb)
        for col, key in enumerate(["match_in", "pattern", "replacement", "comment"], start=1):
            item = QTableWidgetItem(rule.get(key, ""))
            if col == 1:
                item.setData(Qt.UserRole, rule.get("id", ""))
            self._rulesTable.setItem(r, col, item)
        self._rulesTable.setRowHeight(r, 24)

    def _add_rule(self):
        pattern = self._rulePattern.text().strip()
        if not pattern:
            return
        rule = {
            "id":          str(uuid.uuid4())[:8],
            "enabled":     True,
            "match_in":    self._ruleMatchIn.currentText(),
            "pattern":     pattern,
            "replacement": self._ruleReplace.text(),
            "comment":     self._ruleComment.text().strip(),
        }
        self._append_rule_row(rule)
        self._rulePattern.clear()
        self._ruleReplace.clear()
        self._ruleComment.clear()
        self._save_and_push_rules()

    def _rules_context_menu(self, pos):
        row = self._rulesTable.rowAt(pos.y())
        if row < 0:
            return
        menu = QMenu(self)
        rm = menu.addAction("Remove Rule")
        if menu.exec(self._rulesTable.mapToGlobal(pos)) is rm:
            self._rulesTable.removeRow(row)
            self._save_and_push_rules()

    # ── MongoDB-backed tabs ───────────────────────────────────────────────────

    def _build_api_tab(self) -> QWidget:
        return self._flat_tab([
            (Keys.GITHUB_TOKEN, "GitHub Token",
             "Used by GitHub Recon. Format: ghp_…", "ghp_…", True),
            (Keys.SHODAN_KEY, "Shodan API Key",
             "Reserved for future tools. Leave blank if unused.", "Optional", True),
        ])

    def _build_tools_tab(self) -> QWidget:
        return self._flat_tab([
            (Keys.RESOLVER_PATH, "Resolver List",
             f"Path inside the Docker container. Default: {DEFAULTS[Keys.RESOLVER_PATH]}",
             DEFAULTS[Keys.RESOLVER_PATH], False),
            (Keys.DEFAULT_WORDLIST, "Default Wordlist",
             f"Path inside the Docker container. Default: {DEFAULTS[Keys.DEFAULT_WORDLIST]}",
             DEFAULTS[Keys.DEFAULT_WORDLIST], False),
            (Keys.NUCLEI_TEMPLATES, "Nuclei Templates Path",
             "Optional override. Mount your templates via volume entries in the relevant Dockerfile.",
             "/root/nuclei-templates", False),
        ])

    def _build_scan_tab(self) -> QWidget:
        return self._flat_tab([
            (Keys.DEFAULT_THREADS, "Default Threads",
             "Concurrency passed to tools that accept a thread count.",
             DEFAULTS[Keys.DEFAULT_THREADS], False),
            (Keys.DEFAULT_RATE_LIMIT, "Default Rate Limit",
             "Requests per second cap for rate-limited tools.",
             DEFAULTS[Keys.DEFAULT_RATE_LIMIT], False),
            (Keys.DEFAULT_CONCURRENCY, "Default Concurrency",
             "Maximum simultaneous in-flight connections.",
             DEFAULTS[Keys.DEFAULT_CONCURRENCY], False),
        ])

    def _flat_tab(self, entries: list) -> QWidget:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        inner = QWidget()
        vb = QVBoxLayout(inner)
        vb.setContentsMargins(28, 24, 28, 24)
        vb.setSpacing(0)
        for i, (key, heading, hint, placeholder, secret) in enumerate(entries):
            if i > 0:
                vb.addWidget(_hline())
                vb.addSpacing(20)
            vb.addWidget(_section_label(heading))
            vb.addSpacing(6)
            edit = QLineEdit()
            edit.setPlaceholderText(placeholder)
            if secret:
                edit.setEchoMode(QLineEdit.Password)
            self._fields[key] = edit
            vb.addWidget(edit)
            if hint:
                vb.addSpacing(5)
                vb.addWidget(_hint_label(hint))
            vb.addSpacing(20)
        vb.addStretch()
        scroll.setWidget(inner)
        return scroll

    # ── Tool Commands tab ─────────────────────────────────────────────────────

    def _build_cmd_tab(self) -> QWidget:
        outer = QWidget()
        vb = QVBoxLayout(outer)
        vb.setContentsMargins(0, 0, 0, 0)
        vb.setSpacing(0)

        info_bar = QWidget()
        ib = QHBoxLayout(info_bar)
        ib.setContentsMargins(20, 10, 16, 10)
        ib.setSpacing(12)
        info = QLabel(
            "Override the command run inside each tool's container. "
            "Leave blank to use the built-in default.  "
            "Placeholders: <b>{domain}</b>, <b>{url}</b>, <b>{input_file}</b>, "
            "<b>{wordlist}</b>."
        )
        info.setWordWrap(True)
        info.setStyleSheet(f"color:{_DIM};font-size:9pt;background:transparent;")
        ib.addWidget(info, stretch=1)
        rst_all = QPushButton("Reset All")
        rst_all.setStyleSheet(_BTN_RED)
        rst_all.setToolTip("Remove every command override")
        rst_all.clicked.connect(self._reset_all_commands)
        ib.addWidget(rst_all)
        vb.addWidget(info_bar)
        vb.addWidget(_hline())

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        sw = QWidget()
        svb = QVBoxLayout(sw)
        svb.setContentsMargins(20, 12, 20, 12)
        svb.setSpacing(0)

        by_cat: dict[str, list] = defaultdict(list)
        for key, tool in TOOL_REGISTRY.items():
            by_cat[tool.category].append((key, tool))

        _CAT_LABEL = {
            "subdomain": "Subdomain Enumeration",
            "dns":       "DNS",
            "portscan":  "Port Scanning",
            "http":      "HTTP Probing",
            "crawl":     "Crawling & URL Discovery",
            "fuzz":      "Fuzzing",
            "params":    "Parameter Discovery",
            "vuln":      "Vulnerability Scanning",
            "osint":     "OSINT / Cloud",
        }

        first = True
        for cat, tools in by_cat.items():
            if not first:
                svb.addSpacing(6)
                svb.addWidget(_hline())
                svb.addSpacing(6)
            first = False
            svb.addWidget(_section_label(_CAT_LABEL.get(cat, cat.title())))
            svb.addSpacing(6)
            for tool_key, tool in tools:
                svb.addWidget(self._build_cmd_row(tool_key, tool))
                svb.addSpacing(2)

        svb.addStretch()
        scroll.setWidget(sw)
        vb.addWidget(scroll, stretch=1)
        return outer

    def _build_cmd_row(self, tool_key: str, tool) -> QWidget:
        from PySide6.QtGui import QFont as _QFont
        _mono = _QFont("Cascadia Code", 9)
        row = QWidget()
        hl = QHBoxLayout(row)
        hl.setContentsMargins(0, 1, 0, 1)
        hl.setSpacing(8)
        name = QLabel(tool.display_name)
        name.setFixedWidth(132)
        name.setFont(_mono)
        name.setStyleSheet(
            f"color:{_TEXT};background:{_SURFACE};border-radius:3px;"
            " padding:2px 6px;font-size:9px;"
        )
        hl.addWidget(name)
        try:
            default_cmd = tool.build_command(
                domain="<domain>", target="<target>", url="https://<target>",
                host="<target>", query="<target>", keywords="<target>",
                api_key="<api_key>", input_file="<input_file>",
            )
        except Exception:
            default_cmd = ""
        edit = QLineEdit()
        edit.setPlaceholderText(default_cmd)
        edit.setFont(_mono)
        edit.setToolTip(f"Default: {default_cmd}")
        hl.addWidget(edit, stretch=1)
        rst = QPushButton("Reset")
        rst.setFixedSize(54, 26)
        rst.setStyleSheet(_BTN_MUTED)
        rst.clicked.connect(lambda _=False, e=edit: self._reset_cmd_row(e))
        hl.addWidget(rst)
        self._cmd_fields[tool_key] = edit
        return row

    # ── Persistence ───────────────────────────────────────────────────────────

    def _load(self):
        all_settings = self._repo.get_all()
        for key, edit in self._fields.items():
            val = all_settings.get(key, DEFAULTS.get(key, ""))
            edit.setText(str(val) if val else "")
        overrides = self._repo.get_all_tool_commands()
        for tool_key, edit in self._cmd_fields.items():
            edit.setText(overrides.get(tool_key, ""))

    def save(self):
        """Persist all MongoDB-backed fields and tool-command overrides."""
        mapping: dict = {}
        for key, edit in self._fields.items():
            val = edit.text().strip()
            mapping[key] = val if val else (DEFAULTS.get(key) or "")
        self._repo.set_many(mapping)
        for tool_key, edit in self._cmd_fields.items():
            val = edit.text().strip()
            if val:
                self._repo.set_tool_command(tool_key, val)
            else:
                self._repo.reset_tool_command(tool_key)

    def _save_with_feedback(self):
        self.save()
        self._saveBtn.setText("Saved")
        self._saveBtn.setEnabled(False)
        QTimer.singleShot(1500, lambda: (
            self._saveBtn.setText("Save"),
            self._saveBtn.setEnabled(True),
        ))

    def _reset_cmd_row(self, edit: QLineEdit):
        edit.clear()
        edit.setStyleSheet("QLineEdit{border:1px solid #A6E3A1;}")
        QTimer.singleShot(800, lambda: edit.setStyleSheet(""))

    def _reset_all_commands(self):
        for edit in self._cmd_fields.values():
            edit.clear()
        self._repo.reset_all_tool_commands()


# ── Thin dialog wrapper (used by PipelineWindow) ──────────────────────────────

class SettingsWindow(QDialog):
    """Modal dialog that wraps SettingsWidget with Save / Cancel buttons."""

    def __init__(self, project_dir: str, mongo_uri: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.resize(820, 600)

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        self._widget = SettingsWidget(
            project_dir=project_dir,
            mongo_uri=mongo_uri,
            parent=self,
        )
        root.addWidget(self._widget, stretch=1)

        footer = QWidget()
        footer.setStyleSheet(
            f"background:{_MANTLE};border-top:1px solid {_SURFACE};"
        )
        fl = QHBoxLayout(footer)
        fl.setContentsMargins(16, 10, 16, 10)
        fl.addStretch()
        btns = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        btns.accepted.connect(self._save_and_accept)
        btns.rejected.connect(self.reject)
        fl.addWidget(btns)
        root.addWidget(footer)

    def _save_and_accept(self):
        self._widget.save()
        self.accept()
