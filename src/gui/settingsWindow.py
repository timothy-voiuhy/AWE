"""
Project settings window — API keys, tool paths, scan defaults.
"""
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QDialog, QDialogButtonBox, QFormLayout, QFrame, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QScrollArea, QSizePolicy, QTabWidget,
    QVBoxLayout, QWidget,
)

from containers.tool_registry import TOOL_REGISTRY
from database.settings_repository import DEFAULTS, Keys, SettingsRepository


class SettingsWindow(QDialog):
    def __init__(self, project_dir: str, mongo_uri: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Project Settings")
        self.resize(720, 520)
        self._repo = SettingsRepository(project_dir, mongo_uri)
        self._fields: dict[str, QLineEdit] = {}
        # tool_key → QLineEdit holding the override command
        self._cmd_fields: dict[str, QLineEdit] = {}

        vbox = QVBoxLayout(self)
        vbox.setSpacing(8)

        tabs = QTabWidget()
        tabs.addTab(self._build_api_tab(),      "API Keys")
        tabs.addTab(self._build_tools_tab(),    "Tool Config")
        tabs.addTab(self._build_scan_tab(),     "Scan Defaults")
        tabs.addTab(self._build_cmd_tab(),      "Tool Commands")
        vbox.addWidget(tabs)

        buttons = QDialogButtonBox(
            QDialogButtonBox.Save | QDialogButtonBox.Cancel
        )
        buttons.accepted.connect(self._save)
        buttons.rejected.connect(self.reject)
        vbox.addWidget(buttons)

        self._load()

    # ── Tabs ──────────────────────────────────────────────────────────────────

    def _build_api_tab(self) -> QWidget:
        w = QWidget()
        form = QFormLayout(w)
        self._add_field(form, Keys.GITHUB_TOKEN, "GitHub Token",
                        placeholder="ghp_…", secret=True)
        self._add_field(form, Keys.SHODAN_KEY,   "Shodan API Key",
                        placeholder="Optional", secret=True)
        form.addRow(self._note(
            "GitHub token is used by GitHub Recon. "
            "Shodan key reserved for future tools."
        ))
        return w

    def _build_tools_tab(self) -> QWidget:
        w = QWidget()
        form = QFormLayout(w)
        self._add_field(form, Keys.RESOLVER_PATH,
                        "Resolver list (container path)",
                        placeholder=DEFAULTS[Keys.RESOLVER_PATH])
        self._add_field(form, Keys.DEFAULT_WORDLIST,
                        "Default wordlist (container path)",
                        placeholder=DEFAULTS[Keys.DEFAULT_WORDLIST])
        self._add_field(form, Keys.NUCLEI_TEMPLATES,
                        "Nuclei templates path (optional)",
                        placeholder="/root/nuclei-templates")
        form.addRow(self._note(
            "Paths are inside the Docker container. "
            "Mount your wordlists by adding volume entries to the relevant Dockerfile."
        ))
        return w

    def _build_scan_tab(self) -> QWidget:
        w = QWidget()
        form = QFormLayout(w)
        self._add_field(form, Keys.DEFAULT_THREADS,
                        "Default threads",     placeholder=DEFAULTS[Keys.DEFAULT_THREADS])
        self._add_field(form, Keys.DEFAULT_RATE_LIMIT,
                        "Default rate limit",  placeholder=DEFAULTS[Keys.DEFAULT_RATE_LIMIT])
        self._add_field(form, Keys.DEFAULT_CONCURRENCY,
                        "Default concurrency", placeholder=DEFAULTS[Keys.DEFAULT_CONCURRENCY])
        return w

    def _build_cmd_tab(self) -> QWidget:
        """
        Scrollable per-tool command override editor.

        Each row shows:
          [Tool name badge]  [editable command QLineEdit]  [Reset ↺]

        The placeholder text is the default command rendered with a dummy
        domain so the user can see exactly what will run.

        Unsaved indicator: when a field differs from the saved override (or
        the placeholder when no override exists), the row is highlighted.
        A global "Reset All to Defaults" button clears every override.
        """
        outer = QWidget()
        outer_vb = QVBoxLayout(outer)
        outer_vb.setContentsMargins(8, 8, 8, 4)
        outer_vb.setSpacing(6)

        # ── header row ────────────────────────────────────────────────────────
        hdr = QHBoxLayout()
        info = QLabel(
            "Override the command run inside each tool's container.  "
            "Leave blank to use the built-in default.  "
            "Use <b>{domain}</b>, <b>{url}</b>, <b>{input_file}</b> etc. as "
            "placeholders — they are substituted at run time."
        )
        info.setObjectName("certDialogSubtitle")
        info.setWordWrap(True)
        hdr.addWidget(info, stretch=1)

        reset_all_btn = QPushButton("Reset All")
        reset_all_btn.setToolTip("Remove every command override (revert all tools to defaults)")
        reset_all_btn.setFixedHeight(26)
        reset_all_btn.setStyleSheet(
            "QPushButton{background:#3B1F1F;color:#F38BA8;"
            "border:1px solid #F38BA8;border-radius:4px;"
            "padding:0 12px;font-size:9px;}"
            "QPushButton:hover{background:#4D2A2A;}"
        )
        reset_all_btn.clicked.connect(self._reset_all_commands)
        hdr.addWidget(reset_all_btn)
        outer_vb.addLayout(hdr)

        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setObjectName("certDivider")
        outer_vb.addWidget(sep)

        # ── scrollable tool list ──────────────────────────────────────────────
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll_w = QWidget()
        scroll_vb = QVBoxLayout(scroll_w)
        scroll_vb.setContentsMargins(0, 0, 0, 0)
        scroll_vb.setSpacing(3)

        # Group tools by category with a small section header
        from collections import defaultdict
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

        for cat, tools in by_cat.items():
            # section label
            cat_lbl = QLabel(_CAT_LABEL.get(cat, cat.title()))
            cat_lbl.setStyleSheet(
                "color:#6C7086; font-size:9px; font-weight:bold;"
                " padding:6px 0 2px 2px; background:transparent;"
            )
            scroll_vb.addWidget(cat_lbl)

            for tool_key, tool in tools:
                row_w = self._build_cmd_row(tool_key, tool)
                scroll_vb.addWidget(row_w)

        scroll_vb.addStretch()
        scroll.setWidget(scroll_w)
        outer_vb.addWidget(scroll, stretch=1)

        return outer

    def _build_cmd_row(self, tool_key: str, tool) -> QWidget:
        """One tool row: name badge | command edit | reset button."""
        row = QWidget()
        hl = QHBoxLayout(row)
        hl.setContentsMargins(0, 1, 0, 1)
        hl.setSpacing(6)

        # Tool name badge
        name_lbl = QLabel(tool.display_name)
        name_lbl.setFixedWidth(130)
        name_lbl.setFont(QFont("Cascadia Code", 9))
        name_lbl.setStyleSheet(
            "color:#CDD6F4; background:#252540; border-radius:3px;"
            " padding:2px 6px; font-size:9px;"
        )
        hl.addWidget(name_lbl)

        # Render the default command as placeholder text
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
        edit.setFont(QFont("Cascadia Code", 9))
        edit.setObjectName("urlText")
        edit.setToolTip(
            f"Default: {default_cmd}\n\n"
            "Leave blank to use the default. "
            "Placeholders: {domain} {url} {target} {input_file} {wordlist} etc."
        )
        hl.addWidget(edit, stretch=1)

        # Per-row reset button
        rst_btn = QPushButton("Reset")
        rst_btn.setFixedHeight(26)
        rst_btn.setFixedWidth(48)
        rst_btn.setToolTip(f"Reset {tool.display_name} to built-in default")
        rst_btn.setStyleSheet(
            "QPushButton{background:#313244;color:#6C7086;"
            "border:1px solid #45475A;border-radius:4px;"
            "font-size:9px;padding:0 4px;}"
            "QPushButton:hover{background:#45475A;color:#F38BA8;"
            "border-color:#F38BA8;}"
        )
        rst_btn.clicked.connect(lambda _=False, e=edit: self._reset_cmd_row(e))
        hl.addWidget(rst_btn)

        self._cmd_fields[tool_key] = edit
        return row

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _add_field(self, form: QFormLayout, key: str, label: str,
                   placeholder: str = "", secret: bool = False):
        edit = QLineEdit()
        edit.setPlaceholderText(placeholder)
        if secret:
            edit.setEchoMode(QLineEdit.Password)
        self._fields[key] = edit
        form.addRow(label + ":", edit)

    @staticmethod
    def _note(text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setObjectName("certDialogSubtitle")
        lbl.setWordWrap(True)
        return lbl

    def _load(self):
        # Standard fields
        all_settings = self._repo.get_all()
        for key, edit in self._fields.items():
            val = all_settings.get(key, DEFAULTS.get(key, ""))
            edit.setText(str(val) if val else "")

        # Tool command overrides
        overrides = self._repo.get_all_tool_commands()
        for tool_key, edit in self._cmd_fields.items():
            edit.setText(overrides.get(tool_key, ""))

    def _save(self):
        # Standard settings
        mapping = {}
        for key, edit in self._fields.items():
            val = edit.text().strip()
            if val:
                mapping[key] = val
            else:
                default = DEFAULTS.get(key)
                if default:
                    mapping[key] = default
        self._repo.set_many(mapping)

        # Tool command overrides — save non-empty, delete empty (= reset to default)
        for tool_key, edit in self._cmd_fields.items():
            val = edit.text().strip()
            if val:
                self._repo.set_tool_command(tool_key, val)
            else:
                self._repo.reset_tool_command(tool_key)

        self.accept()

    def _reset_cmd_row(self, edit: QLineEdit):
        """Clear a single override field (row-level reset button)."""
        edit.clear()
        # Visual feedback: briefly tint the field green
        edit.setStyleSheet("QLineEdit{border:1px solid #A6E3A1;}")
        from PySide6.QtCore import QTimer
        QTimer.singleShot(800, lambda: edit.setStyleSheet(""))

    def _reset_all_commands(self):
        """Clear every command override field in the UI (does not save yet)."""
        for edit in self._cmd_fields.values():
            edit.clear()
        # Persist the reset immediately so it's not lost if dialog is cancelled
        self._repo.reset_all_tool_commands()
        # Visual feedback on the button is handled by the stylesheet hover
