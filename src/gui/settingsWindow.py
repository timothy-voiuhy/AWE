"""
Project settings window — API keys, tool paths, scan defaults.
"""
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QDialog, QDialogButtonBox, QFormLayout, QFrame, QLabel,
    QLineEdit, QPushButton, QTabWidget, QVBoxLayout, QWidget,
)

from database.settings_repository import DEFAULTS, Keys, SettingsRepository


class SettingsWindow(QDialog):
    def __init__(self, project_dir: str, mongo_uri: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Project Settings")
        self.resize(540, 420)
        self._repo = SettingsRepository(project_dir, mongo_uri)
        self._fields: dict[str, QLineEdit] = {}

        vbox = QVBoxLayout(self)
        vbox.setSpacing(8)

        tabs = QTabWidget()
        tabs.addTab(self._build_api_tab(),     "API Keys")
        tabs.addTab(self._build_tools_tab(),   "Tool Config")
        tabs.addTab(self._build_scan_tab(),    "Scan Defaults")
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
        all_settings = self._repo.get_all()
        for key, edit in self._fields.items():
            val = all_settings.get(key, DEFAULTS.get(key, ""))
            edit.setText(str(val) if val else "")

    def _save(self):
        mapping = {}
        for key, edit in self._fields.items():
            val = edit.text().strip()
            if val:
                mapping[key] = val
            else:
                # Save the default so get() doesn't need special-casing
                default = DEFAULTS.get(key)
                if default:
                    mapping[key] = default
        self._repo.set_many(mapping)
        self.accept()
