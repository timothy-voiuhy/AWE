"""
Testing Methodology tracker — vulnerability testing checklist with descriptions.

Data loaded from resources/methodology/registry.json.
Per-project state persisted as <project_dir>/testing_methodology.json.
Description files live under resources/methodology/descriptions/<category>/<id>.md.
"""

import json
import os
from typing import Optional

from PySide6.QtCore import Qt, Signal, QSize, QPoint
from PySide6.QtGui import QColor, QFont, QPainter, QPen, QBrush, QTextCursor
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QScrollArea, QFrame, QTextEdit, QTextBrowser, QLineEdit, QComboBox,
    QDialog, QDialogButtonBox, QSplitter, QToolButton,
    QSizePolicy, QApplication, QMenu, QMessageBox,
)

from config.config import RUNDIR
from gui.palette import (
    BASE, MANTLE, SURFACE0, SURFACE1, SURFACE2, OVERLAY0, OVERLAY2,
    TEXT, SUBTEXT1, BLUE, GREEN, RED, YELLOW, MAUVE, PINK,
    SCROLLBAR_V,
)

# ── Paths ─────────────────────────────────────────────────────────────────────

_METHODOLOGY_DIR   = os.path.join(RUNDIR, "resources", "methodology")
_REGISTRY_PATH     = os.path.join(_METHODOLOGY_DIR, "registry.json")
_DESCRIPTIONS_DIR  = os.path.join(_METHODOLOGY_DIR, "descriptions")

# ── Status colours / labels ───────────────────────────────────────────────────

STATUS_META = {
    "not_tested":   {"label": "Not Tested",  "color": OVERLAY0, "dot": OVERLAY0, "emoji": "○"},
    "in_progress":  {"label": "In Progress", "color": YELLOW,   "dot": YELLOW,   "emoji": "◐"},
    "tested_clean": {"label": "Clean",       "color": GREEN,    "dot": GREEN,    "emoji": "✓"},
    "vulnerable":   {"label": "Vulnerable!", "color": RED,      "dot": RED,      "emoji": "⚠"},
    "na":           {"label": "N/A",         "color": SURFACE2, "dot": SURFACE2, "emoji": "—"},
}
STATUS_ORDER = ["not_tested", "in_progress", "tested_clean", "vulnerable", "na"]

# ── Registry loader ───────────────────────────────────────────────────────────

def _load_registry() -> list[dict]:
    """Load categories from registry.json. Returns list of category dicts."""
    try:
        with open(_REGISTRY_PATH, encoding="utf-8") as f:
            data = json.load(f)
        return data.get("categories", [])
    except Exception:
        return []

def _read_description(relative_path: str) -> str:
    """Read a description markdown file and return its content."""
    full = os.path.join(_DESCRIPTIONS_DIR, relative_path)
    try:
        with open(full, encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        name = os.path.splitext(os.path.basename(relative_path))[0]
        return f"# {name.replace('_', ' ').title()}\n\n*Description file not found.*\n\nExpected path: `{full}`"
    except Exception as e:
        return f"# Error\n\nCould not load description: {e}"

# ── Markdown viewer ───────────────────────────────────────────────────────────

_MD_CSS = f"""
body {{
    color: {TEXT};
    background: {BASE};
    margin: 0;
    padding: 0;
    line-height: 1.6;
}}
h1 {{ color: {BLUE}; font-size: 1.4em; border-bottom: 1px solid {SURFACE0}; padding-bottom: 6px; margin-top: 0; }}
h2 {{ color: {MAUVE}; font-size: 1.0em; margin-top: 18px; margin-bottom: 6px; letter-spacing: 0.5px; }}
h3 {{ color: {GREEN}; font-size: 0.95em; margin-top: 14px; margin-bottom: 4px; }}
p  {{ margin: 6px 0; }}
ul, ol {{ margin: 6px 0; padding-left: 20px; }}
li {{ margin: 3px 0; color: {SUBTEXT1}; }}
code {{
    font-family: 'Cascadia Code', 'Fira Code', monospace;
    font-size: 11px;
    background: {MANTLE};
    color: {GREEN};
    padding: 1px 4px;
    border-radius: 3px;
}}
pre {{
    background: {MANTLE};
    border: 1px solid {SURFACE0};
    border-left: 3px solid {BLUE};
    border-radius: 4px;
    padding: 10px 12px;
    margin: 8px 0;
    overflow-x: auto;
}}
pre code {{
    background: transparent;
    color: {TEXT};
    padding: 0;
    font-size: 11px;
}}
blockquote {{
    border-left: 3px solid {YELLOW};
    margin: 8px 0;
    padding: 4px 12px;
    color: {OVERLAY2};
    background: {BASE};
}}
a {{ color: {BLUE}; text-decoration: none; }}
strong {{ color: {TEXT}; }}
em {{ color: {PINK}; }}
hr {{ border: none; border-top: 1px solid {SURFACE0}; margin: 12px 0; }}
table {{ border-collapse: collapse; width: 100%; margin: 8px 0; }}
th {{ background: {SURFACE0}; color: {TEXT}; padding: 6px 10px; text-align: left; }}
td {{ border-bottom: 1px solid {SURFACE0}; padding: 5px 10px; color: {SUBTEXT1}; }}
"""

class _DescriptionPanel(QWidget):
    """Right-side panel that renders a vulnerability description in Markdown."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._current_id: Optional[str] = None

        vb = QVBoxLayout(self)
        vb.setContentsMargins(0, 0, 0, 0)
        vb.setSpacing(0)

        # ── header strip ─────────────────────────────────────────────────────
        self._header = QWidget()
        self._header.setFixedHeight(44)
        self._header.setStyleSheet(f"background:{MANTLE}; border-bottom:1px solid {SURFACE0};")
        hdr_row = QHBoxLayout(self._header)
        hdr_row.setContentsMargins(16, 0, 16, 0)
        hdr_row.setSpacing(10)

        self._title_lbl = QLabel("Select a vulnerability to view its description")
        self._title_lbl.setStyleSheet(f"color:{OVERLAY0}; font-size:12px;")
        hdr_row.addWidget(self._title_lbl, stretch=1)

        self._status_lbl = QLabel("")
        self._status_lbl.setStyleSheet("font-size:9px;")
        hdr_row.addWidget(self._status_lbl)

        vb.addWidget(self._header)

        # ── markdown browser ─────────────────────────────────────────────────
        self._browser = QTextBrowser()
        self._browser.setOpenExternalLinks(False)
        self._browser.setStyleSheet(
            f"QTextBrowser {{ background:{BASE}; color:{TEXT}; border:none; padding:20px; }}"
            + SCROLLBAR_V
        )
        self._browser.document().setDefaultStyleSheet(_MD_CSS)
        self._browser.setPlaceholderText("Select a vulnerability on the left to read its description.")
        vb.addWidget(self._browser, stretch=1)

    def show_placeholder(self):
        self._title_lbl.setText("Select a vulnerability to view its description")
        self._title_lbl.setStyleSheet(f"color:{OVERLAY0}; font-size:12px;")
        self._status_lbl.setText("")
        self._browser.setMarkdown("")
        self._current_id = None

    def load(self, vuln_id: str, name: str, status: str, desc_file: str):
        m = STATUS_META.get(status, STATUS_META["not_tested"])
        self._title_lbl.setText(name)
        self._title_lbl.setStyleSheet(f"color:{TEXT}; font-size:12px; font-weight:bold;")
        self._status_lbl.setText(f"{m['emoji']} {m['label']}")
        self._status_lbl.setStyleSheet(f"color:{m['color']}; font-size:9px; font-weight:bold;")

        # Only reload markdown content when the vulnerability changes
        if vuln_id != self._current_id:
            self._current_id = vuln_id
            content = _read_description(desc_file)
            self._browser.setMarkdown(content)
            # setMarkdown() replaces the document, which loses the default stylesheet.
            self._browser.document().setDefaultStyleSheet(_MD_CSS)
            self._browser.moveCursor(QTextCursor.Start)
        else:
            self._current_id = vuln_id

    def update_status(self, status: str):
        m = STATUS_META.get(status, STATUS_META["not_tested"])
        self._status_lbl.setText(f"{m['emoji']} {m['label']}")
        self._status_lbl.setStyleSheet(f"color:{m['color']}; font-size:9px; font-weight:bold;")

    def current_id(self) -> Optional[str]:
        return self._current_id

# ── Status badge ──────────────────────────────────────────────────────────────

class _StatusBadge(QPushButton):
    status_changed = Signal(str)

    def __init__(self, status: str = "not_tested", parent=None):
        super().__init__(parent)
        self._status = status
        self.setFixedSize(114, 22)
        self.setCursor(Qt.PointingHandCursor)
        self._apply()
        self.clicked.connect(self._cycle)

    def _apply(self):
        m = STATUS_META[self._status]
        self.setText(f"{m['emoji']}  {m['label']}")
        self.setStyleSheet(f"""
            QPushButton {{
                background: {BASE};
                color: {m['color']};
                border: 1px solid {m['color']};
                border-radius: 10px;
                font-size: 9px;
                font-weight: bold;
                padding: 0 6px;
            }}
            QPushButton:hover {{ background: {m['color']}22; }}
        """)

    def _cycle(self):
        idx = STATUS_ORDER.index(self._status)
        self._status = STATUS_ORDER[(idx + 1) % len(STATUS_ORDER)]
        self._apply()
        self.status_changed.emit(self._status)

    def set_status(self, s: str):
        if s in STATUS_ORDER:
            self._status = s
            self._apply()

    def status(self) -> str:
        return self._status

# ── Single vulnerability row ──────────────────────────────────────────────────

class _VulnRow(QFrame):
    changed  = Signal()
    selected = Signal(str, str, str, str)  # vuln_id, name, status, desc_file

    def __init__(self, vuln_id: str, name: str, desc_file: str,
                 state: dict, parent=None):
        super().__init__(parent)
        self._id        = vuln_id
        self._name      = name
        self._desc_file = desc_file
        self._active    = False

        self.setObjectName("vulnRow")
        self._base_style = f"""
            QFrame#vulnRow {{ background: {MANTLE}; border: none; border-radius: 4px; }}
            QFrame#vulnRow:hover {{ background: #20203a; }}
        """
        self._active_style = f"""
            QFrame#vulnRow {{ background: {BASE}; border: none;
                             border-left: 3px solid {BLUE}; border-radius: 0px; }}
        """
        self.setStyleSheet(self._base_style)
        self.setFixedHeight(36)
        self.setCursor(Qt.PointingHandCursor)

        row = QHBoxLayout(self)
        row.setContentsMargins(10, 0, 8, 0)
        row.setSpacing(8)

        self._name_lbl = QLabel(name)
        self._name_lbl.setStyleSheet(f"color:{TEXT}; font-size:11px; background:transparent;")
        self._name_lbl.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)

        self._badge = _StatusBadge(state.get("status", "not_tested"))
        self._badge.status_changed.connect(self._on_status_change)

        self._note_btn = QToolButton()
        self._note_btn.setText("✎")
        self._note_btn.setFixedSize(22, 22)
        self._note_btn.setCursor(Qt.PointingHandCursor)
        self._note_btn.setStyleSheet(
            f"QToolButton {{ background:transparent; color:{OVERLAY0}; border:none; font-size:13px; }}"
            f" QToolButton:hover {{ color:{TEXT}; }}"
        )
        self._note_btn.clicked.connect(self._open_note_editor)

        self._note_text: str = state.get("notes", "")
        self._update_note_indicator()

        row.addWidget(self._name_lbl)
        row.addWidget(self._badge)
        row.addWidget(self._note_btn)

    # intercept mouse presses on the whole row (excluding child widgets)
    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.selected.emit(self._id, self._name,
                               self._badge.status(), self._desc_file)
        super().mousePressEvent(event)

    def set_active(self, active: bool):
        self._active = active
        self.setStyleSheet(self._active_style if active else self._base_style)
        self._name_lbl.setStyleSheet(
            f"color:{BLUE if active else TEXT}; font-size:11px; background:transparent;"
        )

    def _update_note_indicator(self):
        has = bool(self._note_text.strip())
        color = BLUE if has else OVERLAY0
        self._note_btn.setStyleSheet(
            f"QToolButton {{ background:transparent; color:{color}; border:none; font-size:13px; }}"
            f" QToolButton:hover {{ color:{TEXT}; }}"
        )
        tip = f"Notes: {self._note_text[:80]}…" if has else "Add notes"
        self._note_btn.setToolTip(tip)

    def _open_note_editor(self):
        dlg = _NoteDialog(self._name, self._note_text, self)
        if dlg.exec() == QDialog.Accepted:
            self._note_text = dlg.text()
            self._update_note_indicator()
            self.changed.emit()

    def _on_status_change(self, status: str):
        self.changed.emit()
        # If this row is currently selected in the description panel, update it
        self.selected.emit(self._id, self._name, status, self._desc_file)

    def state(self) -> dict:
        return {"status": self._badge.status(), "notes": self._note_text}

    def name(self) -> str:        return self._name
    def vuln_id(self) -> str:     return self._id
    def desc_file(self) -> str:   return self._desc_file
    def current_status(self) -> str: return self._badge.status()

    def matches_filter(self, text: str, status_filter: str) -> bool:
        text_ok   = not text or text.lower() in self._name.lower()
        status_ok = (status_filter == "all") or (self._badge.status() == status_filter)
        return text_ok and status_ok

# ── Note editor dialog ────────────────────────────────────────────────────────

class _NoteDialog(QDialog):
    def __init__(self, vuln_name: str, current: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Vulnerability Notes")
        self.setMinimumWidth(480)
        self.setModal(True)
        self.setStyleSheet(f"""
            QDialog {{ background:{BASE}; color:{TEXT}; }}
            QTextEdit {{
                background:{MANTLE}; color:{TEXT}; border:1px solid {SURFACE0};
                border-radius:4px;
            }}
            QPushButton {{
                background:{SURFACE0}; color:{TEXT}; border:none;
                border-radius:4px; padding:5px 14px;
            }}
            QPushButton:hover {{ background:{SURFACE1}; }}
            QPushButton:default {{ background:{BLUE}; color:{BASE}; }}
            QLabel {{ color:{OVERLAY0}; }}
        """)
        vb = QVBoxLayout(self)
        vb.setSpacing(10)
        vb.setContentsMargins(16, 16, 16, 16)

        hdr = QLabel(f"<span style='color:{BLUE};font-size:13px;font-weight:bold;'>{vuln_name}</span>")
        hdr.setTextFormat(Qt.RichText)
        vb.addWidget(hdr)

        hint = QLabel("Jot down findings, payloads that worked, affected parameters, or references.")
        vb.addWidget(hint)

        self._edit = QTextEdit()
        self._edit.setPlaceholderText("e.g. Found reflected XSS in ?q= parameter. Payload: <img src=x onerror=alert(1)>")
        self._edit.setPlainText(current)
        self._edit.setFixedHeight(200)
        vb.addWidget(self._edit)

        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)
        vb.addWidget(bb)

    def text(self) -> str:
        return self._edit.toPlainText()

# ── Custom vulnerability dialog ───────────────────────────────────────────────

class _AddCustomDialog(QDialog):
    def __init__(self, categories: list[str], parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add Custom Check")
        self.setMinimumWidth(420)
        self.setModal(True)
        self.setStyleSheet(f"""
            QDialog {{ background:{BASE}; color:{TEXT}; }}
            QLineEdit, QComboBox {{
                background:{MANTLE}; color:{TEXT}; border:1px solid {SURFACE0};
                border-radius:4px; padding:5px 8px; font-size:11px;
            }}
            QComboBox QAbstractItemView {{
                background:{BASE}; color:{TEXT}; border:1px solid {SURFACE0};
            }}
            QLabel {{ color:{OVERLAY2}; font-size:10px; }}
            QPushButton {{
                background:{SURFACE0}; color:{TEXT}; border:none;
                border-radius:4px; padding:5px 14px; font-size:11px;
            }}
            QPushButton:hover {{ background:{SURFACE1}; }}
            QPushButton:default {{ background:{GREEN}; color:{BASE}; }}
        """)
        vb = QVBoxLayout(self)
        vb.setSpacing(10)
        vb.setContentsMargins(16, 16, 16, 16)

        vb.addWidget(QLabel("Vulnerability / Check Name"))
        self._name = QLineEdit()
        self._name.setPlaceholderText("e.g. Business logic flaw in checkout flow")
        vb.addWidget(self._name)

        vb.addWidget(QLabel("Category"))
        self._cat = QComboBox()
        for c in categories:
            self._cat.addItem(c)
        self._cat.addItem("+ New Category…")
        vb.addWidget(self._cat)

        self._new_cat = QLineEdit()
        self._new_cat.setPlaceholderText("New category name")
        self._new_cat.hide()
        self._cat.currentIndexChanged.connect(
            lambda: self._new_cat.setVisible(self._cat.currentText() == "+ New Category…")
        )
        vb.addWidget(self._new_cat)

        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        bb.accepted.connect(self._on_ok)
        bb.rejected.connect(self.reject)
        vb.addWidget(bb)

        self._result_name = ""
        self._result_cat  = ""

    def _on_ok(self):
        name = self._name.text().strip()
        if not name:
            self._name.setFocus()
            return
        cat = (self._new_cat.text().strip()
               if self._new_cat.isVisible() else self._cat.currentText())
        if not cat or cat == "+ New Category…":
            return
        self._result_name = name
        self._result_cat  = cat
        self.accept()

    def result_name(self) -> str: return self._result_name
    def result_cat(self) -> str:  return self._result_cat

# ── Category section header ───────────────────────────────────────────────────

class _CategoryHeader(QFrame):
    toggle_requested = Signal()

    def __init__(self, name: str, icon: str, accent: str, parent=None):
        super().__init__(parent)
        self._expanded = True
        self._accent   = accent
        self.setStyleSheet(f"""
            QFrame {{
                background: {BASE};
                border: none;
                border-left: 3px solid {accent};
            }}
        """)
        self.setFixedHeight(36)
        self.setCursor(Qt.PointingHandCursor)

        row = QHBoxLayout(self)
        row.setContentsMargins(12, 0, 12, 0)
        row.setSpacing(8)

        self._arrow = QLabel("▾")
        self._arrow.setStyleSheet(f"color:{accent}; font-size:12px; background:transparent;")
        row.addWidget(self._arrow)

        icon_lbl = QLabel(icon)
        icon_lbl.setStyleSheet("font-size:14px; background:transparent;")
        row.addWidget(icon_lbl)

        name_lbl = QLabel(name.upper())
        name_lbl.setStyleSheet(
            f"color:{accent}; font-size:9px; letter-spacing:1.4px;"
            " font-weight:bold; background:transparent;"
        )
        row.addWidget(name_lbl, stretch=1)

        self._counter = QLabel("")
        self._counter.setStyleSheet(f"color:{OVERLAY0}; font-size:9px; background:transparent;")
        row.addWidget(self._counter)

    def update_counter(self, total: int, tested: int, vuln: int):
        parts = [f"{tested}/{total}"]
        if vuln:
            parts.append(f"⚠ {vuln}")
        self._counter.setText("  ".join(parts))

    def mousePressEvent(self, event):
        self._expanded = not self._expanded
        self._arrow.setText("▾" if self._expanded else "▸")
        self.toggle_requested.emit()

# ── Progress strip ────────────────────────────────────────────────────────────

class _ProgressStrip(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(5)
        self._segments: list[tuple[float, str]] = []

    def set_data(self, counts: dict[str, int], total: int):
        self._segments = []
        if total:
            for s in STATUS_ORDER:
                if counts.get(s, 0):
                    self._segments.append((counts[s] / total, STATUS_META[s]["dot"]))
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        w, h = self.width(), self.height()
        x = 0
        for frac, col in self._segments:
            sw = int(w * frac)
            p.fillRect(x, 0, sw, h, QColor(col))
            x += sw
        if x < w:
            p.fillRect(x, 0, w - x, h, QColor(SURFACE0))

# ── Left panel (checklist) ────────────────────────────────────────────────────

class _ChecklistPanel(QWidget):
    """Left half of the splitter: search bar, filter, scrollable vuln rows."""

    vuln_selected = Signal(str, str, str, str)   # id, name, status, desc_file

    def __init__(self, parent=None):
        super().__init__(parent)
        self._rows:       list[_VulnRow]                          = []
        self._cat_blocks: dict[str, tuple[object, list, object]]  = {}
        self._active_row: Optional[_VulnRow]                      = None

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # ── top controls ─────────────────────────────────────────────────────
        ctrl = QWidget()
        ctrl.setFixedHeight(40)
        ctrl.setStyleSheet(f"background:{MANTLE}; border-bottom:1px solid {SURFACE0};")
        ctrl_row = QHBoxLayout(ctrl)
        ctrl_row.setContentsMargins(8, 4, 8, 4)
        ctrl_row.setSpacing(6)

        self._search = QLineEdit()
        self._search.setPlaceholderText("Search…")
        self._search.setStyleSheet(f"""
            QLineEdit {{
                background:{BASE}; color:{TEXT}; border:1px solid {SURFACE0};
                border-radius:10px; padding:2px 8px; font-size:10px;
            }}
        """)
        self._search.textChanged.connect(self._apply_filter)
        ctrl_row.addWidget(self._search, stretch=1)

        self._status_filter = QComboBox()
        self._status_filter.addItem("All", "all")
        for s in STATUS_ORDER:
            self._status_filter.addItem(
                f"{STATUS_META[s]['emoji']} {STATUS_META[s]['label']}", s
            )
        self._status_filter.setFixedWidth(128)
        self._status_filter.setStyleSheet(f"""
            QComboBox {{
                background:{BASE}; color:{TEXT}; border:1px solid {SURFACE0};
                border-radius:4px; padding:2px 6px; font-size:10px;
            }}
            QComboBox QAbstractItemView {{
                background:{BASE}; color:{TEXT}; border:1px solid {SURFACE0};
            }}
            QComboBox::drop-down {{ border:none; }}
        """)
        self._status_filter.currentIndexChanged.connect(self._apply_filter)
        ctrl_row.addWidget(self._status_filter)

        outer.addWidget(ctrl)

        # ── scroll area ───────────────────────────────────────────────────────
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setStyleSheet(
            f"QScrollArea {{ background:{MANTLE}; border:none; }}"
            + SCROLLBAR_V
        )
        self._content = QWidget()
        self._content.setStyleSheet(f"background:{MANTLE};")
        self._cl = QVBoxLayout(self._content)
        self._cl.setContentsMargins(6, 6, 6, 20)
        self._cl.setSpacing(1)
        scroll.setWidget(self._content)
        outer.addWidget(scroll, stretch=1)

    def add_category(self, cat: dict):
        cat_id   = cat["id"]
        accent   = cat.get("accent", OVERLAY2)
        icon     = cat.get("icon", "◉")
        name     = cat["name"]
        vulns    = cat.get("vulnerabilities", [])

        hdr = _CategoryHeader(name, icon, accent)
        self._cl.addWidget(hdr)

        container = QWidget()
        container.setStyleSheet(f"background:{MANTLE};")
        c_vb = QVBoxLayout(container)
        c_vb.setContentsMargins(0, 1, 0, 4)
        c_vb.setSpacing(1)
        self._cl.addWidget(container)

        row_list: list[_VulnRow] = []
        for v in vulns:
            self._add_vuln(v["id"], v["name"], v.get("description_file", ""),
                           row_list, c_vb)

        self._cat_blocks[cat_id] = (hdr, row_list, c_vb)
        hdr.toggle_requested.connect(lambda c=container: c.setVisible(not c.isVisible()))
        self._update_cat_counter(cat_id)

    def add_custom_vuln(self, cat_id: str, cat_name: str,
                         accent: str, icon: str,
                         vuln_id: str, name: str, desc_file: str, state: dict):
        if cat_id not in self._cat_blocks:
            self._cl.takeAt(self._cl.count() - 1)  # remove stretch
            fake_cat = {"id": cat_id, "name": cat_name,
                        "accent": accent, "icon": icon, "vulnerabilities": []}
            self.add_category(fake_cat)
            self._cl.addStretch()

        _, row_list, c_vb = self._cat_blocks[cat_id]
        self._add_vuln(vuln_id, name, desc_file, row_list, c_vb)
        self._update_cat_counter(cat_id)

    def _add_vuln(self, vid: str, name: str, desc_file: str,
                  row_list: list, layout: QVBoxLayout, state: dict | None = None):
        row = _VulnRow(vid, name, desc_file, state or {})
        row.changed.connect(self._on_row_change)
        row.selected.connect(self._on_row_selected)
        row_list.append(row)
        self._rows.append(row)
        layout.addWidget(row)

    def _on_row_change(self):
        self._refresh_counters()
        self.changed_signal()

    def _on_row_selected(self, vid: str, name: str, status: str, desc_file: str):
        # Deactivate previous
        if self._active_row and self._active_row.vuln_id() != vid:
            self._active_row.set_active(False)
        # Activate clicked
        for row in self._rows:
            if row.vuln_id() == vid:
                row.set_active(True)
                self._active_row = row
                break
        self.vuln_selected.emit(vid, name, status, desc_file)

    # exposed for external wiring
    def changed_signal(self):
        pass  # subclassed / connected externally

    def _apply_filter(self):
        text = self._search.text()
        sf   = self._status_filter.currentData() or "all"
        for row in self._rows:
            row.setVisible(row.matches_filter(text, sf))

    def _refresh_counters(self):
        for cat_id, (hdr, row_list, _) in self._cat_blocks.items():
            self._update_cat_counter(cat_id)

    def _update_cat_counter(self, cat_id: str):
        if cat_id not in self._cat_blocks:
            return
        hdr, row_list, _ = self._cat_blocks[cat_id]
        t      = len(row_list)
        tested = sum(1 for r in row_list
                     if r.state()["status"] in ("tested_clean", "vulnerable"))
        vuln   = sum(1 for r in row_list
                     if r.state()["status"] == "vulnerable")
        hdr.update_counter(t, tested, vuln)

    def finalize(self):
        """Call after all categories added to append stretch."""
        self._cl.addStretch()

    def all_rows(self) -> list[_VulnRow]:
        return self._rows

    def set_row_states(self, state: dict):
        """Apply persisted states to all rows."""
        for row in self._rows:
            s = state.get(row.vuln_id(), {})
            if s:
                row._badge.set_status(s.get("status", "not_tested"))
                row._note_text = s.get("notes", "")
                row._update_note_indicator()
        self._refresh_counters()

# ── Main methodology widget ───────────────────────────────────────────────────

class TestingMethodologyWidget(QWidget):
    def __init__(self, project_dir: str, repo=None, parent=None):
        super().__init__(parent)
        self._project_dir = project_dir
        self._repo        = repo
        self._state: dict = {}
        self._registry: list[dict] = _load_registry()

        self._load_state()
        self._build_ui()
        self._populate()
        self._seed_db()

    # ── Persistence ───────────────────────────────────────────────────────────

    def _state_path(self) -> str:
        return os.path.join(self._project_dir, "testing_methodology.json")

    def _load_state(self):
        # Try DB first (authoritative if populated), fall back to JSON file
        db_state: dict = {}
        if self._repo:
            try:
                db_state = self._repo.load_methodology_states()
            except Exception:
                pass

        json_state: dict = {}
        p = self._state_path()
        if os.path.exists(p):
            try:
                with open(p) as f:
                    json_state = json.load(f)
            except Exception:
                pass

        # Merge: DB takes precedence for individual vuln states, JSON for __custom__
        self._state = json_state.copy()
        for vid, s in db_state.items():
            self._state[vid] = s

    def _save(self):
        state: dict = {"__custom__": self._state.get("__custom__", [])}
        for row in self._checklist.all_rows():
            state[row.vuln_id()] = row.state()
        self._state = state

        # Persist to JSON file
        try:
            with open(self._state_path(), "w") as f:
                json.dump(self._state, f, indent=2)
        except Exception:
            pass

        # Persist to MongoDB
        if self._repo:
            try:
                self._repo.save_methodology_state(state)
            except Exception:
                pass

        self._refresh_progress()

    def _seed_db(self):
        """Seed the global methodology registry into MongoDB on first load."""
        if self._repo and self._registry:
            try:
                self._repo.seed_methodology_registry(self._registry)
            except Exception:
                pass

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── top bar ──────────────────────────────────────────────────────────
        topbar = QWidget()
        topbar.setFixedHeight(46)
        topbar.setStyleSheet(f"background:{MANTLE}; border-bottom:1px solid {SURFACE0};")
        tb = QHBoxLayout(topbar)
        tb.setContentsMargins(16, 0, 16, 0)
        tb.setSpacing(12)

        icon_lbl = QLabel("🗂")
        icon_lbl.setStyleSheet("font-size:18px;")
        tb.addWidget(icon_lbl)

        title = QLabel("Testing Methodology")
        title.setStyleSheet(f"color:{TEXT}; font-size:13px; font-weight:bold;")
        tb.addWidget(title)

        tb.addStretch()

        add_btn = QPushButton("＋  Add Custom Check")
        add_btn.setCursor(Qt.PointingHandCursor)
        add_btn.setStyleSheet(f"""
            QPushButton {{
                background:{BASE}; color:{GREEN};
                border:1px solid {GREEN}; border-radius:4px;
                padding:4px 14px; font-size:11px;
            }}
            QPushButton:hover {{ background:{GREEN}22; }}
        """)
        add_btn.clicked.connect(self._add_custom)
        tb.addWidget(add_btn)

        root.addWidget(topbar)

        # ── progress strip ────────────────────────────────────────────────────
        self._progress = _ProgressStrip()
        root.addWidget(self._progress)

        # ── stats bar ─────────────────────────────────────────────────────────
        stats = QWidget()
        stats.setFixedHeight(28)
        stats.setStyleSheet(f"background:{BASE}; border-bottom:1px solid {SURFACE0};")
        sb = QHBoxLayout(stats)
        sb.setContentsMargins(16, 0, 16, 0)
        sb.setSpacing(18)
        self._stat_lbls: dict[str, QLabel] = {}
        for s in STATUS_ORDER:
            m = STATUS_META[s]
            lbl = QLabel(f"{m['emoji']} {m['label']}: 0")
            lbl.setStyleSheet(f"color:{m['color']}; font-size:9px;")
            sb.addWidget(lbl)
            self._stat_lbls[s] = lbl
        sb.addStretch()
        self._total_lbl = QLabel("Total: 0")
        self._total_lbl.setStyleSheet(f"color:{OVERLAY0}; font-size:9px;")
        sb.addWidget(self._total_lbl)
        root.addWidget(stats)

        # ── splitter ──────────────────────────────────────────────────────────
        splitter = QSplitter(Qt.Horizontal)
        splitter.setHandleWidth(2)
        splitter.setStyleSheet(f"QSplitter::handle {{ background:{SURFACE0}; }}")

        self._checklist = _ChecklistPanel()
        self._checklist.vuln_selected.connect(self._on_vuln_selected)
        self._checklist.changed_signal = self._save  # wire save

        self._desc_panel = _DescriptionPanel()

        splitter.addWidget(self._checklist)
        splitter.addWidget(self._desc_panel)
        splitter.setSizes([380, 600])
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)

        root.addWidget(splitter, stretch=1)

    # ── Populate ──────────────────────────────────────────────────────────────

    def _populate(self):
        for cat in self._registry:
            self._checklist.add_category(cat)

        # Custom entries
        for custom in self._state.get("__custom__", []):
            self._checklist.add_custom_vuln(
                cat_id   = custom.get("category_id", "custom"),
                cat_name = custom.get("category_name", "Custom"),
                accent   = OVERLAY2,
                icon     = "★",
                vuln_id  = custom["id"],
                name     = custom["name"],
                desc_file= custom.get("description_file", ""),
                state    = self._state.get(custom["id"], {}),
            )

        self._checklist.finalize()

        # Apply saved states
        self._checklist.set_row_states(self._state)
        self._refresh_progress()

    # ── Event handlers ────────────────────────────────────────────────────────

    def _on_vuln_selected(self, vid: str, name: str, status: str, desc_file: str):
        self._desc_panel.load(vid, name, status, desc_file)

    def _refresh_progress(self):
        rows = self._checklist.all_rows()
        counts = {s: 0 for s in STATUS_ORDER}
        for row in rows:
            counts[row.state()["status"]] += 1
        total = len(rows)
        self._progress.set_data(counts, total)
        self._total_lbl.setText(f"Total: {total}")
        for s in STATUS_ORDER:
            m = STATUS_META[s]
            self._stat_lbls[s].setText(f"{m['emoji']} {m['label']}: {counts[s]}")

    def _add_custom(self):
        cat_names = [c["name"] for c in self._registry]
        dlg = _AddCustomDialog(cat_names, self)
        if dlg.exec() != QDialog.Accepted:
            return

        name     = dlg.result_name()
        cat_name = dlg.result_cat()

        cat_id = None
        for cat in self._registry:
            if cat["name"] == cat_name:
                cat_id = cat["id"]
                break
        if cat_id is None:
            import re
            cat_id = "custom_" + re.sub(r'\W+', '_', cat_name.lower())

        vuln_id = f"custom_{cat_id}_{len(self._checklist.all_rows())}"

        self._checklist.add_custom_vuln(
            cat_id=cat_id, cat_name=cat_name,
            accent=OVERLAY2, icon="★",
            vuln_id=vuln_id, name=name, desc_file="", state={},
        )

        custom_list = self._state.get("__custom__", [])
        custom_list.append({
            "id":            vuln_id,
            "name":          name,
            "category_id":   cat_id,
            "category_name": cat_name,
            "description_file": "",
        })
        self._state["__custom__"] = custom_list
        self._save()
