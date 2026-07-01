"""
ScopeEditorWidget — embeds into the Target page.

Shows two lists (In Scope / Out of Scope) with inline add/remove.
Persists to MongoDB via AweRepository.save_scope() on Save.
Emits scope_changed(ScopeConfig) after every save so subscribers
(SiteMapPage, pipeline) can react without polling.
"""
from __future__ import annotations

import logging

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QComboBox, QLineEdit, QCheckBox, QScrollArea, QFrame,
    QSizePolicy,
)

from database.scope import ScopeConfig, ScopeEntry

log = logging.getLogger(__name__)

# ── colour tokens ─────────────────────────────────────────────────────────────
_IN_COLOR  = "#A6E3A1"   # green  — in scope
_OUT_COLOR = "#F38BA8"   # red    — out of scope
_TAG_COLORS = {
    "domain":   "#89B4FA",
    "wildcard": "#F9E2AF",
    "url":      "#94E2D5",
    "regex":    "#CBA6F7",
}
_ENTRY_TYPES = ["domain", "wildcard", "url", "regex"]


class ScopeEditorWidget(QWidget):
    scope_changed = Signal(object)   # emits ScopeConfig

    def __init__(self, repository, parent=None):
        super().__init__(parent)
        self._repo    = repository
        self._entries: list[ScopeEntry] = []
        self._rows: list[_EntryRow] = []
        self._build_ui()
        self.load()

    # ── public ────────────────────────────────────────────────────────────────

    def load(self) -> None:
        try:
            cfg = self._repo.get_scope()
        except Exception:
            cfg = ScopeConfig()
        self._entries = list(cfg.entries)
        self._include_sub.setChecked(cfg.include_subdomains)
        self._rebuild_rows()

    def save(self) -> None:
        cfg = ScopeConfig(
            entries=list(self._entries),
            include_subdomains=self._include_sub.isChecked(),
        )
        try:
            self._repo.save_scope(cfg)
        except Exception:
            log.warning("Failed to persist scope to database", exc_info=True)
        self.scope_changed.emit(cfg)

    def current_config(self) -> ScopeConfig:
        return ScopeConfig(
            entries=list(self._entries),
            include_subdomains=self._include_sub.isChecked(),
        )

    # ── UI construction ───────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        vb = QVBoxLayout(self)
        vb.setContentsMargins(0, 0, 0, 0)
        vb.setSpacing(10)

        # ── include subdomains toggle ─────────────────────────────────────────
        sub_row = QHBoxLayout()
        sub_row.setContentsMargins(0, 0, 0, 0)
        self._include_sub = QCheckBox("Include subdomains automatically")
        self._include_sub.setChecked(True)
        self._include_sub.setStyleSheet(
            "QCheckBox{color:#CDD6F4; font-size:10px; background:transparent;}"
            "QCheckBox::indicator{width:14px;height:14px;}"
        )
        self._include_sub.toggled.connect(self.save)
        sub_row.addWidget(self._include_sub)
        sub_row.addStretch()
        vb.addLayout(sub_row)

        # ── In Scope ──────────────────────────────────────────────────────────
        vb.addWidget(_section_label("In Scope", _IN_COLOR))
        self._in_container, self._in_vb = _scrollable_list()
        vb.addWidget(self._in_container, stretch=3)
        vb.addLayout(self._add_row(in_scope=True))

        # ── Out of Scope ──────────────────────────────────────────────────────
        vb.addWidget(_section_label("Out of Scope", _OUT_COLOR))
        self._out_container, self._out_vb = _scrollable_list()
        vb.addWidget(self._out_container, stretch=3)
        vb.addLayout(self._add_row(in_scope=False))


    def _add_row(self, in_scope: bool) -> QHBoxLayout:
        """Returns an HBox with type-combo + value-input + Add button."""
        hl = QHBoxLayout()
        hl.setSpacing(6)

        combo = QComboBox()
        combo.addItems(_ENTRY_TYPES)
        combo.setFixedWidth(90)
        combo.setStyleSheet(
            "QComboBox{background:#181825;color:#CDD6F4;border:1px solid #45475A;"
            "border-radius:4px;padding:2px 6px;font-size:9px;}"
        )

        edit = QLineEdit()
        edit.setPlaceholderText("example.com  /  *.example.com  /  …")
        edit.setStyleSheet(
            "QLineEdit{background:#181825;color:#CDD6F4;border:1px solid #45475A;"
            "border-radius:4px;padding:3px 8px;font-size:10px;}"
            "QLineEdit:focus{border-color:#89B4FA;}"
        )

        color   = _IN_COLOR if in_scope else _OUT_COLOR
        add_btn = QPushButton("+  Add")
        add_btn.setFixedHeight(28)
        add_btn.setStyleSheet(
            f"QPushButton{{background:#313244;color:{color};border:1px solid #45475A;"
            "border-radius:4px;padding:0 10px;font-size:9px;}"
            "QPushButton:hover{background:#45475A;}"
        )

        def _add():
            val = edit.text().strip()
            if not val:
                return
            entry = ScopeEntry(value=val, entry_type=combo.currentText(), in_scope=in_scope)
            self._entries.append(entry)
            self._rebuild_rows()
            edit.clear()
            self.save()

        add_btn.clicked.connect(_add)
        edit.returnPressed.connect(_add)

        hl.addWidget(combo)
        hl.addWidget(edit, stretch=1)
        hl.addWidget(add_btn)
        return hl

    # ── row management ────────────────────────────────────────────────────────

    def _rebuild_rows(self) -> None:
        self._rows.clear()
        _clear_layout(self._in_vb)
        _clear_layout(self._out_vb)

        for entry in self._entries:
            row = _EntryRow(entry, on_remove=self._remove_entry)
            self._rows.append(row)
            if entry.in_scope:
                self._in_vb.addWidget(row)
            else:
                self._out_vb.addWidget(row)

        self._in_vb.addStretch()
        self._out_vb.addStretch()

    def _remove_entry(self, entry: ScopeEntry) -> None:
        if entry in self._entries:
            self._entries.remove(entry)
        self._rebuild_rows()
        self.save()


# ── entry row widget ──────────────────────────────────────────────────────────

class _EntryRow(QWidget):
    def __init__(self, entry: ScopeEntry, on_remove, parent=None):
        super().__init__(parent)
        self._entry = entry
        hl = QHBoxLayout(self)
        hl.setContentsMargins(6, 3, 6, 3)
        hl.setSpacing(8)

        # type tag
        tag = QLabel(entry.entry_type)
        tag.setFixedWidth(62)
        tag.setAlignment(Qt.AlignCenter)
        c = _TAG_COLORS.get(entry.entry_type, "#6C7086")
        tag.setStyleSheet(
            f"background:{c}22; color:{c}; border:1px solid {c}55;"
            "border-radius:3px; padding:1px 4px; font-size:9px;"
        )
        hl.addWidget(tag)

        # value
        val = QLabel(entry.value)
        val.setStyleSheet("color:#CDD6F4; font-size:10px; background:transparent;")
        val.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        hl.addWidget(val, stretch=1)

        # remove button — always visible, turns bright red on hover
        rm = QPushButton("✕  Remove")
        rm.setFixedHeight(22)
        rm.setStyleSheet(
            "QPushButton{background:#2A1A1A;color:#F38BA8;border:1px solid rgba(243,139,168,68);"
            "border-radius:3px;padding:0 8px;font-size:9px;}"
            "QPushButton:hover{background:rgba(243,139,168,34);border-color:#F38BA8;}"
        )
        rm.clicked.connect(lambda: on_remove(self._entry))
        hl.addWidget(rm)

        self.setStyleSheet(
            "background:#1E1E2E; border-radius:4px;"
            "border:1px solid #313244;"
        )
        self.setFixedHeight(32)


# ── helpers ───────────────────────────────────────────────────────────────────

def _section_label(text: str, color: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setStyleSheet(
        f"color:{color}; font-size:10px; font-weight:bold; "
        "background:transparent; border:none; padding-bottom:2px;"
    )
    return lbl


def _scrollable_list() -> tuple[QScrollArea, QVBoxLayout]:
    inner = QWidget()
    vb    = QVBoxLayout(inner)
    vb.setContentsMargins(4, 4, 4, 4)
    vb.setSpacing(4)

    scroll = QScrollArea()
    scroll.setWidget(inner)
    scroll.setWidgetResizable(True)
    scroll.setMinimumHeight(180)
    scroll.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
    scroll.setStyleSheet(
        "QScrollArea{background:#181825; border:1px solid #313244; border-radius:4px;}"
        "QScrollBar:vertical{width:6px;background:#181825;border:none;}"
        "QScrollBar::handle:vertical{background:#313244;border-radius:3px;}"
    )
    return scroll, vb


def _clear_layout(layout: QVBoxLayout) -> None:
    while layout.count():
        item = layout.takeAt(0)
        if item.widget():
            item.widget().deleteLater()
