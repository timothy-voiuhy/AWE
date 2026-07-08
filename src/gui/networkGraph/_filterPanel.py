"""
Filter strip for the Network / Attack-Surface graph page.

Unlike gui.filterPanel (which filters proxy-traffic documents for SiteMap /
HTTP History), this panel filters GraphNode objects and only constrains two
node kinds:

  - "vuln"     (Findings)  — severity toggles + text search over name/description
  - "endpoint" (Endpoints) — method + status-class toggles + text search over URL

Every other node kind (target, subdomain, ip, port, tech, cdn, …) always
passes — the filter is scoped to findings/endpoints, not the whole graph.

Reuses the toggle-button / divider / clear-button primitives and the
method/status colour tables from gui.filterPanel so it matches the SiteMap /
HTTP History look.
"""
from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QLabel

from gui.filterPanel import (
    _ToggleBtn, _vdiv, _clear_btn,
    _METHODS, _METHOD_COLORS, _STATUS_CATS, _STATUS_COLORS, _status_cat,
)
from ._models import GraphNode

_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
_SEVERITY_COLORS: dict[str, tuple[str, str]] = {
    "CRITICAL": ("#3A1A1A", "#F38BA8"),
    "HIGH":     ("#3A2A1A", "#FAB387"),
    "MEDIUM":   ("#3A3A1A", "#F9E2AF"),
    "LOW":      ("#1A3A2A", "#A6E3A1"),
    "INFO":     ("#1C3A5F", "#89B4FA"),
}


class GraphFilterPanel(QWidget):
    changed = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet("background:#181825;")
        self._build()

    # ── build ─────────────────────────────────────────────────────────────────

    def _build(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(8, 6, 8, 6)
        outer.setSpacing(4)

        row1 = QHBoxLayout(); row1.setSpacing(6)
        row2 = QHBoxLayout(); row2.setSpacing(6)

        # ── Search (findings name/description, endpoint url) ───────────────────
        self._search = QLineEdit()
        self._search.setPlaceholderText("Search findings / endpoints…")
        self._search.setFixedHeight(22)
        self._search.setStyleSheet(
            "QLineEdit{background:#11111B;color:#CDD6F4;border:1px solid #313244;"
            "border-radius:3px;padding:0 6px;font-size:9px;}"
            "QLineEdit:focus{border-color:#89B4FA;}"
        )
        self._search.textChanged.connect(self.changed)
        s_lbl = QLabel("Search:")
        s_lbl.setStyleSheet("color:#6C7086;font-size:8px;")
        row1.addWidget(s_lbl)
        row1.addWidget(self._search, stretch=1)

        # ── Severity toggles (Findings) ──────────────────────────────────────────
        row1.addWidget(_vdiv())
        sev_lbl = QLabel("Severity:")
        sev_lbl.setStyleSheet("color:#6C7086;font-size:8px;")
        row1.addWidget(sev_lbl)
        self._severity_btns: dict[str, _ToggleBtn] = {}
        for sev in _SEVERITIES:
            bg, fg = _SEVERITY_COLORS[sev]
            btn = _ToggleBtn(sev.title(), bg, fg)
            btn.toggled.connect(self.changed)
            self._severity_btns[sev] = btn
            row1.addWidget(btn)

        row1.addStretch()
        clr1 = _clear_btn()
        clr1.clicked.connect(self._clear_row1)
        row1.addWidget(clr1)

        # ── Method toggles (Endpoints) ───────────────────────────────────────────
        method_lbl = QLabel("Method:")
        method_lbl.setStyleSheet("color:#6C7086;font-size:8px;")
        row2.addWidget(method_lbl)
        self._method_btns: dict[str, _ToggleBtn] = {}
        for m in _METHODS:
            bg, fg = _METHOD_COLORS[m]
            btn = _ToggleBtn(m, bg, fg)
            btn.toggled.connect(self.changed)
            self._method_btns[m] = btn
            row2.addWidget(btn)

        # ── Status toggles (Endpoints) ───────────────────────────────────────────
        row2.addWidget(_vdiv())
        status_lbl = QLabel("Status:")
        status_lbl.setStyleSheet("color:#6C7086;font-size:8px;")
        row2.addWidget(status_lbl)
        self._status_btns: dict[str, _ToggleBtn] = {}
        for cat in _STATUS_CATS:
            bg, fg = _STATUS_COLORS[cat]
            btn = _ToggleBtn(cat.upper(), bg, fg)
            btn.toggled.connect(self.changed)
            self._status_btns[cat] = btn
            row2.addWidget(btn)

        row2.addStretch()
        clr2 = _clear_btn()
        clr2.clicked.connect(self._clear_row2)
        row2.addWidget(clr2)

        outer.addLayout(row1)
        outer.addLayout(row2)

    # ── filter logic ──────────────────────────────────────────────────────────

    def passes(self, node: GraphNode) -> bool:
        """Return True if node should remain visible under the active filters."""
        q = self._search.text().strip().lower()

        if node.kind == "vuln":
            active_sev = {s for s, b in self._severity_btns.items() if b.isChecked()}
            if active_sev and node.data.get("severity", "info").upper() not in active_sev:
                return False
            if q and not self._vuln_matches(node, q):
                return False
            return True

        if node.kind == "endpoint":
            active_methods = {m for m, b in self._method_btns.items() if b.isChecked()}
            if active_methods and node.data.get("method", "GET").upper() not in active_methods:
                return False
            active_status = {c for c, b in self._status_btns.items() if b.isChecked()}
            if active_status and _status_cat(node.data.get("status_code", 0)) not in active_status:
                return False
            if q and not self._endpoint_matches(node, q):
                return False
            return True

        return True

    @staticmethod
    def _vuln_matches(node: GraphNode, q: str) -> bool:
        return (q in node.data.get("name", "").lower()
                or q in node.data.get("description", "").lower()
                or q in node.label.lower())

    @staticmethod
    def _endpoint_matches(node: GraphNode, q: str) -> bool:
        return (q in node.data.get("url", "").lower()
                or q in node.label.lower())

    # ── state ─────────────────────────────────────────────────────────────────

    def is_active(self) -> bool:
        if self._search.text().strip():
            return True
        if any(b.isChecked() for b in self._severity_btns.values()):
            return True
        if any(b.isChecked() for b in self._method_btns.values()):
            return True
        if any(b.isChecked() for b in self._status_btns.values()):
            return True
        return False

    def reset(self) -> None:
        self._search.clear()
        for b in [*self._severity_btns.values(),
                  *self._method_btns.values(),
                  *self._status_btns.values()]:
            b.setChecked(False)

    def to_dict(self) -> dict:
        return {
            "search":      self._search.text(),
            "severities":  [s for s, b in self._severity_btns.items() if b.isChecked()],
            "methods":     [m for m, b in self._method_btns.items() if b.isChecked()],
            "status_cats": [c for c, b in self._status_btns.items() if b.isChecked()],
        }

    def from_dict(self, data: dict) -> None:
        """Restore state without emitting changed (caller drives the refresh)."""
        widgets = [
            self._search,
            *self._severity_btns.values(),
            *self._method_btns.values(),
            *self._status_btns.values(),
        ]
        for w in widgets:
            w.blockSignals(True)
        try:
            self._search.setText(data.get("search", ""))
            for s, b in self._severity_btns.items():
                c = s in data.get("severities", [])
                b.setChecked(c); b._update_style(c)
            for m, b in self._method_btns.items():
                c = m in data.get("methods", [])
                b.setChecked(c); b._update_style(c)
            for cat, b in self._status_btns.items():
                c = cat in data.get("status_cats", [])
                b.setChecked(c); b._update_style(c)
        finally:
            for w in widgets:
                w.blockSignals(False)

    # ── internal clears ───────────────────────────────────────────────────────

    def _clear_row1(self) -> None:
        self._search.clear()
        for b in self._severity_btns.values():
            b.setChecked(False)

    def _clear_row2(self) -> None:
        for b in [*self._method_btns.values(), *self._status_btns.values()]:
            b.setChecked(False)
