"""
Shared HTTP filter panel.

Reused by HttpHistoryPage and SiteMapPage.

Usage
-----
    from gui.filterPanel import FilterPanel, _status_cat, _status_color, _file_type

    # All sections (HTTP History):
    panel = FilterPanel()

    # Subset (Site Map — no SSE-only toggle, no length range):
    panel = FilterPanel(sections={"search", "method", "status", "hide_types"})

    # In the per-row filter check:
    if not panel.passes(doc, resp, body, is_sse, is_rsc, length):
        continue
"""
from __future__ import annotations

import re
from pathlib import PurePosixPath

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QFrame,
    QPushButton, QLabel, QLineEdit,
)

# ── Static-asset / RSC classification ────────────────────────────────────────

_STATIC_EXTS: dict[str, set[str]] = {
    "images": {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico",
               ".svg", ".bmp", ".tiff", ".avif"},
    "css":    {".css", ".scss", ".less", ".sass"},
    # js includes TypeScript / JSX so the sitemap "Scripts" group maps cleanly
    "js":     {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"},
    "fonts":  {".woff", ".woff2", ".ttf", ".eot", ".otf"},
    "media":  {".mp4", ".mp3", ".webm", ".ogg", ".wav", ".avi", ".mov", ".mkv", ".flac"},
}

_CT_TYPES: dict[str, tuple[str, ...]] = {
    "images": ("image/",),
    "css":    ("text/css",),
    "js":     ("application/javascript", "text/javascript", "application/x-javascript"),
    "fonts":  ("font/", "application/font", "application/x-font"),
    "media":  ("video/", "audio/"),
}

_RSC_LINE_RE = re.compile(r'^(?:\d+:|:(?:HL|HC|HK|E|S|M|I)\[)')


def _looks_like_rsc(body: str) -> bool:
    lines = [ln.strip() for ln in body[:512].splitlines() if ln.strip()][:6]
    return sum(1 for ln in lines if _RSC_LINE_RE.match(ln)) >= 2


def _file_type(path: str, resp: dict, is_rsc: bool = False) -> str | None:
    """Return the asset category string for a path/response, or None."""
    if is_rsc:
        return "rsc"
    ext = PurePosixPath(path.split("?")[0]).suffix.lower()
    for t, exts in _STATIC_EXTS.items():
        if ext in exts:
            return t
    ct = str((resp.get("headers") or {}).get("content-type", "")).lower()
    if "text/x-component" in ct:
        return "rsc"
    for t, prefixes in _CT_TYPES.items():
        if any(p in ct for p in prefixes):
            return t
    return None


# ── Status helpers ────────────────────────────────────────────────────────────

def _status_cat(code) -> str:
    try:
        c = int(code)
    except (TypeError, ValueError):
        return "err"
    if 200 <= c < 300: return "2xx"
    if 300 <= c < 400: return "3xx"
    if 400 <= c < 500: return "4xx"
    if 500 <= c < 600: return "5xx"
    return "err"


_STATUS_CAT_COLORS = {
    "2xx": "#A6E3A1",
    "3xx": "#89B4FA",
    "4xx": "#F9E2AF",
    "5xx": "#F38BA8",
    "err": "#6C7086",
}


def _status_color(code) -> str:
    return _STATUS_CAT_COLORS.get(_status_cat(code), "#6C7086")


# ── Widget primitives ─────────────────────────────────────────────────────────

_METHODS      = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
_STATUS_CATS  = ["2xx", "3xx", "4xx", "5xx", "err"]
_HIDE_TYPES   = ["images", "css", "js", "fonts", "media", "rsc"]
_HIDE_LABELS  = {"images": "Images", "css": "CSS", "js": "JS",
                 "fonts": "Fonts", "media": "Media", "rsc": "RSC"}

_METHOD_COLORS = {
    "GET":     ("#1C3A5F", "#89B4FA"),
    "POST":    ("#1A3A2A", "#A6E3A1"),
    "PUT":     ("#3A2A1A", "#FAB387"),
    "DELETE":  ("#3A1A1A", "#F38BA8"),
    "PATCH":   ("#2A2A1A", "#F9E2AF"),
    "HEAD":    ("#1E2030", "#8AADF4"),
    "OPTIONS": ("#1A2A2A", "#94E2D5"),
}
_STATUS_COLORS = {
    "2xx": ("#1A3A2A", "#A6E3A1"),
    "3xx": ("#1C3A5F", "#89B4FA"),
    "4xx": ("#3A3A1A", "#F9E2AF"),
    "5xx": ("#3A1A1A", "#F38BA8"),
    "err": ("#2A2A2A", "#6C7086"),
}
_HIDE_COLORS = {
    "images": ("#2A1F3A", "#CBA6F7"),
    "css":    ("#1A2A3A", "#89DCEB"),
    "js":     ("#2A2A1A", "#F9E2AF"),
    "fonts":  ("#1A3A2A", "#A6E3A1"),
    "media":  ("#3A1A2A", "#F38BA8"),
    "rsc":    ("#0A2025", "#89DCEB"),
}


def _toggle_ss(bg_on: str, fg_on: str) -> tuple[str, str]:
    on = (
        f"QPushButton{{background:{bg_on};color:{fg_on};"
        f"border:1px solid {fg_on};border-radius:3px;"
        "padding:0 7px;font-size:8px;min-height:20px;}"
        f"QPushButton:hover{{background:{bg_on};}}"
    )
    off = (
        "QPushButton{background:#252535;color:#45475A;"
        "border:1px solid #313244;border-radius:3px;"
        "padding:0 7px;font-size:8px;min-height:20px;}"
        "QPushButton:hover{background:#313244;color:#6C7086;}"
    )
    return on, off


class _ToggleBtn(QPushButton):
    def __init__(self, label: str, bg_on: str, fg_on: str, parent=None):
        super().__init__(label, parent)
        self.setCheckable(True)
        self._ss_on, self._ss_off = _toggle_ss(bg_on, fg_on)
        self.setStyleSheet(self._ss_off)
        self.toggled.connect(self._update_style)

    def _update_style(self, checked: bool):
        self.setStyleSheet(self._ss_on if checked else self._ss_off)


def _vdiv() -> QFrame:
    f = QFrame()
    f.setFrameShape(QFrame.VLine)
    f.setFixedWidth(1)
    f.setStyleSheet("background:#313244; border:none;")
    return f


def _clear_btn() -> QPushButton:
    b = QPushButton("✕")
    b.setFixedSize(20, 20)
    b.setToolTip("Clear these filters")
    b.setStyleSheet(
        "QPushButton{background:transparent;color:#45475A;border:none;font-size:10px;}"
        "QPushButton:hover{color:#F38BA8;}"
    )
    return b


# ── FilterPanel ───────────────────────────────────────────────────────────────

_SCOPE_COLORS = {
    "path":      ("#1C3A5F", "#89B4FA"),
    "headers":   ("#3A2A10", "#FAB387"),
    "req_body":  ("#1A3A2A", "#A6E3A1"),
    "resp_body": ("#0A2025", "#89DCEB"),
}


class FilterPanel(QWidget):
    """
    Compact two-row filter strip.

    Parameters
    ----------
    sections : set[str] | None
        Controls which filter controls are built.  Pass a subset of
        ``FilterPanel.ALL_SECTIONS`` to suppress irrelevant controls.
        ``None`` → all sections shown (HTTP History default).

    Available sections
    ------------------
    "search"        — text search input
    "search_scopes" — Path / Headers / Body scope toggles beside the search field
    "method"        — per-method toggle buttons
    "status"        — 2xx / 3xx / 4xx / 5xx / err toggles
    "hide_types"    — hide Images / CSS / JS / Fonts / Media / RSC
    "sse"           — SSE-only toggle (HTTP History only)
    "length"        — min / max byte-length fields (HTTP History only)
    """

    changed = Signal()

    ALL_SECTIONS = frozenset({
        "search", "search_scopes",
        "method", "status", "hide_types", "sse", "length",
    })

    def __init__(self, sections=None, parent=None):
        super().__init__(parent)
        self._sections: frozenset[str] = (
            frozenset(sections) if sections is not None else self.ALL_SECTIONS
        )
        self.setStyleSheet("background:#181825;")
        self._build()

    # ── build ─────────────────────────────────────────────────────────────────

    def _build(self) -> None:
        s = self._sections
        outer = QVBoxLayout(self)
        outer.setContentsMargins(8, 6, 8, 6)
        outer.setSpacing(4)

        row1_widgets: list = []   # track whether row1 has content
        row2_widgets: list = []

        row1 = QHBoxLayout(); row1.setSpacing(6)
        row2 = QHBoxLayout(); row2.setSpacing(6)

        # ── Search ────────────────────────────────────────────────────────────
        self._search: QLineEdit | None = None
        self._scope_path: _ToggleBtn | None      = None
        self._scope_headers: _ToggleBtn | None   = None
        self._scope_req_body: _ToggleBtn | None  = None
        self._scope_resp_body: _ToggleBtn | None = None
        if "search" in s:
            self._search = QLineEdit()
            self._search.setPlaceholderText("Search…")
            self._search.setFixedHeight(22)
            self._search.setStyleSheet(
                "QLineEdit{background:#11111B;color:#CDD6F4;border:1px solid #313244;"
                "border-radius:3px;padding:0 6px;font-size:9px;}"
                "QLineEdit:focus{border-color:#89B4FA;}"
            )
            self._search.textChanged.connect(self.changed)
            lbl = QLabel("Search:")
            lbl.setStyleSheet("color:#6C7086;font-size:8px;")
            row1.addWidget(lbl)
            row1.addWidget(self._search, stretch=1)
            row1_widgets.append(self._search)

        # ── Search scope toggles (Path / Headers / Req Body / Resp Body) ──────
        if "search" in s and "search_scopes" in s:
            self._scope_path = _ToggleBtn("Path", *_SCOPE_COLORS["path"])
            self._scope_path.setChecked(True)        # default on
            self._scope_path.toggled.connect(self.changed)
            self._scope_headers = _ToggleBtn("Headers", *_SCOPE_COLORS["headers"])
            self._scope_headers.toggled.connect(self.changed)
            self._scope_req_body = _ToggleBtn("Req Body", *_SCOPE_COLORS["req_body"])
            self._scope_req_body.toggled.connect(self.changed)
            self._scope_resp_body = _ToggleBtn("Resp Body", *_SCOPE_COLORS["resp_body"])
            self._scope_resp_body.toggled.connect(self.changed)
            for btn in (self._scope_path, self._scope_headers,
                        self._scope_req_body, self._scope_resp_body):
                row1.addWidget(btn)
                row1_widgets.append(btn)

        # ── Method toggles ────────────────────────────────────────────────────
        self._method_btns: dict[str, _ToggleBtn] = {}
        if "method" in s:
            if row1_widgets:
                row1.addWidget(_vdiv())
            for m in _METHODS:
                bg, fg = _METHOD_COLORS[m]
                btn = _ToggleBtn(m, bg, fg)
                btn.toggled.connect(self.changed)
                self._method_btns[m] = btn
                row1.addWidget(btn)
                row1_widgets.append(btn)

        if row1_widgets:
            row1.addStretch()
            clr = _clear_btn()
            clr.clicked.connect(self._clear_row1)
            row1.addWidget(clr)

        # ── Status ────────────────────────────────────────────────────────────
        self._status_btns: dict[str, _ToggleBtn] = {}
        if "status" in s:
            for cat in _STATUS_CATS:
                bg, fg = _STATUS_COLORS[cat]
                btn = _ToggleBtn(cat.upper(), bg, fg)
                btn.toggled.connect(self.changed)
                self._status_btns[cat] = btn
                row2.addWidget(btn)
                row2_widgets.append(btn)

        # ── Hide types ────────────────────────────────────────────────────────
        self._hide_btns: dict[str, _ToggleBtn] = {}
        if "hide_types" in s:
            if row2_widgets:
                row2.addWidget(_vdiv())
            lbl = QLabel("Hide:")
            lbl.setStyleSheet("color:#6C7086;font-size:8px;")
            row2.addWidget(lbl)
            for t in _HIDE_TYPES:
                bg, fg = _HIDE_COLORS[t]
                btn = _ToggleBtn(_HIDE_LABELS[t], bg, fg)
                btn.toggled.connect(self.changed)
                self._hide_btns[t] = btn
                row2.addWidget(btn)
                row2_widgets.append(btn)

        # ── SSE only ──────────────────────────────────────────────────────────
        self._sse_btn: _ToggleBtn | None = None
        if "sse" in s:
            if row2_widgets:
                row2.addWidget(_vdiv())
            self._sse_btn = _ToggleBtn("SSE", "#2A1F3D", "#CBA6F7")
            self._sse_btn.toggled.connect(self.changed)
            row2.addWidget(self._sse_btn)
            row2_widgets.append(self._sse_btn)

        # ── Length range ──────────────────────────────────────────────────────
        self._len_min: QLineEdit | None = None
        self._len_max: QLineEdit | None = None
        if "length" in s:
            if row2_widgets:
                row2.addWidget(_vdiv())
            _fss = (
                "QLineEdit{background:#11111B;color:#CDD6F4;border:1px solid #313244;"
                "border-radius:3px;padding:0 4px;font-size:8px;}"
                "QLineEdit:focus{border-color:#89B4FA;}"
            )
            lbl = QLabel("Len:")
            lbl.setStyleSheet("color:#6C7086;font-size:8px;")
            row2.addWidget(lbl)

            self._len_min = QLineEdit()
            self._len_min.setPlaceholderText("Min")
            self._len_min.setFixedSize(52, 20)
            self._len_min.setStyleSheet(_fss)
            self._len_min.textChanged.connect(self.changed)

            self._len_max = QLineEdit()
            self._len_max.setPlaceholderText("Max")
            self._len_max.setFixedSize(52, 20)
            self._len_max.setStyleSheet(_fss)
            self._len_max.textChanged.connect(self.changed)

            dash = QLabel("–")
            dash.setStyleSheet("color:#45475A;font-size:9px;")
            row2.addWidget(self._len_min)
            row2.addWidget(dash)
            row2.addWidget(self._len_max)
            row2_widgets += [self._len_min, self._len_max]

        if row2_widgets:
            row2.addStretch()
            clr = _clear_btn()
            clr.clicked.connect(self._clear_row2)
            row2.addWidget(clr)

        # ── Assemble ──────────────────────────────────────────────────────────
        if row1_widgets:
            outer.addLayout(row1)
        if row1_widgets and row2_widgets:
            sep = QFrame()
            sep.setFrameShape(QFrame.HLine)
            sep.setFixedHeight(1)
            sep.setStyleSheet("background:#252535;border:none;")
            outer.addWidget(sep)
        if row2_widgets:
            outer.addLayout(row2)

    # ── filter logic ──────────────────────────────────────────────────────────

    def passes(self, doc: dict, req: dict, resp: dict, body: str,
               is_sse: bool, is_rsc: bool, length: int) -> bool:
        # Search (scope-aware)
        if self._search:
            q = self._search.text().strip().lower()
            if q and not self._search_matches(q, doc, req, resp, body):
                return False

        # Method
        if self._method_btns:
            active = {m for m, b in self._method_btns.items() if b.isChecked()}
            if active and doc.get("method", "").upper() not in active:
                return False

        # Status
        if self._status_btns:
            active = {c for c, b in self._status_btns.items() if b.isChecked()}
            if active and _status_cat(doc.get("status_code", 0)) not in active:
                return False

        # SSE only
        if self._sse_btn and self._sse_btn.isChecked() and not is_sse:
            return False

        # Hide types
        if self._hide_btns:
            active = {t for t, b in self._hide_btns.items() if b.isChecked()}
            if active:
                ftype = _file_type(doc.get("path", ""), resp, is_rsc)
                if ftype in active:
                    return False

        # Length
        if self._len_min:
            try:
                if length < int(self._len_min.text()):
                    return False
            except (ValueError, TypeError):
                pass
        if self._len_max:
            try:
                if length > int(self._len_max.text()):
                    return False
            except (ValueError, TypeError):
                pass

        return True

    def _search_matches(self, q: str, doc: dict, req: dict,
                        resp: dict, body: str) -> bool:
        """Return True if q is found in any active search scope."""
        path_on      = self._scope_path      is None or self._scope_path.isChecked()
        headers_on   = self._scope_headers   is not None and self._scope_headers.isChecked()
        req_body_on  = self._scope_req_body  is not None and self._scope_req_body.isChecked()
        resp_body_on = self._scope_resp_body is not None and self._scope_resp_body.isChecked()

        # Nothing selected → fall back to path so we never silently block all rows
        if not (path_on or headers_on or req_body_on or resp_body_on):
            path_on = True

        if path_on:
            if (q in doc.get("host", "").lower()
                    or q in doc.get("path", "").lower()
                    or q in doc.get("method", "").lower()):
                return True

        if headers_on:
            for hdrs in (req.get("headers") or {}, resp.get("headers") or {}):
                if not isinstance(hdrs, dict):
                    continue
                for k, v in hdrs.items():
                    vals = [v] if isinstance(v, str) else (v or [])
                    if q in k.lower() or any(q in str(val).lower() for val in vals):
                        return True

        if req_body_on:
            if q in str(req.get("body") or "").lower():
                return True

        if resp_body_on:
            if q in body.lower():
                return True

        return False

    # ── state ─────────────────────────────────────────────────────────────────

    def is_active(self) -> bool:
        if self._search and self._search.text().strip():
            return True
        if any(b.isChecked() for b in self._method_btns.values()):
            return True
        if any(b.isChecked() for b in self._status_btns.values()):
            return True
        if any(b.isChecked() for b in self._hide_btns.values()):
            return True
        if self._sse_btn and self._sse_btn.isChecked():
            return True
        if self._len_min and self._len_min.text().strip():
            return True
        if self._len_max and self._len_max.text().strip():
            return True
        return False

    def reset(self) -> None:
        if self._search:         self._search.clear()
        if self._len_min:        self._len_min.clear()
        if self._len_max:        self._len_max.clear()
        if self._sse_btn:        self._sse_btn.setChecked(False)
        if self._scope_path:      self._scope_path.setChecked(True)
        if self._scope_headers:   self._scope_headers.setChecked(False)
        if self._scope_req_body:  self._scope_req_body.setChecked(False)
        if self._scope_resp_body: self._scope_resp_body.setChecked(False)
        for b in [*self._method_btns.values(),
                  *self._status_btns.values(),
                  *self._hide_btns.values()]:
            b.setChecked(False)

    def to_dict(self) -> dict:
        d: dict = {}
        if self._search:
            d["search"] = self._search.text()
        if self._scope_path is not None:
            d["scope_path"]      = self._scope_path.isChecked()
            d["scope_headers"]   = self._scope_headers.isChecked()   if self._scope_headers   else False
            d["scope_req_body"]  = self._scope_req_body.isChecked()  if self._scope_req_body  else False
            d["scope_resp_body"] = self._scope_resp_body.isChecked() if self._scope_resp_body else False
        if self._method_btns:
            d["methods"] = [m for m, b in self._method_btns.items() if b.isChecked()]
        if self._status_btns:
            d["status_cats"] = [c for c, b in self._status_btns.items() if b.isChecked()]
        if self._hide_btns:
            d["hide_types"] = [t for t, b in self._hide_btns.items() if b.isChecked()]
        if self._sse_btn:
            d["sse_only"] = self._sse_btn.isChecked()
        if self._len_min:
            d["len_min"] = self._len_min.text()
        if self._len_max:
            d["len_max"] = self._len_max.text()
        return d

    def from_dict(self, data: dict) -> None:
        """Restore state without emitting changed (caller drives the refresh)."""
        all_widgets = [
            w for w in [
                self._search, self._len_min, self._len_max, self._sse_btn,
                self._scope_path, self._scope_headers,
                self._scope_req_body, self._scope_resp_body,
                *self._method_btns.values(),
                *self._status_btns.values(),
                *self._hide_btns.values(),
            ] if w is not None
        ]
        for w in all_widgets:
            w.blockSignals(True)
        try:
            if self._search:
                self._search.setText(data.get("search", ""))
            if self._scope_path is not None:
                c = data.get("scope_path", True)
                self._scope_path.setChecked(c); self._scope_path._update_style(c)
            if self._scope_headers is not None:
                c = data.get("scope_headers", False)
                self._scope_headers.setChecked(c); self._scope_headers._update_style(c)
            if self._scope_req_body is not None:
                c = data.get("scope_req_body", False)
                self._scope_req_body.setChecked(c); self._scope_req_body._update_style(c)
            if self._scope_resp_body is not None:
                c = data.get("scope_resp_body", False)
                self._scope_resp_body.setChecked(c); self._scope_resp_body._update_style(c)
            for m, b in self._method_btns.items():
                c = m in data.get("methods", [])
                b.setChecked(c); b._update_style(c)
            for cat, b in self._status_btns.items():
                c = cat in data.get("status_cats", [])
                b.setChecked(c); b._update_style(c)
            for t, b in self._hide_btns.items():
                c = t in data.get("hide_types", [])
                b.setChecked(c); b._update_style(c)
            if self._sse_btn:
                c = data.get("sse_only", False)
                self._sse_btn.setChecked(c); self._sse_btn._update_style(c)
            if self._len_min:
                self._len_min.setText(data.get("len_min", ""))
            if self._len_max:
                self._len_max.setText(data.get("len_max", ""))
        finally:
            for w in all_widgets:
                w.blockSignals(False)

    # ── internal clears ───────────────────────────────────────────────────────

    def _clear_row1(self) -> None:
        if self._search:          self._search.clear()
        if self._scope_path:      self._scope_path.setChecked(True)
        if self._scope_headers:   self._scope_headers.setChecked(False)
        if self._scope_req_body:  self._scope_req_body.setChecked(False)
        if self._scope_resp_body: self._scope_resp_body.setChecked(False)
        for b in self._method_btns.values():
            b.setChecked(False)

    def _clear_row2(self) -> None:
        if self._len_min:  self._len_min.clear()
        if self._len_max:  self._len_max.clear()
        if self._sse_btn:  self._sse_btn.setChecked(False)
        for b in [*self._status_btns.values(), *self._hide_btns.values()]:
            b.setChecked(False)
