"""
Results Window — view, filter, and export all tool outputs.

Layout
──────
  ┌─ toolbar: [Refresh] [Export] search bar ──────────────────────────────────┐
  │                                                                             │
  │  ┌─ left: category list ──┐  ┌─ right: results panel ───────────────────┐ │
  │  │  subdomain   (247)     │  │  ┌─ tool tabs ──────────────────────────┐ │ │
  │  │  dns          (89)     │  │  │ Amass(89) Subfinder(134) Combined(247)│ │ │
  │  │  endpoints  (1203)     │  │  └─────────────────────────────────────┘ │ │
  │  │  params       (44)     │  │  ┌─ stats bar ──────────────────────────┐ │ │
  │  │  portscan     (12)     │  │  │  247 unique  │ 3 tools  │ filter: 0  │ │ │
  │  │  http        (156)     │  │  └─────────────────────────────────────┘ │ │
  │  │  fuzz        (203)     │  │  ┌─ results table ─────────────────────┐ │ │
  │  │  vuln         (18)     │  │  │  col1 │ col2 │ col3 │ ...           │ │ │
  │  │  osint        (31)     │  │  └─────────────────────────────────────┘ │ │
  │  └────────────────────────┘  └─────────────────────────────────────────┘ │
  └─────────────────────────────────────────────────────────────────────────────┘
"""
import csv
import io
import json
import os
from datetime import datetime
from typing import Any

from PySide6.QtCore import Qt, QItemSelectionModel, QSortFilterProxyModel, QThread, Signal, QTimer
from PySide6.QtGui import QColor, QFont, QStandardItem, QStandardItemModel
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QComboBox, QDialog, QDialogButtonBox,
    QFileDialog, QFrame, QHBoxLayout, QLabel, QLineEdit, QListWidget,
    QListWidgetItem, QMainWindow, QMenu, QMessageBox, QPlainTextEdit,
    QPushButton, QSplitter, QTabWidget, QTableView, QVBoxLayout, QWidget,
)

from containers.results.aggregator import CategoryResults, load_all, load_from_project, load_from_session
from containers.results.asset_filter import is_static_asset
from containers.results.manual_import import parse_endpoints, parse_subdomains
from containers.results.models import (
    BaseResult, DNSRecord, EndpointResult, FuzzResult, LiveHost,
    OSINTResult, ParamResult, PortResult, SubdomainResult,
    VulnFinding, WordlistEntry,
)
from containers.tool_registry import TOOL_CATEGORIES, TOOL_REGISTRY
from database.scope import ScopeConfig
from gui.filterPanel import FilterPanel
from gui.threadrunners import register_monitored_thread


# ── Background loader ─────────────────────────────────────────────────────────

class _Loader(QThread):
    done = Signal(dict)   # {category: CategoryResults}
    error = Signal(str)

    def __init__(self, output_dir: str = "", session_id: str = "", repo=None):
        super().__init__()
        self._dir = output_dir
        self._session_id = session_id
        self._repo = repo

    def run(self):
        try:
            if self._session_id and self._repo:
                results = load_from_session(self._session_id, self._repo)
            elif self._repo:
                # No specific session pinned — show everything found so far in the
                # project, tool-run pipelines and the proxy/SiteMap tap alike.
                results = load_from_project(self._repo)
            else:
                results = load_all(self._dir)
            self.done.emit(results)
        except Exception as exc:
            self.error.emit(str(exc))


# ── Column schemas ────────────────────────────────────────────────────────────

def _row_subdomain(r: SubdomainResult) -> list[str]:
    return [r.domain, r.ip_str, str(len(r.sources)), r.source_str]

def _row_dns(r: DNSRecord) -> list[str]:
    return [r.name, r.record_type, r.value, r.source_str]

def _row_portscan(r: PortResult) -> list[str]:
    return [r.host, str(r.port), r.protocol, r.service, r.version, r.state, r.source_str]

def _row_http(r: LiveHost) -> list[str]:
    return [r.url, str(r.status_code), r.title, r.tech_str, r.source_str]

def _row_endpoint(r: EndpointResult) -> list[str]:
    return [r.url, r.method, str(r.status_code) if r.status_code else "", r.param_str, r.source_str]

def _row_param(r: ParamResult) -> list[str]:
    return [r.name, r.endpoint, r.method, r.param_type, r.source_str]

def _row_fuzz(r: FuzzResult) -> list[str]:
    return [r.url, r.path, str(r.status_code), str(r.content_length),
            str(r.words), str(r.lines), r.redirect_url, r.source_str]

def _row_vuln(r: VulnFinding) -> list[str]:
    return [r.severity.upper(), r.name, r.url, r.template_id, r.tag_str, r.source_str]

def _row_osint(r: OSINTResult) -> list[str]:
    return [r.result_type, r.value, r.provider, r.extra, r.source_str]

def _row_wordlist(r: WordlistEntry) -> list[str]:
    return [r.word, r.source_str]


# Friendly display names for non-tool sources (e.g. the proxy/SiteMap tap), which
# have no entry in TOOL_REGISTRY.
_SOURCE_LABELS: dict[str, str] = {
    "proxy_traffic": "Proxy / SiteMap",
}

SCHEMAS: dict[str, tuple[list[str], callable]] = {
    "subdomain": (["Domain", "IP Address(es)", "# Sources", "Sources"],     _row_subdomain),
    "dns":       (["Name", "Type", "Value", "Sources"],                      _row_dns),
    "portscan":  (["Host", "Port", "Protocol", "Service", "Version", "State", "Sources"], _row_portscan),
    "http":      (["URL", "Status", "Title", "Technologies", "Sources"],     _row_http),
    "crawl":     (["URL", "Method", "Status", "Parameters", "Sources"],      _row_endpoint),
    "params":    (["Parameter", "Endpoint", "Method", "Type", "Sources"],    _row_param),
    "fuzz":      (["Base URL", "Path", "Status", "Length", "Words", "Lines", "Redirect", "Sources"], _row_fuzz),
    "vuln":      (["Severity", "Name", "URL", "Template", "Tags", "Sources"], _row_vuln),
    "osint":     (["Type", "Value", "Provider", "Extra", "Sources"],         _row_osint),
}

_SCOPE_SS_ON = (
    "QPushButton{background:#1E3A2F;color:#A6E3A1;border:1px solid #A6E3A1;"
    "border-radius:4px;padding:0 10px;font-size:9px;}"
    "QPushButton:hover{background:#2A4A3F;}"
)
_SCOPE_SS_OFF = (
    "QPushButton{background:#313244;color:#6C7086;border:1px solid #45475A;"
    "border-radius:4px;padding:0 10px;font-size:9px;}"
    "QPushButton:hover{background:#45475A;color:#CDD6F4;}"
)

_SEVERITY_COLORS = {
    "CRITICAL": "#F38BA8",
    "HIGH":     "#FAB387",
    "MEDIUM":   "#F9E2AF",
    "LOW":      "#A6E3A1",
    "INFO":     "#89B4FA",
}

_STATUS_COLORS = {
    "2": "#A6E3A1",   # 2xx green
    "3": "#89B4FA",   # 3xx blue
    "4": "#FAB387",   # 4xx orange
    "5": "#F38BA8",   # 5xx red
}

# Light background tint for rows the user has reviewed (e.g. via "Open in
# Browser"). Lavender keeps it visually distinct from severity/status colors,
# which are foreground-only and use red/orange/yellow/green/blue.
_REVIEWED_BG = QColor(180, 190, 254, 35)

CATEGORY_DISPLAY = {
    "subdomain": "Subdomain Enum",
    "dns":       "DNS Records",
    "portscan":  "Port Scan",
    "http":      "Live HTTP Hosts",
    "crawl":     "Endpoints / Crawl",
    "params":    "Parameters",
    "fuzz":      "Directory Fuzz",
    "vuln":      "Vulnerabilities",
    "osint":     "OSINT / Cloud",
}

# Categories with a "Hide Static Assets" toggle — endpoints/params tables are
# dominated by CSS/JS/image noise across almost every crawler tool's output.
_ASSET_FILTER_CATEGORIES = {"crawl", "params"}


def _safe_key(r: BaseResult) -> Any:
    """`.key` is a property, not a plain attribute — some implementations can
    raise (e.g. on malformed data) rather than just be absent, so this needs
    a real try/except rather than getattr()'s default."""
    try:
        return r.key
    except Exception:
        return None


def _dedup_for_display(results: list[BaseResult]) -> list[BaseResult]:
    """Merge rows that share the same `.key`, unioning their sources.

    The aggregator already dedupes its `combined` list this way, but the
    per-tool tabs are raw appends (one entry per Mongo doc that named that
    tool as a source) — the same finding seen repeatedly (e.g. a parameter
    hit on every proxied request to an endpoint) would otherwise show once
    per occurrence instead of once overall.
    """
    seen: dict[Any, BaseResult] = {}
    order: list[Any] = []
    for r in results:
        k = _safe_key(r)
        dedup_key = k or id(r)
        if dedup_key in seen:
            seen[dedup_key].merge(r)
        else:
            seen[dedup_key] = r
            order.append(dedup_key)
    return [seen[k] for k in order]


def _param_pseudo_doc(r: ParamResult) -> tuple[dict, dict, dict, str, bool, bool, int]:
    """Adapt a ParamResult to the (doc, req, resp, body, is_sse, is_rsc, length)
    shape FilterPanel.passes() expects, so the same reusable filter widget used
    by SiteMap/HTTP History drives the Parameters table's filter too. Endpoint,
    param name, and example value are folded into "path" so the default text
    search (no search-scope toggles are shown here) matches on any of them."""
    endpoint = getattr(r, "endpoint", "") or ""
    name     = getattr(r, "name", "") or ""
    example  = str(getattr(r, "example_value", "") or "")
    method   = getattr(r, "method", "") or ""
    doc = {
        "host": "",
        "path": f"{endpoint} {name} {example}".strip(),
        "method": method,
        "status_code": 0,
    }
    req  = {"headers": {}, "body": ""}
    resp = {"headers": {}}
    return doc, req, resp, "", False, False, len(example)


def _result_scope_key(category: str, r: BaseResult) -> str:
    """Best-effort host/URL string for scope matching. Empty string means
    "no clear host for this category" — callers treat that as always in scope
    rather than hiding rows they can't classify."""
    try:
        if category == "subdomain":
            return r.domain
        if category == "dns":
            return r.name
        if category == "portscan":
            return r.host
        if category in ("http", "crawl", "fuzz", "vuln"):
            return r.url
        if category == "params":
            return r.endpoint
    except AttributeError:
        pass
    return ""


# ── Filterable table model ────────────────────────────────────────────────────

class _ResultsModel(QStandardItemModel):
    def __init__(self, headers: list[str]):
        super().__init__()
        self.setHorizontalHeaderLabels(headers)

    def populate(self, rows: list[list[str]], category: str = "",
                 reviewed_flags: list[bool] | None = None):
        self.removeRows(0, self.rowCount())
        for i, row_data in enumerate(rows):
            reviewed = bool(reviewed_flags[i]) if reviewed_flags else False
            items = []
            for col, cell in enumerate(row_data):
                item = QStandardItem(cell)
                item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
                # Colour severity column for vulns
                if category == "vuln" and col == 0:
                    color = _SEVERITY_COLORS.get(cell.upper(), "")
                    if color:
                        item.setForeground(QColor(color))
                # Colour status codes
                if category in ("http", "crawl", "fuzz") and col in (1, 2):
                    if cell and cell[0] in _STATUS_COLORS:
                        item.setForeground(QColor(_STATUS_COLORS[cell[0]]))
                if reviewed:
                    item.setBackground(_REVIEWED_BG)
                items.append(item)
            self.appendRow(items)


# ── Table widget ──────────────────────────────────────────────────────────────

class _ResultsTable(QWidget):
    def __init__(self, category: str, repo=None, session_id: str = "", parent=None):
        super().__init__(parent)
        self._category = category
        self._repo = repo
        self._session_id = session_id
        self._all_results: list[BaseResult] = []
        self._row_results: list[BaseResult] = []   # aligned with the model's rows
        self._reviewed_keys: set[str] = set()
        self._search: QLineEdit | None = None
        self._filter_panel: FilterPanel | None = None
        self._filter_btn: QPushButton | None = None
        self._reset_btn: QPushButton | None = None
        self._hide_static = True   # endpoints/params: CSS/JS/image noise hidden by default
        self._hideStaticBtn: QPushButton | None = None
        self._asset_hidden_count = 0

        vbox = QVBoxLayout(self)
        vbox.setContentsMargins(0, 0, 0, 0)
        vbox.setSpacing(4)

        if category == "params":
            self._build_advanced_filter_bar(vbox)
        else:
            # search bar
            search_row = QHBoxLayout()
            self._search = QLineEdit()
            self._search.setPlaceholderText("Filter rows… (Ctrl+F)")
            self._search.setObjectName("urlText")
            self._search.textChanged.connect(self._on_filter)
            search_row.addWidget(self._search)
            if category in _ASSET_FILTER_CATEGORIES:
                self._hideStaticBtn = self._build_hide_static_button()
                search_row.addWidget(self._hideStaticBtn)
            vbox.addLayout(search_row)

        # stats bar
        self._stats = QLabel()
        self._stats.setObjectName("certDialogSubtitle")
        vbox.addWidget(self._stats)

        # table view
        schema = SCHEMAS.get(category, (["Value", "Sources"], lambda r: [str(r), r.source_str]))
        headers, _ = schema
        self._model = _ResultsModel(headers)
        self._proxy = QSortFilterProxyModel()
        self._proxy.setSourceModel(self._model)
        self._proxy.setFilterCaseSensitivity(Qt.CaseInsensitive)
        self._proxy.setFilterKeyColumn(-1)   # search all columns

        self._view = QTableView()
        self._view.setModel(self._proxy)
        self._view.setSortingEnabled(True)
        self._view.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._view.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self._view.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._view.horizontalHeader().setStretchLastSection(True)
        self._view.verticalHeader().setVisible(False)
        self._view.setAlternatingRowColors(True)
        self._view.setObjectName("siteMapTreeView")
        mono = QFont("Cascadia Code", 9)
        self._view.setFont(mono)
        self._view.setContextMenuPolicy(Qt.CustomContextMenu)
        self._view.customContextMenuRequested.connect(self._on_context_menu)
        vbox.addWidget(self._view)

    def _build_advanced_filter_bar(self, vbox: QVBoxLayout) -> None:
        """Parameters table only: a reusable FilterPanel (same widget as
        SiteMap/HTTP History) behind a Filters ▾ toggle, instead of the plain
        text box the other categories use."""
        top_row = QHBoxLayout()
        self._filter_btn = QPushButton("Filters ▾")
        self._filter_btn.setCheckable(True)
        self._filter_btn.setFixedHeight(22)
        self._filter_btn.toggled.connect(self._on_filter_toggle)
        top_row.addWidget(self._filter_btn)

        self._reset_btn = QPushButton("Reset")
        self._reset_btn.setFixedHeight(22)
        self._reset_btn.setVisible(False)
        self._reset_btn.clicked.connect(self._on_filter_reset)
        top_row.addWidget(self._reset_btn)
        top_row.addStretch()
        self._hideStaticBtn = self._build_hide_static_button()
        top_row.addWidget(self._hideStaticBtn)
        vbox.addLayout(top_row)

        self._filter_panel = FilterPanel(sections={"search", "method"})
        self._filter_panel.setVisible(False)
        self._filter_panel.changed.connect(self._on_advanced_filter_changed)
        vbox.addWidget(self._filter_panel)

    def _build_hide_static_button(self) -> QPushButton:
        """Toggle for hiding CSS/JS/image/font/media rows — on by default,
        since these dominate crawl/parameter output by volume but are rarely
        interesting from an attack-surface standpoint."""
        btn = QPushButton("Hide Static Assets")
        btn.setCheckable(True)
        btn.setChecked(True)
        btn.setFixedHeight(22)
        btn.setStyleSheet(_SCOPE_SS_ON)
        btn.toggled.connect(self._on_hide_static_toggle)
        return btn

    def _on_hide_static_toggle(self, checked: bool) -> None:
        self._hide_static = checked
        self._hideStaticBtn.setText("Hide Static Assets" if checked else "Show Static Assets")
        self._hideStaticBtn.setStyleSheet(_SCOPE_SS_ON if checked else _SCOPE_SS_OFF)
        self._rebuild()
        self._update_stats()

    def _asset_url(self, r: BaseResult) -> str:
        if self._category == "crawl":
            return getattr(r, "url", "") or ""
        if self._category == "params":
            return getattr(r, "endpoint", "") or ""
        return ""

    def _on_filter_toggle(self, checked: bool) -> None:
        self._filter_panel.setVisible(checked)
        self._filter_btn.setText("Filters ▴" if checked else "Filters ▾")

    def _on_advanced_filter_changed(self) -> None:
        self._rebuild()
        self._update_stats()
        self._reset_btn.setVisible(self._filter_panel.is_active())

    def _on_filter_reset(self) -> None:
        self._filter_panel.reset()
        self._reset_btn.setVisible(False)
        self._rebuild()
        self._update_stats()

    def _passes_advanced_filter(self, r: BaseResult) -> bool:
        doc, req, resp, body, is_sse, is_rsc, length = _param_pseudo_doc(r)
        return self._filter_panel.passes(doc, req, resp, body, is_sse, is_rsc, length)

    def load(self, results: list[BaseResult]):
        self._all_results = _dedup_for_display(results)
        if self._repo is not None:
            try:
                self._reviewed_keys = self._repo.get_reviewed_keys(self._category)
            except Exception:
                self._reviewed_keys = set()
        self._rebuild()
        self._update_stats()

    def _rebuild(self):
        schema = SCHEMAS.get(self._category,
                              (["Value", "Sources"], lambda r: [str(r), r.source_str]))
        _, row_fn = schema
        results = self._all_results
        if self._filter_panel is not None:
            results = [r for r in results if self._passes_advanced_filter(r)]
        self._asset_hidden_count = 0
        if self._category in _ASSET_FILTER_CATEGORIES and self._hide_static:
            before = len(results)
            results = [r for r in results if not is_static_asset(self._asset_url(r))]
            self._asset_hidden_count = before - len(results)
        rows = []
        row_results = []
        reviewed_flags = []
        for r in results:
            try:
                row = row_fn(r)
            except Exception:
                continue
            rows.append(row)
            row_results.append(r)
            reviewed_flags.append(self._is_reviewed(r))
        self._row_results = row_results
        self._model.populate(rows, self._category, reviewed_flags)
        self._view.resizeColumnsToContents()

    def _is_reviewed(self, r: BaseResult) -> bool:
        k = _safe_key(r)
        if k is None:
            return False
        return k in self._reviewed_keys

    def _set_reviewed(self, r: BaseResult, reviewed: bool) -> None:
        k = _safe_key(r)
        if k is None:
            return
        if reviewed:
            self._reviewed_keys.add(k)
        else:
            self._reviewed_keys.discard(k)
        if self._repo is not None:
            try:
                self._repo.mark_result_reviewed(self._category, k, reviewed)
            except Exception:
                pass
        self._rebuild()
        self._update_stats()

    def _on_filter(self, text: str):
        self._proxy.setFilterFixedString(text)
        self._update_stats()

    def _update_stats(self):
        total = self._model.rowCount()
        visible = self._proxy.rowCount()
        sources = set()
        for r in self._all_results:
            sources.update(r.sources)
        extra = f"  ·  {self._asset_hidden_count} static hidden" if self._asset_hidden_count else ""
        self._stats.setText(
            f"{total} unique  ·  {len(sources)} tool(s)  ·  showing {visible}{extra}"
        )

    def visible_rows(self) -> list[list[str]]:
        rows = []
        for i in range(self._proxy.rowCount()):
            row = []
            for j in range(self._model.columnCount()):
                src_idx = self._proxy.mapToSource(self._proxy.index(i, j))
                row.append(self._model.item(src_idx.row(), src_idx.column()).text())
            rows.append(row)
        return rows

    def headers(self) -> list[str]:
        return [self._model.horizontalHeaderItem(i).text()
                for i in range(self._model.columnCount())]

    def search_widget(self) -> QLineEdit:
        return self._search

    # ── Context menu ──────────────────────────────────────────────────────────

    def _on_context_menu(self, pos) -> None:
        idx = self._view.indexAt(pos)
        if not idx.isValid():
            return

        # Right-clicking a row that's part of the current multi-selection acts
        # on the whole selection; right-clicking outside it re-selects just
        # the clicked row (standard Qt/Explorer-style behaviour).
        sel_rows = sorted({i.row() for i in self._view.selectionModel().selectedRows()})
        if idx.row() not in sel_rows:
            self._view.selectionModel().select(
                idx, QItemSelectionModel.ClearAndSelect | QItemSelectionModel.Rows)
            sel_rows = [idx.row()]

        src_row = self._proxy.mapToSource(idx).row()
        row_data = []
        for col in range(self._model.columnCount()):
            it = self._model.item(src_row, col)
            row_data.append(it.text() if it else "")

        url    = self._row_url(row_data)
        result = self._row_results[src_row] if src_row < len(self._row_results) else None
        reviewed = self._is_reviewed(result) if result is not None else False

        selected_results: list[BaseResult] = []
        for prow in sel_rows:
            srow = self._proxy.mapToSource(self._proxy.index(prow, 0)).row()
            if srow < len(self._row_results):
                selected_results.append(self._row_results[srow])

        menu     = QMenu(self)
        open_act = menu.addAction("Open in Browser")
        open_act.setEnabled(bool(url))

        copy_act = menu.addAction("Copy Cell")
        cell_text = row_data[idx.column()] if idx.column() < len(row_data) else ""
        copy_act.setEnabled(bool(cell_text))

        review_act = menu.addAction("Mark Not Reviewed" if reviewed else "Mark Reviewed")
        review_act.setEnabled(result is not None)

        menu.addSeparator()
        delete_label = "Delete Row" if len(selected_results) <= 1 else f"Delete {len(selected_results)} Rows"
        delete_act = menu.addAction(delete_label)
        delete_act.setEnabled(bool(selected_results) and self._repo is not None)

        chosen = menu.exec(self._view.viewport().mapToGlobal(pos))
        if chosen is open_act and url:
            tw = self._find_target_window()
            if tw:
                tw.openNewBrowserTab(url)
            # Opening a row in the browser counts as having reviewed it.
            if result is not None:
                self._set_reviewed(result, True)
        elif chosen is copy_act and cell_text:
            QApplication.clipboard().setText(cell_text)
        elif chosen is review_act and result is not None:
            self._set_reviewed(result, not reviewed)
        elif chosen is delete_act and selected_results:
            self._delete_results(selected_results)

    def _find_target_window(self):
        w = self.parent()
        while w is not None:
            if hasattr(w, 'openNewBrowserTab'):
                return w
            w = w.parent()
        return None

    def _find_results_window(self):
        w = self.parent()
        while w is not None:
            if hasattr(w, 'remove_results'):
                return w
            w = w.parent()
        return None

    def _delete_results(self, results: list[BaseResult]) -> None:
        """Context menu 'Delete' — removes the selected row(s) from MongoDB
        (not just this table), so they don't reappear on the next refresh."""
        if self._repo is None:
            return
        n = len(results)
        label = "this result" if n == 1 else f"these {n} results"
        confirm = QMessageBox.question(
            self, "Delete",
            f"Permanently delete {label} from the database? This cannot be undone.",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return

        keys = [k for k in (_safe_key(r) for r in results) if k is not None]
        if not keys:
            return

        try:
            self._repo.delete_results(self._category, keys, session_id=self._session_id or None)
        except Exception as exc:
            QMessageBox.warning(self, "Delete", f"Delete failed:\n{exc}")
            return

        keyset = set(keys)
        rw = self._find_results_window()
        if rw is not None:
            # Updates every tab (combined + per-tool) and the sidebar count
            # in one pass, without a full DB reload.
            rw.remove_results(self._category, keyset)
        else:
            self._all_results = [r for r in self._all_results if _safe_key(r) not in keyset]
            self._reviewed_keys -= keyset
            self._rebuild()
            self._update_stats()

    def _row_url(self, row: list[str]) -> str | None:
        if not row:
            return None
        cat = self._category
        if cat == "subdomain":
            return f"https://{row[0]}" if row[0] else None
        if cat in ("http", "crawl", "fuzz"):
            return row[0] or None
        if cat == "vuln":
            return row[2] if len(row) > 2 and row[2] else None
        if cat == "params":
            return row[1] if len(row) > 1 and row[1] else None
        if cat == "portscan":
            host, port = row[0], row[1] if len(row) > 1 else ""
            if host and port:
                scheme = "https" if port in ("443", "8443") else "http"
                return f"{scheme}://{host}:{port}"
        return None


# ── Category panel (tabs per tool + combined) ─────────────────────────────────

class _CategoryPanel(QWidget):
    def __init__(self, category: str, repo=None, session_id: str = "", parent=None):
        super().__init__(parent)
        self._category = category
        self._repo = repo
        self._session_id = session_id
        self._tables: dict[str, _ResultsTable] = {}

        vbox = QVBoxLayout(self)
        vbox.setContentsMargins(0, 0, 0, 0)

        self._tabs = QTabWidget()
        self._tabs.setObjectName("dockerLeftTabs")
        vbox.addWidget(self._tabs)

    def load(self, cat_results: CategoryResults):
        self._tabs.clear()
        self._tables.clear()

        # Combined tab first
        combined_table = _ResultsTable(self._category, repo=self._repo, session_id=self._session_id)
        combined_table.load(cat_results.combined)
        self._tabs.addTab(combined_table,
                          f"Combined  ({len(cat_results.combined)})")
        self._tables["combined"] = combined_table

        # Per-tool tabs
        for tool_key, results in sorted(cat_results.per_tool.items(),
                                         key=lambda kv: -len(kv[1])):
            if not results:
                continue
            display = TOOL_REGISTRY.get(tool_key, None)
            label = display.display_name if display else _SOURCE_LABELS.get(tool_key, tool_key)
            t = _ResultsTable(self._category, repo=self._repo, session_id=self._session_id)
            t.load(results)
            self._tabs.addTab(t, f"{label}  ({len(results)})")
            self._tables[tool_key] = t

    def current_table(self) -> _ResultsTable | None:
        w = self._tabs.currentWidget()
        return w if isinstance(w, _ResultsTable) else None


# ── Import dialog ─────────────────────────────────────────────────────────────

class _ImportDialog(QDialog):
    """Pick a category, load a .txt file (or paste directly), and preview the
    lines before importing them as results — one subdomain/URL per line."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Import from file")
        self.resize(560, 460)

        vbox = QVBoxLayout(self)

        row = QHBoxLayout()
        row.addWidget(QLabel("Import as:"))
        self._kindCombo = QComboBox()
        self._kindCombo.addItem("Subdomains", "subdomain")
        self._kindCombo.addItem("URL Endpoints", "crawl")
        row.addWidget(self._kindCombo, stretch=1)

        browseBtn = QPushButton("Browse…")
        browseBtn.clicked.connect(self._browse)
        row.addWidget(browseBtn)
        vbox.addLayout(row)

        hint = QLabel(
            "One entry per line. Blank lines and '#' comments are ignored.\n"
            "Endpoints may optionally be prefixed with an HTTP method, e.g. "
            "\"POST https://host/api/login\"."
        )
        hint.setObjectName("certDialogSubtitle")
        hint.setWordWrap(True)
        vbox.addWidget(hint)

        self._text = QPlainTextEdit()
        self._text.setPlaceholderText("Paste entries here, or Browse… for a .txt file")
        mono = QFont("Cascadia Code", 9)
        self._text.setFont(mono)
        vbox.addWidget(self._text, stretch=1)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        vbox.addWidget(buttons)

    def _browse(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select a text file", "", "Text files (*.txt);;All files (*)"
        )
        if not path:
            return
        try:
            with open(path, "r", errors="replace") as f:
                self._text.setPlainText(f.read())
        except OSError as exc:
            QMessageBox.warning(self, "Import", f"Could not read file:\n{exc}")

    def category(self) -> str:
        return self._kindCombo.currentData()

    def text(self) -> str:
        return self._text.toPlainText()


# ── Main window ───────────────────────────────────────────────────────────────

class ResultsWindow(QMainWindow):
    def __init__(
        self,
        output_dir: str = "",
        session_id: str = "",
        repo=None,
        parent=None,
    ):
        super().__init__(parent)
        self._output_dir = output_dir
        self._session_id = session_id
        self._repo = repo
        self._raw_results: dict[str, CategoryResults] = {}     # unscoped, straight from the loader
        self._all_results: dict[str, CategoryResults] = {}     # scope-filtered view actually displayed
        self._panels: dict[str, _CategoryPanel] = {}
        self._loader: _Loader | None = None
        self._scope = ScopeConfig()
        self._filter_scope = True
        self._load_scope()

        self._update_title()
        self.resize(1400, 820)

        self._build_ui()
        self._load()

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build_ui(self):
        root = QWidget()
        self.setCentralWidget(root)
        vbox = QVBoxLayout(root)
        vbox.setContentsMargins(8, 4, 8, 8)
        vbox.setSpacing(0)

        toolbar = self._build_toolbar()
        toolbar.setFixedHeight(36)
        vbox.addWidget(toolbar)
        vbox.addWidget(self._hline())

        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(self._build_sidebar())
        splitter.addWidget(self._build_main_area())
        splitter.setSizes([210, 1150])
        vbox.addWidget(splitter)

    def _build_toolbar(self) -> QWidget:
        w = QWidget()
        row = QHBoxLayout(w)
        row.setContentsMargins(0, 0, 0, 0)

        self._statusLabel = QLabel("Loading…")
        self._statusLabel.setObjectName("dockerStatusMsg")
        row.addWidget(self._statusLabel)
        row.addStretch()

        self._scopeBtn = QPushButton("Filter by Scope: ON")
        self._scopeBtn.setCheckable(True)
        self._scopeBtn.setChecked(True)
        self._scopeBtn.setFixedHeight(24)
        self._scopeBtn.setStyleSheet(_SCOPE_SS_ON)
        self._scopeBtn.toggled.connect(self._on_scope_toggle)
        row.addWidget(self._scopeBtn)

        self._globalSearch = QLineEdit()
        self._globalSearch.setPlaceholderText("Global search…")
        self._globalSearch.setFixedWidth(220)
        self._globalSearch.setObjectName("urlText")
        self._globalSearch.textChanged.connect(self._on_global_search)
        row.addWidget(self._globalSearch)

        refreshBtn = QPushButton("Refresh")
        refreshBtn.clicked.connect(self._load)
        row.addWidget(refreshBtn)

        importBtn = QPushButton("Import")
        importBtn.clicked.connect(self._import)
        row.addWidget(importBtn)

        exportBtn = QPushButton("Export")
        exportBtn.setObjectName("primaryButton")
        exportBtn.clicked.connect(self._export)
        row.addWidget(exportBtn)
        return w

    def _build_sidebar(self) -> QWidget:
        w = QWidget()
        vbox = QVBoxLayout(w)
        vbox.setContentsMargins(0, 0, 4, 0)
        vbox.setSpacing(4)

        title = QLabel("Categories")
        title.setObjectName("certStepLabel")
        vbox.addWidget(title)

        self._catList = QListWidget()
        self._catList.setObjectName("siteMapTreeView")
        self._catList.currentItemChanged.connect(self._on_category_selected)
        font = QFont("Cascadia Code", 9)
        self._catList.setFont(font)
        vbox.addWidget(self._catList)
        return w

    def _build_main_area(self) -> QWidget:
        self._mainStack = QWidget()
        self._mainLayout = QVBoxLayout(self._mainStack)
        self._mainLayout.setContentsMargins(0, 0, 0, 0)

        placeholder = QLabel("Select a category →")
        placeholder.setAlignment(Qt.AlignCenter)
        placeholder.setObjectName("certDialogSubtitle")
        self._mainLayout.addWidget(placeholder)
        self._placeholder = placeholder
        return self._mainStack

    # ── Public refresh API ────────────────────────────────────────────────────

    def refresh(self) -> None:
        """Re-run the current load (same session, or the whole-project view) —
        called after new data lands, e.g. a proxy/SiteMap traffic sync."""
        self._load()

    def load_session(self, session_id: str, repo) -> None:
        """Narrow the view to a specific pipeline session — only called when the
        user explicitly asks to view one pipeline's results (e.g. "View Results"
        from the Pipeline page/Live Monitor). Any other navigation to the Results
        page should leave (or restore) the merged, all-sessions default —
        see show_merged()."""
        self._session_id = session_id
        self._repo = repo
        self._output_dir = ""
        self._reset_main_area()
        self._update_title()
        self._load()

    def show_merged(self) -> None:
        """Reset to the project-wide merged view — every pipeline session plus
        the proxy/SiteMap tap. This is the default, and is what the generic
        "Results" nav button restores to even after a prior load_session()
        narrowed the view to one pipeline's session."""
        if not self._session_id:
            return   # already merged — avoid an unnecessary reload
        self._session_id = ""
        self._reset_main_area()
        self._update_title()
        self._load()

    def _update_title(self) -> None:
        title = "Results"
        if self._session_id and self._repo:
            session = self._repo.get_session(self._session_id)
            if session:
                target = session.get("target", "")
                pipe = session.get("pipeline_name", "")
                dt = (session.get("started_at") or "")[:16].replace("T", " ")
                title = f"Results — {pipe}  ·  {target}  ·  {dt}"
        elif self._repo:
            title = "Results — All Sessions"
        self.setWindowTitle(title)

    def _reset_main_area(self) -> None:
        self._panels.clear()
        self._detach_main_widgets()
        self._mainLayout.addWidget(self._placeholder)
        self._placeholder.show()

    def _detach_main_widgets(self) -> None:
        while self._mainLayout.count():
            item = self._mainLayout.takeAt(0)
            w = item.widget()
            if w:
                # Hide before detaching — an orphaned widget that's still
                # visible gets promoted to its own top-level window by Qt.
                w.hide()
                w.setParent(None)

    # ── Data loading ──────────────────────────────────────────────────────────

    def _load(self):
        self._statusLabel.setText("Loading results…")
        if self._loader and self._loader.isRunning():
            return
        self._loader = _Loader(
            output_dir=self._output_dir,
            session_id=self._session_id,
            repo=self._repo,
        )
        self._loader.done.connect(self._on_loaded)
        self._loader.error.connect(lambda e: self._statusLabel.setText(f"Error: {e}"))
        register_monitored_thread(self._loader, self, "Results Loader")
        self._loader.start()

    def _on_loaded(self, all_results: dict):
        self._raw_results = all_results
        self._recompute_scoped_results()
        total = sum(cr.total_unique for cr in self._all_results.values())
        if self._session_id:
            source_hint = f"session {self._session_id[:8]}… (MongoDB)"
        elif self._repo:
            source_hint = "all sessions, incl. proxy/SiteMap (MongoDB)"
        else:
            source_hint = self._output_dir
        self._statusLabel.setText(f"{total} unique results  ·  {source_hint}")
        # Auto-select first category with results
        for i in range(self._catList.count()):
            item = self._catList.item(i)
            if item.data(Qt.UserRole + 1) > 0:
                self._catList.setCurrentItem(item)
                break

    # ── Scope ─────────────────────────────────────────────────────────────────

    def _load_scope(self) -> None:
        if self._repo:
            try:
                self._scope = self._repo.get_scope()
            except Exception:
                pass

    def _on_scope_toggle(self, checked: bool) -> None:
        self._filter_scope = checked
        self._scopeBtn.setText(f"Filter by Scope: {'ON' if checked else 'OFF'}")
        self._scopeBtn.setStyleSheet(_SCOPE_SS_ON if checked else _SCOPE_SS_OFF)
        self._load_scope()
        self._recompute_scoped_results()

    def _recompute_scoped_results(self) -> None:
        cat_item = self._catList.currentItem()
        current_cat = cat_item.data(Qt.UserRole) if cat_item is not None else None

        if self._filter_scope:
            self._all_results = {
                cat: self._scope_filter_category(cr) for cat, cr in self._raw_results.items()
            }
        else:
            self._all_results = dict(self._raw_results)
        self._rebuild_sidebar()

        # Restore the same category selection (rebuild cleared it) — this re-triggers
        # _show_category via currentItemChanged so the visible panel reflects scope too.
        if current_cat is not None:
            for i in range(self._catList.count()):
                item = self._catList.item(i)
                if item.data(Qt.UserRole) == current_cat:
                    self._catList.setCurrentItem(item)
                    break

    def _scope_filter_category(self, cr: CategoryResults) -> CategoryResults:
        def _in_scope(r: BaseResult) -> bool:
            host = _result_scope_key(cr.category, r)
            return not host or self._scope.matches(host)

        return CategoryResults(
            category=cr.category,
            per_tool={t: [r for r in rs if _in_scope(r)] for t, rs in cr.per_tool.items()},
            combined=[r for r in cr.combined if _in_scope(r)],
        )

    # ── Row deletion ──────────────────────────────────────────────────────────

    def remove_results(self, category: str, keys: set[str]) -> None:
        """Called by a table's context-menu Delete after it removes the rows
        from MongoDB — strips them from the in-memory raw/scoped result sets
        and rebuilds the sidebar + panel in place. Deliberately not a full
        _load(): that would re-run _on_loaded()'s "auto-select first category"
        jump and bounce the user away from the category they were just editing."""
        def _strip(cr: CategoryResults | None) -> CategoryResults | None:
            if cr is None:
                return cr
            return CategoryResults(
                category=cr.category,
                per_tool={t: [r for r in rs if _safe_key(r) not in keys] for t, rs in cr.per_tool.items()},
                combined=[r for r in cr.combined if _safe_key(r) not in keys],
            )

        if category in self._raw_results:
            self._raw_results[category] = _strip(self._raw_results[category])
        self._recompute_scoped_results()

    def _rebuild_sidebar(self):
        self._catList.clear()
        for cat in ["subdomain", "dns", "portscan", "http", "crawl",
                     "params", "fuzz", "vuln", "osint"]:
            cr = self._all_results.get(cat)
            count = cr.total_unique if cr else 0
            label = CATEGORY_DISPLAY.get(cat, cat)
            item = QListWidgetItem(f"{label}  ({count})")
            item.setData(Qt.UserRole, cat)
            item.setData(Qt.UserRole + 1, count)
            if count == 0:
                item.setForeground(QColor("#585B70"))
            else:
                item.setForeground(QColor("#CDD6F4"))
            self._catList.addItem(item)

    # ── Category switching ────────────────────────────────────────────────────

    def _on_category_selected(self, current, _previous):
        if current is None:
            return
        cat = current.data(Qt.UserRole)
        if cat is None:
            return
        self._show_category(cat)

    def _show_category(self, cat: str):
        self._detach_main_widgets()

        if cat not in self._panels:
            panel = _CategoryPanel(cat, repo=self._repo, session_id=self._session_id)
            self._panels[cat] = panel

        panel = self._panels[cat]
        cr = self._all_results.get(cat)
        if cr and cr.has_results():
            panel.load(cr)
        else:
            panel.load(CategoryResults(category=cat))

        self._mainLayout.addWidget(panel)
        panel.show()

        # Apply global search to new panel (categories with a plain search box only —
        # the Parameters table's FilterPanel has its own independent search field)
        q = self._globalSearch.text()
        if q:
            table = panel.current_table()
            if table and table.search_widget():
                table.search_widget().setText(q)

    # ── Filtering ─────────────────────────────────────────────────────────────

    def _on_global_search(self, text: str):
        # Apply search to the currently visible panel's current table
        cat_item = self._catList.currentItem()
        if cat_item is None:
            return
        cat = cat_item.data(Qt.UserRole)
        panel = self._panels.get(cat)
        if panel:
            table = panel.current_table()
            if table and table.search_widget():
                table.search_widget().setText(text)

    # ── Export ────────────────────────────────────────────────────────────────

    def _export(self):
        cat_item = self._catList.currentItem()
        if cat_item is None:
            return
        cat = cat_item.data(Qt.UserRole)
        panel = self._panels.get(cat)
        if not panel:
            return
        table = panel.current_table()
        if not table:
            return

        path, fmt = QFileDialog.getSaveFileName(
            self,
            "Export Results",
            f"{cat}_results_{datetime.now():%Y%m%d_%H%M%S}",
            "CSV (*.csv);;JSON (*.json);;Text (*.txt)",
        )
        if not path:
            return

        headers = table.headers()
        rows = table.visible_rows()

        if path.endswith(".json"):
            data = [dict(zip(headers, row)) for row in rows]
            with open(path, "w") as f:
                json.dump(data, f, indent=2)
        elif path.endswith(".txt"):
            with open(path, "w") as f:
                for row in rows:
                    f.write("\t".join(row) + "\n")
        else:
            with open(path, "w", newline="") as f:
                w = csv.writer(f)
                w.writerow(headers)
                w.writerows(rows)

        self._statusLabel.setText(f"Exported {len(rows)} rows → {path}")

    # ── Import ────────────────────────────────────────────────────────────────

    def _import(self):
        if self._repo is None:
            QMessageBox.warning(
                self, "Import",
                "Importing requires an open project (no database connection available).",
            )
            return

        dlg = _ImportDialog(self)
        if dlg.exec() != QDialog.Accepted:
            return

        category = dlg.category()
        text = dlg.text()
        if not text.strip():
            return

        if category == "subdomain":
            results = parse_subdomains(text)
        else:
            results = parse_endpoints(text)

        if not results:
            QMessageBox.information(self, "Import", "No valid entries found.")
            return

        try:
            session_id = self._repo.get_or_create_manual_import_session()
            run_id = self._repo.get_manual_import_tool_run_id(session_id)
            count = self._repo.upsert_results(session_id, run_id, category, results)
        except Exception as exc:
            QMessageBox.warning(self, "Import", f"Import failed:\n{exc}")
            return

        self._statusLabel.setText(
            f"Imported {len(results)} entries → {count} new unique "
            f"{CATEGORY_DISPLAY.get(category, category)}"
        )
        self._load()

    # ── helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _hline() -> QFrame:
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setObjectName("certDivider")
        return line
