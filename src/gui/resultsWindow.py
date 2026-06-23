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

from PySide6.QtCore import Qt, QSortFilterProxyModel, QThread, Signal, QTimer
from PySide6.QtGui import QColor, QFont, QStandardItem, QStandardItemModel
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QComboBox, QFileDialog, QFrame,
    QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem,
    QMainWindow, QMenu, QPushButton, QSplitter, QTabWidget, QTableView,
    QVBoxLayout, QWidget,
)

from containers.results.aggregator import CategoryResults, load_all, load_from_session
from containers.results.models import (
    BaseResult, DNSRecord, EndpointResult, FuzzResult, LiveHost,
    OSINTResult, ParamResult, PortResult, SubdomainResult,
    VulnFinding, WordlistEntry,
)
from containers.tool_registry import TOOL_CATEGORIES, TOOL_REGISTRY


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


# ── Filterable table model ────────────────────────────────────────────────────

class _ResultsModel(QStandardItemModel):
    def __init__(self, headers: list[str]):
        super().__init__()
        self.setHorizontalHeaderLabels(headers)

    def populate(self, rows: list[list[str]], category: str = ""):
        self.removeRows(0, self.rowCount())
        for row_data in rows:
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
                items.append(item)
            self.appendRow(items)


# ── Table widget ──────────────────────────────────────────────────────────────

class _ResultsTable(QWidget):
    def __init__(self, category: str, parent=None):
        super().__init__(parent)
        self._category = category
        self._all_results: list[BaseResult] = []

        vbox = QVBoxLayout(self)
        vbox.setContentsMargins(0, 0, 0, 0)
        vbox.setSpacing(4)

        # search bar
        search_row = QHBoxLayout()
        self._search = QLineEdit()
        self._search.setPlaceholderText("Filter rows… (Ctrl+F)")
        self._search.setObjectName("urlText")
        self._search.textChanged.connect(self._on_filter)
        search_row.addWidget(self._search)
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

    def load(self, results: list[BaseResult]):
        self._all_results = results
        self._rebuild()
        self._update_stats()

    def _rebuild(self):
        schema = SCHEMAS.get(self._category,
                              (["Value", "Sources"], lambda r: [str(r), r.source_str]))
        _, row_fn = schema
        rows = []
        for r in self._all_results:
            try:
                rows.append(row_fn(r))
            except Exception:
                pass
        self._model.populate(rows, self._category)
        self._view.resizeColumnsToContents()

    def _on_filter(self, text: str):
        self._proxy.setFilterFixedString(text)
        self._update_stats()

    def _update_stats(self):
        total = self._model.rowCount()
        visible = self._proxy.rowCount()
        sources = set()
        for r in self._all_results:
            sources.update(r.sources)
        self._stats.setText(
            f"{total} unique  ·  {len(sources)} tool(s)  ·  showing {visible}"
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
        row_data = []
        for col in range(self._model.columnCount()):
            src = self._proxy.mapToSource(self._proxy.index(idx.row(), col))
            it  = self._model.item(src.row(), src.column())
            row_data.append(it.text() if it else "")

        url = self._row_url(row_data)

        menu     = QMenu(self)
        open_act = menu.addAction("Open in Browser")
        open_act.setEnabled(bool(url))

        copy_act = menu.addAction("Copy Cell")
        cell_text = row_data[idx.column()] if idx.column() < len(row_data) else ""
        copy_act.setEnabled(bool(cell_text))

        chosen = menu.exec(self._view.viewport().mapToGlobal(pos))
        if chosen is open_act and url:
            tw = self._find_target_window()
            if tw:
                tw.openNewBrowserTab(url)
        elif chosen is copy_act and cell_text:
            QApplication.clipboard().setText(cell_text)

    def _find_target_window(self):
        w = self.parent()
        while w is not None:
            if hasattr(w, 'openNewBrowserTab'):
                return w
            w = w.parent()
        return None

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
    def __init__(self, category: str, parent=None):
        super().__init__(parent)
        self._category = category
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
        combined_table = _ResultsTable(self._category)
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
            label = display.display_name if display else tool_key
            t = _ResultsTable(self._category)
            t.load(results)
            self._tabs.addTab(t, f"{label}  ({len(results)})")
            self._tables[tool_key] = t

    def current_table(self) -> _ResultsTable | None:
        w = self._tabs.currentWidget()
        return w if isinstance(w, _ResultsTable) else None


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
        self._all_results: dict[str, CategoryResults] = {}
        self._panels: dict[str, _CategoryPanel] = {}
        self._loader: _Loader | None = None

        title = "Results"
        if session_id and repo:
            session = repo.get_session(session_id)
            if session:
                target = session.get("target", "")
                pipe = session.get("pipeline_name", "")
                dt = (session.get("started_at") or "")[:16].replace("T", " ")
                title = f"Results — {pipe}  ·  {target}  ·  {dt}"
        self.setWindowTitle(title)
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

        self._globalSearch = QLineEdit()
        self._globalSearch.setPlaceholderText("Global search…")
        self._globalSearch.setFixedWidth(220)
        self._globalSearch.setObjectName("urlText")
        self._globalSearch.textChanged.connect(self._on_global_search)
        row.addWidget(self._globalSearch)

        refreshBtn = QPushButton("Refresh")
        refreshBtn.clicked.connect(self._load)
        row.addWidget(refreshBtn)

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

    def load_session(self, session_id: str, repo) -> None:
        """Switch to showing results from a specific pipeline session."""
        self._session_id = session_id
        self._repo = repo
        self._output_dir = ""
        self._panels.clear()
        while self._mainLayout.count():
            item = self._mainLayout.takeAt(0)
            if item.widget():
                item.widget().setParent(None)
        self._mainLayout.addWidget(self._placeholder)
        self._placeholder.show()
        self._load()

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
        self._loader.start()

    def _on_loaded(self, all_results: dict):
        self._all_results = all_results
        self._rebuild_sidebar()
        total = sum(cr.total_unique for cr in all_results.values())
        source_hint = (
            f"session {self._session_id[:8]}… (MongoDB)"
            if self._session_id
            else self._output_dir
        )
        self._statusLabel.setText(f"{total} unique results  ·  {source_hint}")
        # Auto-select first category with results
        for i in range(self._catList.count()):
            item = self._catList.item(i)
            if item.data(Qt.UserRole + 1) > 0:
                self._catList.setCurrentItem(item)
                break

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
        # Remove current main widget
        while self._mainLayout.count():
            item = self._mainLayout.takeAt(0)
            if item.widget():
                item.widget().setParent(None)

        if cat not in self._panels:
            panel = _CategoryPanel(cat)
            self._panels[cat] = panel

        panel = self._panels[cat]
        cr = self._all_results.get(cat)
        if cr and cr.has_results():
            panel.load(cr)
        else:
            panel.load(CategoryResults(category=cat))

        self._mainLayout.addWidget(panel)
        panel.show()

        # Apply global search to new panel
        q = self._globalSearch.text()
        if q:
            table = panel.current_table()
            if table:
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
            if table:
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

    # ── helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _hline() -> QFrame:
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setObjectName("certDivider")
        return line
