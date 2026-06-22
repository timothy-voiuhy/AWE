"""
SiteMapPage — Burp-style hierarchical URL tree per target.

Tree structure:
    example.com
    └── api
        ├── v1
        │   ├── users      GET 200
        │   └── auth       POST 401
        └── health         GET 200

One entry per unique (method, path) per host.  The latest status_code for
each pair is shown.  Data comes from MongoDB (awe_proxy_traffic.traffic).
"""
from __future__ import annotations

import logging
from pathlib import Path

from bson import ObjectId
from PySide6.QtCore import Qt, QModelIndex, QTimer, QPoint, Signal
from PySide6.QtGui import QStandardItem, QStandardItemModel, QColor, QFont, QPainter, QPolygon
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QFrame,
    QPushButton, QLabel, QTreeView, QTabWidget, QTextEdit,
    QProxyStyle, QStyle, QMenu,
)

from database.scope import ScopeConfig
from gui.guiUtilities import SyntaxHighlighter

log = logging.getLogger(__name__)

_DOC_ID_ROLE = Qt.UserRole + 1   # MongoDB _id string on leaf items
_KEY_ROLE    = Qt.UserRole + 2   # stable path key for expansion tracking

# ── File-type filter groups ───────────────────────────────────────────────────

_EXT_GROUPS: dict[str, frozenset[str]] = {
    "Images":  frozenset({".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico",
                           ".webp", ".bmp", ".avif", ".tiff"}),
    "CSS":     frozenset({".css", ".scss", ".less", ".sass"}),
    "Scripts": frozenset({".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}),
    "Fonts":   frozenset({".woff", ".woff2", ".ttf", ".eot", ".otf"}),
    "Media":   frozenset({".mp4", ".mp3", ".avi", ".wav", ".ogg", ".flac",
                           ".mkv", ".webm", ".mov"}),
}

_DEFAULT_HIDDEN: frozenset[str] = frozenset({"Images", "CSS", "Fonts", "Media"})


# ── helpers ───────────────────────────────────────────────────────────────────

def _status_color(code) -> str:
    try:
        c = int(code)
    except (TypeError, ValueError):
        return "#6C7086"
    if 200 <= c < 300: return "#A6E3A1"
    if 300 <= c < 400: return "#89B4FA"
    if 400 <= c < 500: return "#F9E2AF"
    if 500 <= c < 600: return "#F38BA8"
    return "#6C7086"


class _PathNode:
    """One segment in the URL path tree."""
    __slots__ = ("children", "entries")

    def __init__(self):
        self.children: dict[str, _PathNode] = {}
        # Each entry: (doc_id_str, method, status_code)
        self.entries: list[tuple[str, str, int]] = []


class _TreeStyle(QProxyStyle):
    """Draws theme-appropriate expand/collapse triangles for the dark tree view."""

    def drawPrimitive(self, element, option, painter, widget=None):
        if element == QStyle.PE_IndicatorBranch:
            has_children = bool(int(option.state) & int(QStyle.State_Children))
            is_open      = bool(int(option.state) & int(QStyle.State_Open))
            if has_children:
                painter.save()
                painter.setRenderHint(QPainter.Antialiasing)
                painter.setPen(Qt.NoPen)
                painter.setBrush(QColor("#6C7086"))
                r  = option.rect
                cx = r.center().x()
                cy = r.center().y()
                if is_open:
                    pts = QPolygon([
                        QPoint(cx - 4, cy - 2),
                        QPoint(cx + 4, cy - 2),
                        QPoint(cx,     cy + 3),
                    ])
                else:
                    pts = QPolygon([
                        QPoint(cx - 2, cy - 4),
                        QPoint(cx - 2, cy + 4),
                        QPoint(cx + 3, cy),
                    ])
                painter.drawPolygon(pts)
                painter.restore()
        else:
            super().drawPrimitive(element, option, painter, widget)


# ── main widget ───────────────────────────────────────────────────────────────

class SiteMapPage(QWidget):
    send_to_repeater = Signal(str)
    sync_requested   = Signal()
    traffic_changed  = Signal()

    def __init__(self, project_dir, target_host, proxy_col,
                 repository=None, parent=None):
        super().__init__(parent)
        self._project_dir  = project_dir
        self._target_host  = target_host
        self._col          = proxy_col   # pymongo Collection or None
        self._repo         = repository
        self._scope        = ScopeConfig()
        self._filter_scope = True
        self._last_count   = -1          # for change detection

        self._show_types: dict[str, bool] = {
            g: (g not in _DEFAULT_HIDDEN) for g in _EXT_GROUPS
        }
        self._type_btns: dict[str, QPushButton] = {}
        self._tree_initialized = False   # True after first successful load

        self._build_ui()
        self._scope_btn.setChecked(True)
        self._load_scope()
        self._refresh_tree()
        self._start_poll_timer()

    # ── public ────────────────────────────────────────────────────────────────

    def on_scope_changed(self, config: ScopeConfig) -> None:
        self._scope = config
        if self._filter_scope:
            self._refresh_tree()

    def refresh(self) -> None:
        self._load_scope()
        self._refresh_tree()

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── row 1: main toolbar ───────────────────────────────────────────────
        tb = QHBoxLayout()
        tb.setContentsMargins(8, 6, 8, 4)
        tb.setSpacing(10)
        title = QLabel("Site Map")
        title.setStyleSheet("color:#CDD6F4; font-weight:bold; font-size:11px;")
        tb.addWidget(title)
        tb.addStretch()

        self._count_lbl = QLabel("0 endpoints")
        self._count_lbl.setStyleSheet("color:#6C7086; font-size:9px;")
        tb.addWidget(self._count_lbl)

        self._scope_btn = QPushButton("Filter by Scope: ON")
        self._scope_btn.setCheckable(True)
        self._scope_btn.setFixedHeight(24)
        self._scope_btn.setStyleSheet(_TOGGLE_SS_ON)
        self._scope_btn.toggled.connect(self._on_scope_toggle)
        tb.addWidget(self._scope_btn)

        ref_btn = QPushButton("Refresh")
        ref_btn.setFixedHeight(24)
        ref_btn.setStyleSheet(_BTN_SS)
        ref_btn.clicked.connect(self.refresh)
        tb.addWidget(ref_btn)

        sync_btn = QPushButton("⇅  Sync to Results")
        sync_btn.setFixedHeight(24)
        sync_btn.setToolTip("Extract subdomains, endpoints and parameters into the results database")
        sync_btn.setStyleSheet(_BTN_SS)
        sync_btn.clicked.connect(self.sync_requested.emit)
        tb.addWidget(sync_btn)
        root.addLayout(tb)

        # ── row 2: file-type filter bar ───────────────────────────────────────
        fb = QHBoxLayout()
        fb.setContentsMargins(8, 0, 8, 5)
        fb.setSpacing(5)

        show_lbl = QLabel("Show:")
        show_lbl.setStyleSheet("color:#6C7086; font-size:9px; margin-right:2px;")
        fb.addWidget(show_lbl)

        for group in _EXT_GROUPS:
            shown = self._show_types[group]
            btn   = QPushButton(group)
            btn.setCheckable(True)
            btn.setChecked(shown)
            btn.setFixedHeight(20)
            btn.setStyleSheet(_TOGGLE_SS_ON if shown else _TOGGLE_SS_OFF)
            btn.toggled.connect(lambda checked, g=group: self._on_type_toggle(g, checked))
            self._type_btns[group] = btn
            fb.addWidget(btn)

        fb.addStretch()
        root.addLayout(fb)

        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setFixedHeight(1)
        sep.setStyleSheet("background:#313244; border:none;")
        root.addWidget(sep)

        # ── splitter — tree left, req/resp right ──────────────────────────────
        splitter = QSplitter(Qt.Horizontal)
        splitter.setChildrenCollapsible(False)
        splitter.setStyleSheet("QSplitter::handle{background:#313244;width:3px;}")

        self._model = QStandardItemModel()
        self._tree  = QTreeView()
        self._tree.setModel(self._model)
        self._tree_style = _TreeStyle(self._tree.style())
        self._tree.setStyle(self._tree_style)
        self._tree.setAnimated(True)
        self._tree.setUniformRowHeights(True)
        self._tree.setEditTriggers(QTreeView.NoEditTriggers)
        self._tree.setHeaderHidden(True)
        self._tree.clicked.connect(self._on_item_clicked)
        self._tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self._tree.customContextMenuRequested.connect(self._on_tree_context_menu)
        self._tree.setIndentation(20)
        self._tree.setStyleSheet(
            "QTreeView{background:#1E1E2E; border:none;}"
            "QTreeView::item{padding:2px 0;}"
            "QTreeView::item:selected{background:#313244; color:#CDD6F4;}"
            "QTreeView::item:hover{background:#181825;}"
            "QTreeView::branch{background:#1E1E2E;}"
        )
        splitter.addWidget(self._tree)

        rr = QWidget()
        rr_vb = QVBoxLayout(rr)
        rr_vb.setContentsMargins(0, 0, 0, 0)
        self._tabs = QTabWidget()
        self._tabs.setStyleSheet(
            "QTabBar::tab{background:#181825;color:#6C7086;padding:4px 12px;border:none;}"
            "QTabBar::tab:selected{background:#313244;color:#CDD6F4;}"
        )
        self._req_view  = _CodeView()
        self._resp_view = _CodeView()
        self._tabs.addTab(self._req_view,  "Request")
        self._tabs.addTab(self._resp_view, "Response")
        rr_vb.addWidget(self._tabs)
        splitter.addWidget(rr)
        splitter.setSizes([300, 680])
        root.addWidget(splitter, stretch=1)

    # ── tree ──────────────────────────────────────────────────────────────────

    def _should_show_path(self, path: str) -> bool:
        ext = Path(path).suffix.lower()
        if not ext:
            return True
        for group, exts in _EXT_GROUPS.items():
            if ext in exts and not self._show_types[group]:
                return False
        return True

    def _refresh_tree(self) -> None:
        # Preserve the user's current tree state before clearing
        expanded_keys = self._save_expansion()
        scroll_pos    = self._tree.verticalScrollBar().value()
        is_first_load = not self._tree_initialized

        self._model.clear()

        if self._col is None:
            self._count_lbl.setText("database unavailable")
            return

        try:
            all_hosts = self._col.distinct("host")
        except Exception as exc:
            log.warning("SiteMap DB query failed: %s", exc)
            self._count_lbl.setText("DB error")
            return

        in_scope = [
            h for h in all_hosts
            if not self._filter_scope or self._scope.matches(h)
        ]
        if not in_scope:
            self._count_lbl.setText("0 endpoints")
            return

        pipeline = [
            {"$match": {"host": {"$in": in_scope}}},
            {"$sort": {"timestamp": -1}},
            {"$group": {
                "_id":         {"host": "$host", "method": "$method", "path": "$path"},
                "status_code": {"$first": "$status_code"},
                "doc_id":      {"$first": "$_id"},
            }},
        ]

        by_host: dict[str, list[tuple]] = {}
        try:
            for doc in self._col.aggregate(pipeline):
                host   = doc["_id"]["host"]
                method = doc["_id"]["method"]
                path   = doc["_id"]["path"] or "/"
                if not self._should_show_path(path):
                    continue
                by_host.setdefault(host, []).append(
                    (method, path, doc["status_code"], str(doc["doc_id"]))
                )
        except Exception as exc:
            log.warning("SiteMap aggregation failed: %s", exc)
            return

        total = 0
        for host in sorted(by_host.keys()):
            entries = by_host[host]

            tree_root = _PathNode()
            for method, path, status, doc_id in entries:
                segments = [s for s in path.split("/") if s] or [""]
                node = tree_root
                for seg in segments:
                    node.children.setdefault(seg, _PathNode())
                    node = node.children[seg]
                node.entries.append((doc_id, method, int(status or 0)))

            host_item = QStandardItem(f"  {host}  ({len(entries)})")
            host_item.setForeground(QColor("#CDD6F4"))
            f = QFont(); f.setBold(True)
            host_item.setFont(f)
            host_item.setData("", _DOC_ID_ROLE)
            host_item.setData(host, _KEY_ROLE)
            host_item.setEditable(False)
            self._model.appendRow(host_item)
            _fill_node(host_item, tree_root)
            total += len(entries)

        self._count_lbl.setText(f"{total} endpoint{'s' if total != 1 else ''}")

        # On first load expand all host nodes; afterwards restore what the user had open
        if is_first_load:
            root = self._model.invisibleRootItem()
            for i in range(root.rowCount()):
                self._tree.expand(self._model.indexFromItem(root.child(i)))
            self._tree_initialized = True
        else:
            self._restore_expansion(expanded_keys)
            self._tree.verticalScrollBar().setValue(scroll_pos)

    # ── expansion save / restore ──────────────────────────────────────────────

    def _save_expansion(self) -> set[tuple[str, ...]]:
        """Return path tuples for every currently expanded item."""
        result: set[tuple[str, ...]] = set()
        root = self._model.invisibleRootItem()
        for i in range(root.rowCount()):
            host_item = root.child(i)
            key = host_item.data(_KEY_ROLE) or ""
            if key and self._tree.isExpanded(self._model.indexFromItem(host_item)):
                result.add((key,))
                self._collect_expanded(host_item, (key,), result)
        return result

    def _collect_expanded(
        self,
        parent: QStandardItem,
        path: tuple[str, ...],
        result: set,
    ) -> None:
        for i in range(parent.rowCount()):
            child     = parent.child(i)
            key       = child.data(_KEY_ROLE) or ""
            child_path = path + (key,)
            if key and self._tree.isExpanded(self._model.indexFromItem(child)):
                result.add(child_path)
                self._collect_expanded(child, child_path, result)

    def _restore_expansion(self, expanded_keys: set[tuple[str, ...]]) -> None:
        root = self._model.invisibleRootItem()
        for i in range(root.rowCount()):
            host_item = root.child(i)
            key = host_item.data(_KEY_ROLE) or ""
            if (key,) in expanded_keys:
                self._tree.expand(self._model.indexFromItem(host_item))
                self._restore_children(host_item, (key,), expanded_keys)

    def _restore_children(
        self,
        parent: QStandardItem,
        path: tuple[str, ...],
        expanded_keys: set,
    ) -> None:
        for i in range(parent.rowCount()):
            child      = parent.child(i)
            key        = child.data(_KEY_ROLE) or ""
            child_path = path + (key,)
            if child_path in expanded_keys:
                self._tree.expand(self._model.indexFromItem(child))
                self._restore_children(child, child_path, expanded_keys)

    # ── interactions ──────────────────────────────────────────────────────────

    def _load_doc(self, doc_id: str) -> dict | None:
        if not doc_id or self._col is None:
            return None
        try:
            return self._col.find_one({"_id": ObjectId(doc_id)})
        except Exception as exc:
            log.warning("Failed to load doc %s: %s", doc_id, exc)
            return None

    def _on_item_clicked(self, index: QModelIndex) -> None:
        item   = self._model.itemFromIndex(index)
        doc_id = item.data(_DOC_ID_ROLE) if item else ""
        if not doc_id:
            return
        doc = self._load_doc(doc_id)
        if doc:
            self._req_view.setText(_fmt_request(doc.get("request", {})))
            self._resp_view.setText(_fmt_response(doc.get("response", {})))
            self._tabs.setCurrentIndex(0)

    def _on_tree_context_menu(self, pos: QPoint) -> None:
        index  = self._tree.indexAt(pos)
        if not index.isValid():
            return
        item   = self._model.itemFromIndex(index)
        doc_id = item.data(_DOC_ID_ROLE) if item else ""
        if not doc_id:
            return
        menu   = QMenu(self)
        action = menu.addAction("Send to Repeater")
        chosen = menu.exec(self._tree.mapToGlobal(pos))
        if chosen is action:
            doc = self._load_doc(doc_id)
            if doc:
                self.send_to_repeater.emit(_fmt_request(doc.get("request", {})))

    def _on_scope_toggle(self, checked: bool) -> None:
        self._filter_scope = checked
        self._scope_btn.setText(f"Filter by Scope: {'ON' if checked else 'OFF'}")
        self._scope_btn.setStyleSheet(_TOGGLE_SS_ON if checked else _TOGGLE_SS_OFF)
        self._refresh_tree()

    def _on_type_toggle(self, group: str, checked: bool) -> None:
        self._show_types[group] = checked
        self._type_btns[group].setStyleSheet(_TOGGLE_SS_ON if checked else _TOGGLE_SS_OFF)
        self._refresh_tree()

    def _load_scope(self) -> None:
        if self._repo:
            try:
                self._scope = self._repo.get_scope()
            except Exception:
                pass

    # ── poll timer ────────────────────────────────────────────────────────────

    def _start_poll_timer(self) -> None:
        self._poll_timer = QTimer(self)
        self._poll_timer.setInterval(2000)
        self._poll_timer.timeout.connect(self._check_new_traffic)
        self._poll_timer.start()

    def _check_new_traffic(self) -> None:
        if self._col is None:
            return
        try:
            count = self._col.estimated_document_count()
        except Exception:
            return
        if count != self._last_count:
            self._last_count = count
            self._refresh_tree()
            self.traffic_changed.emit()


# ── tree helpers ──────────────────────────────────────────────────────────────

def _fill_node(parent: QStandardItem, node: _PathNode) -> None:
    for seg in sorted(node.children.keys()):
        child   = node.children[seg]
        display = seg if seg else "/"

        if not child.entries:
            item = QStandardItem(f"  {display}")
            item.setForeground(QColor("#6C7086"))
            item.setData("", _DOC_ID_ROLE)
        elif len(child.entries) == 1:
            doc_id, method, status = child.entries[0]
            item = QStandardItem(f"  {display}   {method}  {status}")
            item.setForeground(QColor(_status_color(status)))
            item.setData(doc_id, _DOC_ID_ROLE)
        else:
            item = QStandardItem(f"  {display}")
            item.setForeground(QColor("#CDD6F4"))
            item.setData("", _DOC_ID_ROLE)
            for doc_id, method, status in sorted(child.entries, key=lambda e: e[1]):
                mi = QStandardItem(f"    {method}  {status}")
                mi.setForeground(QColor(_status_color(status)))
                mi.setData(doc_id, _DOC_ID_ROLE)
                mi.setData(method, _KEY_ROLE)   # method as leaf key
                mi.setEditable(False)
                item.appendRow(mi)

        item.setData(display, _KEY_ROLE)   # path segment as node key
        item.setEditable(False)
        parent.appendRow(item)

        if child.children:
            _fill_node(item, child)


# ── formatting helpers ────────────────────────────────────────────────────────

def _fmt_request(req: dict) -> str:
    method  = req.get("method", "")
    url     = req.get("url", "")
    headers = req.get("headers", {})
    body    = req.get("body", "")
    lines   = [f"{method} {url}"]
    for k, v in (headers.items() if isinstance(headers, dict) else []):
        for val in ([v] if isinstance(v, str) else v):
            lines.append(f"{k}: {val}")
    if body:
        lines += ["", body]
    return "\n".join(lines)


def _fmt_response(resp: dict) -> str:
    status  = resp.get("status_code", "")
    reason  = resp.get("reason", "")
    version = resp.get("http_version", "HTTP/1.1")
    headers = resp.get("headers", {})
    body    = resp.get("body", "")
    lines   = [f"{version} {status} {reason}"]
    for k, v in (headers.items() if isinstance(headers, dict) else []):
        for val in ([v] if isinstance(v, str) else v):
            lines.append(f"{k}: {val}")
    if body:
        lines += ["", body]
    return "\n".join(lines)


# ── shared style constants ────────────────────────────────────────────────────

_TOGGLE_SS_ON = (
    "QPushButton{background:#1E3A2F;color:#A6E3A1;border:1px solid #A6E3A1;"
    "border-radius:4px;padding:0 10px;font-size:9px;}"
    "QPushButton:hover{background:#2A4A3F;}"
)
_TOGGLE_SS_OFF = (
    "QPushButton{background:#313244;color:#6C7086;border:1px solid #45475A;"
    "border-radius:4px;padding:0 10px;font-size:9px;}"
    "QPushButton:hover{background:#45475A;color:#CDD6F4;}"
)
_BTN_SS = (
    "QPushButton{background:#313244;color:#6C7086;border:1px solid #45475A;"
    "border-radius:4px;padding:0 10px;font-size:9px;}"
    "QPushButton:hover{background:#45475A;color:#CDD6F4;}"
)


# ── code viewer ───────────────────────────────────────────────────────────────

class _CodeView(QTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setFont(QFont("Cascadia Code", 9))
        self.setStyleSheet(
            "QTextEdit{background:#11111B; color:#CDD6F4; border:none; padding:8px;}"
        )
        self._hl = SyntaxHighlighter(self.document())
