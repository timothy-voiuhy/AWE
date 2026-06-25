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
import re as _re
from pathlib import Path

from bson import ObjectId
from PySide6.QtCore import Qt, QModelIndex, QTimer, QPoint, Signal, QEvent
from PySide6.QtGui import QStandardItem, QStandardItemModel, QColor, QFont, QPainter, QPolygon
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QFrame,
    QPushButton, QLabel, QTreeView, QTabWidget, QTextEdit,
    QProxyStyle, QStyle, QMenu, QToolTip, QDialog, QApplication,
)

from database.scope import ScopeConfig, ScopeEntry
from gui.appearance import load_ui_settings, save_ui_settings
from gui.filterPanel import FilterPanel, _status_color, _file_type
from gui.guiUtilities import (
    SyntaxHighlighter, format_http_body, SearchBar,
    decode_text, DecodeDialog,
    parse_http_headers, set_header_clipboard, HeaderSelectorDialog,
    ResponseRenderView,
)

log = logging.getLogger(__name__)

_DOC_ID_ROLE = Qt.UserRole + 1   # MongoDB _id string on leaf items
_KEY_ROLE    = Qt.UserRole + 2   # stable path key for expansion tracking

# SSE-only and length filters are HTTP-History-specific.
_SITEMAP_SECTIONS = frozenset({"search", "search_scopes", "method", "status", "hide_types"})

_HTTP_METHODS = frozenset({
    "GET", "POST", "PUT", "DELETE", "PATCH",
    "HEAD", "OPTIONS", "CONNECT", "TRACE",
})

# Default hidden types on first launch (no saved settings)
_SITEMAP_DEFAULT_HIDDEN = ["images", "css", "fonts", "media"]


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
    send_to_repeater       = Signal(str)
    send_to_intruder       = Signal(str)
    send_to_decoder        = Signal(str)
    send_to_comparer_left  = Signal(str)
    send_to_comparer_right = Signal(str)
    send_to_jwt            = Signal(str)
    send_to_graphql        = Signal(str)
    sync_requested         = Signal()
    traffic_changed        = Signal()
    scope_modified         = Signal(object)   # emits ScopeConfig after a sitemap scope action

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

        self._tree_initialized = False   # True after first successful load

        self._build_ui()
        self._scope_btn.setChecked(True)
        self._load_scope()
        self._restore_saved_filters()
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

        self._filter_btn = QPushButton("Filters ▾")
        self._filter_btn.setCheckable(True)
        self._filter_btn.setFixedHeight(24)
        self._filter_btn.setStyleSheet(_BTN_SS)
        self._filter_btn.toggled.connect(self._on_filter_toggle)
        tb.addWidget(self._filter_btn)

        self._reset_btn = QPushButton("Reset")
        self._reset_btn.setFixedHeight(24)
        self._reset_btn.setStyleSheet(_BTN_SS)
        self._reset_btn.clicked.connect(self._on_filter_reset)
        self._reset_btn.setVisible(False)
        tb.addWidget(self._reset_btn)

        self._filter_active_lbl = QLabel("")
        self._filter_active_lbl.setStyleSheet(
            "color:#F9E2AF; font-size:9px; background:#2A2A1A;"
            " border:1px solid #45475A; border-radius:3px; padding:0 6px;"
        )
        self._filter_active_lbl.setVisible(False)
        tb.addWidget(self._filter_active_lbl)

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

        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setFixedHeight(1)
        sep.setStyleSheet("background:#313244; border:none;")
        root.addWidget(sep)

        # ── filter panel (collapsed by default) ───────────────────────────────
        self._filter_panel = FilterPanel(sections=_SITEMAP_SECTIONS)
        self._filter_panel.setVisible(False)
        self._filter_panel.changed.connect(self._on_filter_changed)
        root.addWidget(self._filter_panel)

        self._filter_sep = QFrame()
        self._filter_sep.setFrameShape(QFrame.HLine)
        self._filter_sep.setFixedHeight(1)
        self._filter_sep.setStyleSheet("background:#313244; border:none;")
        self._filter_sep.setVisible(False)
        root.addWidget(self._filter_sep)

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
        self._render_view = ResponseRenderView()
        self._tabs.addTab(self._req_view,    "Request")
        self._tabs.addTab(self._resp_view,   "Response")
        self._tabs.addTab(self._render_view, "Render")
        self._req_view.send_to_repeater.connect(self.send_to_repeater)
        self._req_view.send_to_intruder.connect(self.send_to_intruder)
        self._req_view.send_to_decoder.connect(self.send_to_decoder)
        self._req_view.send_to_comparer_left.connect(self.send_to_comparer_left)
        self._req_view.send_to_comparer_right.connect(self.send_to_comparer_right)
        self._req_view.send_to_jwt.connect(self.send_to_jwt)
        self._req_view.send_to_graphql.connect(self.send_to_graphql)
        self._resp_view.send_to_repeater.connect(
            lambda _: self.send_to_repeater.emit(self._req_view.toPlainText()))
        self._resp_view.send_to_intruder.connect(
            lambda _: self.send_to_intruder.emit(self._req_view.toPlainText()))
        self._resp_view.send_to_decoder.connect(self.send_to_decoder)
        self._resp_view.send_to_comparer_left.connect(self.send_to_comparer_left)
        self._resp_view.send_to_comparer_right.connect(self.send_to_comparer_right)
        self._resp_view.send_to_jwt.connect(self.send_to_jwt)
        self._resp_view.send_to_graphql.connect(self.send_to_graphql)
        rr_vb.addWidget(self._tabs)

        self._search_bar = SearchBar(rr)
        self._search_bar.set_editor(self._req_view)
        rr_vb.addWidget(self._search_bar)

        self._current_doc: dict | None = None

        def _on_tab_changed(idx: int) -> None:
            current = self._tabs.widget(idx)
            is_render = current is self._render_view
            self._render_view.on_tab_visibility_changed(is_render)
            self._search_bar.setVisible(not is_render)
            if is_render:
                self._render_current_response()
            else:
                self._search_bar.set_editor(current)

        self._tabs.currentChanged.connect(_on_tab_changed)
        self._req_view.installEventFilter(self)
        self._resp_view.installEventFilter(self)

        splitter.addWidget(rr)
        splitter.setSizes([300, 680])
        root.addWidget(splitter, stretch=1)

    # ── tree ──────────────────────────────────────────────────────────────────

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
                "_id":          {"host": "$host", "method": "$method", "path": "$path"},
                "status_code":  {"$first": "$status_code"},
                "doc_id":       {"$first": "$_id"},
                "req_headers":  {"$first": "$request.headers"},
                "req_body":     {"$first": "$request.body"},
                "resp_headers": {"$first": "$response.headers"},
                "resp_body":    {"$first": "$response.body"},
            }},
        ]

        fp = self._filter_panel
        by_host: dict[str, list[tuple]] = {}
        try:
            for doc in self._col.aggregate(pipeline):
                host        = doc["_id"]["host"]
                method      = doc["_id"]["method"]
                path        = doc["_id"]["path"] or "/"
                status_code = doc["status_code"]
                mini = {"host": host, "method": method,
                        "path": path, "status_code": status_code}
                req  = {"headers": doc.get("req_headers") or {},
                        "body":    doc.get("req_body") or ""}
                resp = {"headers": doc.get("resp_headers") or {}}
                body = doc.get("resp_body") or ""
                if not fp.passes(mini, req, resp, body, False, False, 0):
                    continue
                by_host.setdefault(host, []).append(
                    (method, path, status_code, str(doc["doc_id"]))
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
        self._update_filter_indicator()

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
            self._current_doc = doc
            self._req_view.setText(_fmt_request(doc.get("request", {})))
            self._resp_view.setText(_fmt_response(doc.get("response", {})))
            if self._tabs.currentWidget() is self._render_view:
                self._render_current_response()
            else:
                self._tabs.setCurrentIndex(0)

    def _render_current_response(self) -> None:
        doc = self._current_doc
        if not doc:
            self._render_view.clear()
            return
        resp = doc.get("response") or {}
        body_str = resp.get("body", "") or ""
        body_bytes = body_str.encode("utf-8", errors="replace")
        hdrs = resp.get("headers") or {}
        ct_val = hdrs.get("content-type") or hdrs.get("Content-Type") or ""
        if isinstance(ct_val, list):
            ct_val = ct_val[0] if ct_val else ""
        content_type = str(ct_val).split(";")[0].strip()
        req = doc.get("request") or {}
        base_url = req.get("url") or ""
        self._render_view.render_response(body_bytes, content_type, base_url)

    def _on_tree_context_menu(self, pos: QPoint) -> None:
        index  = self._tree.indexAt(pos)
        item   = self._model.itemFromIndex(index) if index.isValid() else None
        doc_id = item.data(_DOC_ID_ROLE) if item else ""

        menu = QMenu(self)

        # ── expand / collapse ─────────────────────────────────────────────
        expand_act   = menu.addAction("Expand All")
        collapse_act = menu.addAction("Collapse All")
        expand_sub_act = None
        if index.isValid() and item and item.hasChildren():
            menu.addSeparator()
            expand_sub_act = menu.addAction("Expand Subtree")

        # ── delete ────────────────────────────────────────────────────────
        del_entry_act = del_sub_act = None
        if item and index.isValid():
            is_host = item.parent() is None
            menu.addSeparator()
            if doc_id:
                del_entry_act = menu.addAction("Delete Entry")
            del_sub_act = menu.addAction(
                "Delete All for Host" if is_host else "Delete Subtree"
            )

        # ── scope ─────────────────────────────────────────────────────────
        add_scope_act = excl_scope_act = None
        if item and index.isValid() and self._repo is not None:
            menu.addSeparator()
            add_scope_act  = menu.addAction("Add to Scope")
            excl_scope_act = menu.addAction("Exclude from Scope")

        # ── send ──────────────────────────────────────────────────────────
        rep_act = int_act = None
        if doc_id:
            menu.addSeparator()
            rep_act = menu.addAction("Send to Repeater")
            int_act = menu.addAction("Send to Intruder")

        chosen = menu.exec(self._tree.mapToGlobal(pos))
        if chosen is None:
            return

        if chosen is expand_act:
            self._tree.expandAll()
        elif chosen is collapse_act:
            self._tree.collapseAll()
        elif expand_sub_act and chosen is expand_sub_act:
            self._tree.expandRecursively(index)
        elif chosen is del_entry_act:
            self._delete_entry(doc_id)
        elif chosen is del_sub_act:
            self._delete_subtree(item)
        elif chosen is add_scope_act:
            self._modify_scope(item, in_scope=True)
        elif chosen is excl_scope_act:
            self._modify_scope(item, in_scope=False)
        elif doc_id and chosen in (rep_act, int_act):
            doc = self._load_doc(doc_id)
            if doc:
                raw = _fmt_request(doc.get("request", {}))
                if chosen is rep_act:
                    self.send_to_repeater.emit(raw)
                else:
                    self.send_to_intruder.emit(raw)

    # ── tree node helpers ─────────────────────────────────────────────────────

    def _item_ancestry(self, item: QStandardItem) -> tuple[str, list[str]]:
        """Return (host, [path_segments]) for any tree item.

        Method-leaf keys (GET/POST/…) are excluded so the result always
        represents a host + URL-path pair.  The "/" segment is normalised
        to an empty string so path-joining works cleanly.
        """
        segments: list[str] = []
        cur = item
        while True:
            par = cur.parent()
            if par is None:
                host = cur.data(_KEY_ROLE) or ""
                segments.reverse()
                return host, segments
            key = cur.data(_KEY_ROLE) or ""
            if key and key.upper() not in _HTTP_METHODS:
                segments.append("" if key == "/" else key)
            cur = par

    def _delete_entry(self, doc_id: str) -> None:
        """Delete a single traffic document by _id."""
        if not doc_id or self._col is None:
            return
        try:
            self._col.delete_one({"_id": ObjectId(doc_id)})
        except Exception as exc:
            log.warning("Delete entry failed: %s", exc)
        self._refresh_tree()

    def _delete_subtree(self, item: QStandardItem) -> None:
        """Delete all traffic docs matching this node and its URL descendants."""
        if self._col is None:
            return
        host, segs = self._item_ancestry(item)
        if not host:
            return
        try:
            if not segs:
                self._col.delete_many({"host": host})
            else:
                prefix = "/" + "/".join(segs)
                self._col.delete_many({
                    "host": host,
                    "path": {"$regex": "^" + _re.escape(prefix) + r"(/.*)?$"},
                })
        except Exception as exc:
            log.warning("Delete subtree failed: %s", exc)
        self._refresh_tree()

    def _modify_scope(self, item: QStandardItem, in_scope: bool) -> None:
        """Add a scope rule for the selected tree node and broadcast the change."""
        if self._repo is None:
            return
        host, segs = self._item_ancestry(item)
        if not host:
            return
        if segs:
            value      = "https://{}/{}".format(host, "/".join(segs))
            entry_type = "url"
        else:
            value      = host
            entry_type = "domain"
        try:
            cfg = self._repo.get_scope()
        except Exception:
            cfg = ScopeConfig()
        entry = ScopeEntry(value=value, entry_type=entry_type, in_scope=in_scope)
        # avoid exact duplicates
        for e in cfg.entries:
            if (e.value == entry.value
                    and e.entry_type == entry.entry_type
                    and e.in_scope == entry.in_scope):
                return
        cfg.entries.append(entry)
        try:
            self._repo.save_scope(cfg)
        except Exception as exc:
            log.warning("Scope save failed: %s", exc)
            return
        self._scope = cfg
        self.scope_modified.emit(cfg)
        if self._filter_scope:
            self._refresh_tree()

    def eventFilter(self, obj, event) -> bool:
        if (event.type() == QEvent.Type.KeyPress
                and event.modifiers() == Qt.ControlModifier
                and event.key() == Qt.Key_F):
            self._search_bar.set_editor(obj)
            self._search_bar.activate()
            return True
        return super().eventFilter(obj, event)

    def _on_scope_toggle(self, checked: bool) -> None:
        self._filter_scope = checked
        self._scope_btn.setText(f"Filter by Scope: {'ON' if checked else 'OFF'}")
        self._scope_btn.setStyleSheet(_TOGGLE_SS_ON if checked else _TOGGLE_SS_OFF)
        self._refresh_tree()

    def _on_filter_toggle(self, checked: bool) -> None:
        self._filter_panel.setVisible(checked)
        self._filter_sep.setVisible(checked)
        self._filter_btn.setText("Filters ▴" if checked else "Filters ▾")

    def _on_filter_changed(self) -> None:
        self._refresh_tree()
        active = self._filter_panel.is_active()
        self._reset_btn.setVisible(active)
        self._save_filters()

    def _on_filter_reset(self) -> None:
        self._filter_panel.reset()
        self._reset_btn.setVisible(False)
        self._refresh_tree()
        self._save_filters()

    def _update_filter_indicator(self) -> None:
        if self._filter_panel.is_active():
            self._filter_active_lbl.setVisible(True)
        else:
            self._filter_active_lbl.setVisible(False)

    def _save_filters(self) -> None:
        try:
            data = load_ui_settings()
            data["sitemap_filters"] = self._filter_panel.to_dict()
            save_ui_settings(data)
        except Exception:
            pass

    def _restore_saved_filters(self) -> None:
        try:
            data   = load_ui_settings()
            saved  = data.get("sitemap_filters")
            if saved is None:
                # First launch: apply sensible defaults (hide images/css/fonts/media)
                saved = {"hide_types": _SITEMAP_DEFAULT_HIDDEN}
            self._filter_panel.from_dict(saved)
            if self._filter_panel.is_active():
                self._filter_btn.setChecked(True)
                self._reset_btn.setVisible(True)
        except Exception:
            pass

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

def _fmt_body(doc: dict) -> str:
    body = doc.get("body", "")
    if not body:
        return ""
    if doc.get("body_encoding") == "base64":
        import base64 as _b64
        try:
            raw  = _b64.b64decode(body)
            size = len(raw)
        except Exception:
            size = len(body) * 3 // 4
        return f"[Binary content — {size:,} bytes, base64]\n{body}"
    return body


def _fmt_request(req: dict) -> str:
    method  = req.get("method", "")
    url     = req.get("url", "")
    headers = req.get("headers", {})
    lines   = [f"{method} {url}"]
    for k, v in (headers.items() if isinstance(headers, dict) else []):
        for val in ([v] if isinstance(v, str) else v):
            lines.append(f"{k}: {val}")
    body = _fmt_body(req)
    if body:
        lines += ["", body]
    return "\n".join(lines)


def _fmt_response(resp: dict) -> str:
    status  = resp.get("status_code", "")
    reason  = resp.get("reason", "")
    version = resp.get("http_version", "HTTP/1.1")
    headers = resp.get("headers", {})
    lines   = [f"{version} {status} {reason}"]
    for k, v in (headers.items() if isinstance(headers, dict) else []):
        for val in ([v] if isinstance(v, str) else v):
            lines.append(f"{k}: {val}")
    body = _fmt_body(resp)
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
    send_to_repeater       = Signal(str)
    send_to_intruder       = Signal(str)
    send_to_decoder        = Signal(str)
    send_to_comparer_left  = Signal(str)
    send_to_comparer_right = Signal(str)
    send_to_jwt            = Signal(str)
    send_to_graphql        = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setFont(QFont("Cascadia Code", 9))
        self.setStyleSheet(
            "QTextEdit{background:#11111B; color:#CDD6F4; border:none; padding:8px;}"
        )
        self._hl = SyntaxHighlighter(self.document())

    def contextMenuEvent(self, event):
        menu      = self.createStandardContextMenu()
        txt       = self.toPlainText()
        selected  = self.textCursor().selectedText().strip()
        has_text  = bool(txt.strip())
        has_body  = has_text and '\n\n' in txt and bool(txt.split('\n\n', 1)[-1].strip())
        has_sel   = bool(selected)

        menu.addSeparator()
        rep_act = menu.addAction("Send to Repeater")
        rep_act.setEnabled(has_text)
        int_act = menu.addAction("Send to Intruder")
        int_act.setEnabled(has_text)

        dec_page_act = menu.addAction("Send to Decoder")
        dec_page_act.setEnabled(has_text)

        cmp_menu  = menu.addMenu("Send to Comparer")
        cmp_left  = cmp_menu.addAction("Left Pane")
        cmp_right = cmp_menu.addAction("Right Pane")
        cmp_left.setEnabled(has_text)
        cmp_right.setEnabled(has_text)

        jwt_act = menu.addAction("Analyze JWT")
        jwt_act.setEnabled(has_sel and selected.count('.') == 2)

        gql_act = menu.addAction("Send to GraphQL")
        _is_gql = ('"query"' in txt or '"mutation"' in txt
                   or txt.lstrip().startswith(('query ', 'mutation ', 'subscription ', '{')))
        gql_act.setEnabled(has_text and _is_gql)

        menu.addSeparator()
        fmt_menu = menu.addMenu("Format Body")
        fmt_menu.setEnabled(has_body)
        json_act = fmt_menu.addAction("JSON")
        xml_act  = fmt_menu.addAction("XML")
        html_act = fmt_menu.addAction("HTML")
        js_act   = fmt_menu.addAction("JavaScript")

        menu.addSeparator()
        dec_menu = menu.addMenu("Decode Selection")
        dec_menu.setEnabled(has_sel)
        dec_auto = dec_menu.addAction("Auto-detect")
        dec_menu.addSeparator()
        dec_b64  = dec_menu.addAction("Base64")
        dec_url  = dec_menu.addAction("URL")
        dec_html = dec_menu.addAction("HTML Entities")
        dec_hex  = dec_menu.addAction("Hex")
        dec_jwt  = dec_menu.addAction("JWT")
        dec_uni  = dec_menu.addAction("Unicode Escape")

        menu.addSeparator()
        copy_hdrs_menu = menu.addMenu("Copy Headers")
        copy_hdrs_menu.setEnabled(has_text)
        copy_all_act = copy_hdrs_menu.addAction("All Headers")
        copy_sel_act = copy_hdrs_menu.addAction("Select Headers…")
        copy_body_act = menu.addAction("Copy Body")
        copy_body_act.setEnabled(has_body)

        chosen = menu.exec(event.globalPos())
        fmt_map = {json_act: 'json', xml_act: 'xml', html_act: 'html', js_act: 'javascript'}
        dec_map = {dec_auto: 'auto', dec_b64: 'base64', dec_url: 'url',
                   dec_html: 'html', dec_hex: 'hex', dec_jwt: 'jwt', dec_uni: 'unicode'}

        if chosen is rep_act:
            self.send_to_repeater.emit(txt)
        elif chosen is int_act:
            self.send_to_intruder.emit(txt)
        elif chosen is dec_page_act:
            self.send_to_decoder.emit(selected if has_sel else txt)
        elif chosen is cmp_left:
            self.send_to_comparer_left.emit(selected if has_sel else txt)
        elif chosen is cmp_right:
            self.send_to_comparer_right.emit(selected if has_sel else txt)
        elif chosen is jwt_act and has_sel:
            self.send_to_jwt.emit(selected)
        elif chosen is gql_act:
            self.send_to_graphql.emit(txt)
        elif chosen in fmt_map:
            result = format_http_body(txt, fmt_map[chosen])
            if result is not None:
                self.setPlainText(result)
        elif chosen in dec_map and has_sel:
            result, used = decode_text(selected, dec_map[chosen])
            if result is None:
                QToolTip.showText(event.globalPos(), f"Cannot decode as {used}")
            else:
                DecodeDialog(result, used, parent=self.window()).show()
        elif chosen is copy_all_act:
            hdrs = parse_http_headers(txt)
            set_header_clipboard(hdrs)
            QToolTip.showText(event.globalPos(),
                              f"Copied {len(hdrs)} header{'s' if len(hdrs) != 1 else ''}")
        elif chosen is copy_sel_act:
            hdrs = parse_http_headers(txt)
            if not hdrs:
                QToolTip.showText(event.globalPos(), "No headers found")
            else:
                dlg = HeaderSelectorDialog(hdrs, parent=self.window())
                if dlg.exec() == QDialog.DialogCode.Accepted:
                    sel = dlg.selected_headers()
                    if sel:
                        set_header_clipboard(sel)
                        QToolTip.showText(event.globalPos(),
                                          f"Copied {len(sel)} header{'s' if len(sel) != 1 else ''}")
        elif chosen is copy_body_act:
            body = txt.split('\n\n', 1)[-1]
            QApplication.clipboard().setText(body)
            QToolTip.showText(event.globalPos(), "Body copied")
