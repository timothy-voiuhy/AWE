import logging
import math
from collections import defaultdict

from PySide6.QtCore import Qt, QRectF, QTimer, Signal
from PySide6.QtGui import QPainter, QPen, QColor
from PySide6.QtWidgets import QGraphicsItem, QGraphicsScene

from .nodeItem import NodeItem
from ._edge_item import EdgeItem, _LaneDecorationItem
from ._models import GraphData, GraphNode
from ._constants import (
    _HIDDEN_BY_DEFAULT, _CHILD_EDGE_KINDS, _LANE_COLUMNS,
    _LANE_NODE_GAP, _LANE_ROW_MIN_H, _LANE_ROW_GAP, _LANE_HEADER_H, _LANE_PAD_TOP,
)

logger = logging.getLogger(__name__)


# ── Scene ─────────────────────────────────────────────────────────────────────

class NetworkGraphScene(QGraphicsScene):
    nodeClicked      = Signal(object)          # GraphNode
    addDataRequested = Signal(str, object)     # action_key, GraphNode | None
    focusChanged     = Signal(bool)            # True = focused, False = normal

    def __init__(self, project_dir: str = "", target: str = "", parent=None):
        super().__init__(parent)
        self._node_items:    dict[str, NodeItem]            = {}
        self._edge_items:    list[EdgeItem]                 = []
        self._pos_cache:     dict[str, tuple[float, float]] = {}
        self._project_dir:   str = project_dir
        self._target:        str = target
        self._expanded_nodes: set[str] = set()   # nodes whose hidden children are shown
        self._focused_id:    str | None = None    # node being focused (None = show all)
        self._search_query:  str = ""             # active search (empty = inactive)
        self._lane_deco_items:      list[_LaneDecorationItem] = []
        self._lane_virtual_items:   list = []           # cloned NodeItem/EdgeItem per row
        self._lane_hidden_items:    list = []           # real items hidden while lane is active
        self._lane_hidden_node_ids: set[str] = set()   # IDs of hidden real nodes
        self._lane_row_nodes:       list[set[str]] = [] # per-row set of all node IDs

        # Debounce timer: write positions to DB 1.5 s after the last drag ends
        self._save_timer = QTimer(self)
        self._save_timer.setSingleShot(True)
        self._save_timer.setInterval(1500)
        self._save_timer.timeout.connect(self._flush_positions)

        # Pre-populate cache from DB so build() can apply saved positions immediately
        if project_dir and target:
            self._load_positions()

    # ── Public ────────────────────────────────────────────────────────────────

    def build(self, data: GraphData) -> None:
        """Full rebuild. Hierarchy layout for visible nodes; child layout for
        hidden-by-default nodes; cached positions override both."""
        self.clear()
        self._node_items.clear()
        self._edge_items.clear()
        self._expanded_nodes.clear()
        self._focused_id = None
        self._lane_deco_items      = []
        self._lane_virtual_items   = []
        self._lane_hidden_items    = []
        self._lane_hidden_node_ids = set()
        self._lane_row_nodes       = []

        if not data.nodes:
            return

        self._hierarchy_layout(data)   # positions visible-kind nodes
        self._child_layout(data)       # positions endpoint/param relative to parents
        for node in data.nodes:        # cached positions win
            if node.id in self._pos_cache:
                node.x, node.y = self._pos_cache[node.id]

        self._bulk_add(data)
        self._refresh_visibility()

    def merge(self, data: GraphData) -> None:
        """Incremental refresh: add new nodes/edges, remove stale ones.
        All existing node positions are left exactly where they are."""
        new_ids  = {n.id for n in data.nodes}
        new_ekeys: set[tuple] = set()
        for e in data.edges:
            new_ekeys.add((e.source_id, e.target_id, e.kind))

        views = self.views()
        for v in views:
            v.setUpdatesEnabled(False)
        try:
            # ── Remove stale nodes ────────────────────────────────────────────
            stale = [nid for nid in list(self._node_items) if nid not in new_ids]
            for nid in stale:
                self.removeItem(self._node_items.pop(nid))

            # ── Remove stale edges ────────────────────────────────────────────
            live_edges = []
            for ei in self._edge_items:
                ek = (ei._src.node().id, ei._tgt.node().id, ei._kind)
                if ek in new_ekeys and ei._src.node().id not in stale and ei._tgt.node().id not in stale:
                    live_edges.append(ei)
                else:
                    self.removeItem(ei)
            self._edge_items = live_edges

            # ── Position genuinely new nodes ──────────────────────────────────
            truly_new = [n for n in data.nodes if n.id not in self._node_items]
            if truly_new:
                # Run hierarchy on the full dataset to get sensible positions
                self._hierarchy_layout(data)
                # Override existing nodes' layout coords with their live positions
                for nid, item in self._node_items.items():
                    node = next((n for n in data.nodes if n.id == nid), None)
                    if node:
                        node.x, node.y = item.x(), item.y()
                # Position new hidden-by-default nodes relative to their parents
                self._child_layout(data, {n.id for n in truly_new})
                # Apply cache to new nodes (handles re-added nodes the user moved before)
                for node in truly_new:
                    if node.id in self._pos_cache:
                        node.x, node.y = self._pos_cache[node.id]
                for node in truly_new:
                    item = NodeItem(node)
                    self.addItem(item)
                    self._node_items[node.id] = item

            # ── Add new edges ─────────────────────────────────────────────────
            live_ekeys = {(ei._src.node().id, ei._tgt.node().id, ei._kind)
                          for ei in self._edge_items}
            nmap = self._node_items
            for edge in data.edges:
                ek = (edge.source_id, edge.target_id, edge.kind)
                if ek not in live_ekeys:
                    si, ti = nmap.get(edge.source_id), nmap.get(edge.target_id)
                    if si and ti:
                        ei = EdgeItem(si, ti, edge.kind)
                        self.addItem(ei)
                        self._edge_items.append(ei)
                        live_ekeys.add(ek)
        finally:
            for v in views:
                v.setUpdatesEnabled(True)
        self._refresh_visibility()

    def reset_layout(self, data: GraphData) -> None:
        """Wipe position cache, persist the wipe to DB, then do a clean rebuild."""
        self._save_timer.stop()
        self._pos_cache.clear()
        self._expanded_nodes.clear()
        self._focused_id = None
        self._flush_positions()
        self._clear_lane_decorations()
        self.build(data)
        self.focusChanged.emit(False)

    # ── Visibility management ─────────────────────────────────────────────────

    def _refresh_visibility(self) -> None:
        """Recompute visibility for every node and edge from scratch.

        Rules (applied in order):
          1. hidden-by-default: endpoint/param only visible when parent expanded.
          2. focus: if _focused_id is set, only nodes in the focused row(s) are
             visible (lane mode) or 1-hop neighbours (free-graph mode).
          3. lane suppression: real nodes replaced by per-row clones stay hidden.
          4. virtual lane items: shown/hidden to match the focus set.
        """
        parent_of: dict[str, str] = {}
        for ei in self._edge_items:
            if ei._kind in _CHILD_EDGE_KINDS:
                parent_of[ei._tgt.node().id] = ei._src.node().id

        # ── Resolve focus set ─────────────────────────────────────────────────
        focus_ids: set[str] | None = None
        fid = self._focused_id
        if fid:
            if self._lane_row_nodes:
                # Lane mode: show every row that contains the focused node ID.
                # _lane_row_nodes entries hold both structural real IDs and
                # virtual clone IDs (plus the real IDs of cloned nodes), so
                # focus_node() works whether called with a real or virtual ID.
                focused_rows = [rs for rs in self._lane_row_nodes if fid in rs]
                if focused_rows:
                    focus_ids = set()
                    for rs in focused_rows:
                        focus_ids.update(rs)
                else:
                    # Overflow / untracked node: fall back to 1-hop
                    focus_ids = (self._neighbor_ids(fid)
                                 if fid in self._node_items else {fid})
            else:
                # Free-graph mode: standard 1-hop neighbourhood
                focus_ids = (self._neighbor_ids(fid)
                             if fid in self._node_items else None)

        # ── Real nodes ────────────────────────────────────────────────────────
        for nid, item in self._node_items.items():
            kind = item.node().kind
            if kind in _HIDDEN_BY_DEFAULT:
                base_vis = parent_of.get(nid) in self._expanded_nodes
            else:
                base_vis = True
            visible = base_vis if focus_ids is None else (nid in focus_ids)
            # Lane suppression always wins — these nodes are replaced by clones
            if nid in self._lane_hidden_node_ids:
                visible = False
            item.setVisible(visible)

        # ── Real edges ────────────────────────────────────────────────────────
        for ei in self._edge_items:
            s = self._node_items.get(ei._src.node().id)
            t = self._node_items.get(ei._tgt.node().id)
            vis = (s is not None and s.isVisible() and
                   t is not None and t.isVisible())
            if (ei._src.node().id in self._lane_hidden_node_ids or
                    ei._tgt.node().id in self._lane_hidden_node_ids):
                vis = False
            ei.setVisible(vis)

        # ── Virtual lane items ────────────────────────────────────────────────
        for item in self._lane_virtual_items:
            if isinstance(item, NodeItem):
                if focus_ids is None:
                    item.setVisible(True)
                else:
                    nid = item.node().id
                    rid = item.node().data.get("_real_id", nid)
                    item.setVisible(nid in focus_ids or rid in focus_ids)
            elif isinstance(item, EdgeItem):
                item.setVisible(item._src.isVisible() and item._tgt.isVisible())

        self.update()

    def _neighbor_ids(self, node_id: str) -> set[str]:
        """Return node_id + all nodes directly connected to it by any edge."""
        ids: set[str] = {node_id}
        for ei in self._edge_items:
            if ei._src.node().id == node_id:
                ids.add(ei._tgt.node().id)
            elif ei._tgt.node().id == node_id:
                ids.add(ei._src.node().id)
        return ids

    def focus_node(self, node_id: str) -> None:
        """Show only the given node and its 1-hop neighbours. Hides everything else."""
        self._focused_id = node_id
        self._refresh_visibility()
        self.focusChanged.emit(True)

    def unfocus(self) -> None:
        """Restore normal visibility (hidden-by-default rule only)."""
        self._focused_id = None
        self._refresh_visibility()
        self.focusChanged.emit(False)

    # ── Graph search ──────────────────────────────────────────────────────────

    def set_search(self, query: str) -> None:
        """Highlight nodes matching query; dim everything else.
        Empty query restores normal visibility."""
        self._search_query = query.strip().lower()
        if not self._search_query:
            for item in self._node_items.values():
                item._search_match = None
                item.update()
            self._refresh_visibility()
            return
        # Search mode: override visibility — show ALL nodes, apply opacity
        for nid, item in self._node_items.items():
            match = self._node_matches(item.node(), self._search_query)
            item._search_match = match
            item.setVisible(True)
            item.setOpacity(1.0 if match else 0.08)
            item.update()
        for ei in self._edge_items:
            sm = self._node_items.get(ei._src.node().id)
            tm = self._node_items.get(ei._tgt.node().id)
            ei.setVisible(
                bool(sm and sm._search_match) and bool(tm and tm._search_match)
            )
        self.update()

    @staticmethod
    def _node_matches(node: "GraphNode", q: str) -> bool:
        if q in node.label.lower():
            return True
        for v in node.data.values():
            if isinstance(v, str) and q in v.lower():
                return True
            if isinstance(v, list):
                for item in v:
                    if isinstance(item, str) and q in item.lower():
                        return True
        return False

    def toggle_children(self, node_id: str) -> bool:
        """Toggle visibility of hidden-by-default children of node_id.

        The node_id is the PARENT (subdomain → endpoints, endpoint → params).
        Returns True if children are now expanded, False if collapsed.
        """
        if node_id in self._expanded_nodes:
            self._expanded_nodes.discard(node_id)
            # Collapse any endpoint children that were themselves expanded
            for ei in self._edge_items:
                if ei._src.node().id == node_id and ei._kind in _CHILD_EDGE_KINDS:
                    self._expanded_nodes.discard(ei._tgt.node().id)
            self._refresh_visibility()
            return False
        else:
            self._expanded_nodes.add(node_id)
            self._refresh_visibility()
            return True

    # ── Position persistence ──────────────────────────────────────────────────

    def _load_positions(self) -> None:
        try:
            from database.mongo import load_graph_positions
            saved = load_graph_positions(self._project_dir, self._target)
            self._pos_cache.update(saved)
        except Exception as exc:
            logger.debug("Could not load graph positions: %s", exc)

    def _flush_positions(self) -> None:
        if not (self._project_dir and self._target):
            return
        try:
            from database.mongo import save_graph_positions
            save_graph_positions(
                self._project_dir, self._target, dict(self._pos_cache)
            )
        except Exception as exc:
            logger.debug("Could not save graph positions: %s", exc)

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _bulk_add(self, data: GraphData) -> None:
        """Add all nodes and edges with a single repaint at the end."""
        views = self.views()
        for v in views:
            v.setUpdatesEnabled(False)
        try:
            for node in data.nodes:
                item = NodeItem(node)
                self.addItem(item)
                self._node_items[node.id] = item

            nmap = self._node_items
            for edge in data.edges:
                si, ti = nmap.get(edge.source_id), nmap.get(edge.target_id)
                if si and ti:
                    ei = EdgeItem(si, ti, edge.kind)
                    self.addItem(ei)
                    self._edge_items.append(ei)
        finally:
            for v in views:
                v.setUpdatesEnabled(True)
        self.update()

    # ── Layouts ───────────────────────────────────────────────────────────────

    def _child_layout(
        self,
        data: GraphData,
        only_ids: set[str] | None = None,
    ) -> None:
        """Position hidden-by-default nodes (endpoints, params) relative to
        their parents. When only_ids is given, only positions nodes in that set."""
        nmap = {n.id: n for n in data.nodes}
        from collections import defaultdict
        ep_kids:  dict[str, list[str]] = defaultdict(list)  # subdomain → [endpoint]
        pm_kids:  dict[str, list[str]] = defaultdict(list)  # endpoint  → [param]
        for e in data.edges:
            if e.kind == "has_endpoint":
                ep_kids[e.source_id].append(e.target_id)
            elif e.kind == "has_param":
                pm_kids[e.source_id].append(e.target_id)

        X_EP, Y_EP = 200, 26    # endpoint offset from parent
        X_PM, Y_PM = 170, 18    # param offset from endpoint

        for parent_id, ep_ids in ep_kids.items():
            parent = nmap.get(parent_id)
            if not parent:
                continue
            n = len(ep_ids)
            for i, ep_id in enumerate(ep_ids):
                if only_ids and ep_id not in only_ids:
                    continue
                ep = nmap.get(ep_id)
                if not ep or ep_id in self._pos_cache:
                    continue
                ep.x = parent.x + X_EP
                ep.y = parent.y + (i - n / 2.0) * Y_EP

                param_ids = pm_kids.get(ep_id, [])
                m = len(param_ids)
                for j, pm_id in enumerate(param_ids):
                    if only_ids and pm_id not in only_ids:
                        continue
                    pm = nmap.get(pm_id)
                    if not pm or pm_id in self._pos_cache:
                        continue
                    pm.x = ep.x + X_PM
                    pm.y = ep.y + (j - m / 2.0) * Y_PM

    def _hierarchy_layout(self, data: GraphData):
        # Only layout visible-kind nodes (skip hidden-by-default kinds so they
        # don't affect spacing of the main graph)
        nmap = {n.id: n for n in data.nodes
                if n.kind not in _HIDDEN_BY_DEFAULT}
        children: dict[str, list[str]] = {n.id: [] for n in data.nodes
                                          if n.id in nmap}
        for e in data.edges:
            if e.source_id in children and e.target_id in nmap:
                children[e.source_id].append(e.target_id)

        targets = [n for n in data.nodes if n.kind == "target"]
        if not targets:
            return

        visited: set[str] = set()
        levels: list[list[str]] = [[targets[0].id]]
        visited.add(targets[0].id)

        while True:
            next_lvl = []
            for nid in levels[-1]:
                for c in children.get(nid, []):
                    if c not in visited:
                        visited.add(c)
                        next_lvl.append(c)
            if not next_lvl:
                break
            levels.append(next_lvl)

        x_gap, y_gap = 170, 80
        for lvl_i, level in enumerate(levels):
            n = len(level)
            for i, nid in enumerate(level):
                node = nmap[nid]
                node.x = lvl_i * x_gap
                node.y = (i - n / 2.0) * y_gap

    # ── Lane layout ───────────────────────────────────────────────────────────

    def _clear_lane_decorations(self) -> None:
        # Remove decoration chrome
        for item in self._lane_deco_items:
            self.removeItem(item)
        self._lane_deco_items = []
        for item in self._lane_virtual_items:
            self.removeItem(item)
        self._lane_virtual_items   = []
        for item in self._lane_hidden_items:
            item.setVisible(True)
        self._lane_hidden_items    = []
        self._lane_hidden_node_ids = set()
        self._lane_row_nodes       = []

    def lane_layout(self, data: GraphData) -> None:
        """Tabular lane layout with strict per-row node isolation.

        Structural nodes (target / subdomain / cname / ip / port) may be shared
        across rows (positioned at the centroid of all their rows).
        Tech/CDN and findings nodes are CLONED per row — every row gets its
        own independent NodeItem so no fan-of-edges ever appears.

        Column indices (col_cxs):
          0 target  1 subdomain  2 cname  3 ip  4 port
          5 tech/cdn  6 origin  7 endpoint  8 param  9 findings
        """
        self._clear_lane_decorations()

        nmap = {n.id: n for n in data.nodes if n.kind not in _HIDDEN_BY_DEFAULT}
        # Full map including hidden-by-default kinds (needed for endpoint/param columns)
        all_nmap = {n.id: n for n in data.nodes}

        children: dict[str, list[tuple[str, str]]] = {}
        for e in data.edges:
            if e.source_id in nmap and e.target_id in nmap:
                children.setdefault(e.source_id, []).append((e.target_id, e.kind))

        all_children: dict[str, list[tuple[str, str]]] = {}
        for e in data.edges:
            if e.source_id in all_nmap and e.target_id in all_nmap:
                all_children.setdefault(e.source_id, []).append((e.target_id, e.kind))

        targets = [n for n in data.nodes if n.kind == "target"]
        if not targets:
            return
        target = targets[0]

        sub_ids_all = [c for c, k in children.get(target.id, []) if k == "has_subdomain"]
        osint_ids   = [c for c, k in children.get(target.id, []) if k == "is_osint"]

        def _kids(nid: str, *kinds) -> list[str]:
            seen: set[str] = set()
            result = []
            for c, k in children.get(nid, []):
                if k in kinds and c in nmap and c not in seen:
                    seen.add(c)
                    result.append(c)
            return result

        def _all_kids(nid: str, *kinds) -> list[str]:
            """Like _kids but includes hidden-by-default node kinds (endpoint/param)."""
            return [c for c, k in all_children.get(nid, []) if k in kinds]

        def _cname_chain(start_id: str) -> list[str]:
            """Follow has_cname edges and return all CNAME node IDs in chain order."""
            chain, cur, seen = [], start_id, set()
            while True:
                nexts = [c for c, k in children.get(cur, [])
                         if k == "has_cname" and c not in seen]
                if not nexts:
                    break
                cn = nexts[0]
                seen.add(cn)
                chain.append(cn)
                cur = cn
            return chain

        # ── Build chain rows ──────────────────────────────────────────────────
        chain_rows: list[dict] = []

        for sub_idx, sub_id in enumerate(sub_ids_all):
            if sub_id not in nmap:
                continue
            cdn_ids   = _kids(sub_id, "proxied_by", "routes_through")
            vuln_ids  = _kids(sub_id, "has_vuln")
            note_ids  = _kids(sub_id, "linked_to", "annotates")
            extra_ids = vuln_ids + note_ids
            sub_osint = osint_ids if sub_idx == 0 else []
            cname_ids = _cname_chain(sub_id)
            ip_ids    = _kids(sub_id, "resolves_to")
            dir_ports = _kids(sub_id, "has_port")
            # Endpoints and params: only shown when user has explicitly expanded this sub
            sub_endpoints = (_all_kids(sub_id, "has_endpoint")
                             if sub_id in self._expanded_nodes else [])
            sub_params = []
            for ep_id in sub_endpoints:
                sub_params.extend(_all_kids(ep_id, "has_param"))

            def _row(ip_id, port_id, techs, first):
                full_techs = list(techs) + (cdn_ids if first else [])
                # collect origin-server IPs from every CDN/RP node in this row
                origins = []
                for tid in full_techs:
                    origins.extend(_kids(tid, "origin_of"))
                chain_rows.append({
                    "sub":       sub_id,
                    "cnames":    cname_ids,   # structural — same list for every row of this sub
                    "ip":        ip_id,
                    "port":      port_id,
                    "techs":     full_techs,
                    "origins":   origins,
                    "endpoints": sub_endpoints if first else [],
                    "params":    sub_params    if first else [],
                    "finds":     (extra_ids + sub_osint) if first else [],
                })

            if ip_ids:
                for ii, ip_id in enumerate(ip_ids):
                    port_ids = _kids(ip_id, "has_port")
                    if port_ids:
                        for pi, port_id in enumerate(port_ids):
                            _row(ip_id, port_id, _kids(port_id, "uses_tech"),
                                 ii == 0 and pi == 0)
                    else:
                        _row(ip_id, None, [], ii == 0)
            elif dir_ports:
                for pi, port_id in enumerate(dir_ports):
                    _row(None, port_id, _kids(port_id, "uses_tech"), pi == 0)
            else:
                _row(None, None, [], True)

        if not chain_rows and osint_ids:
            chain_rows.append({"sub": None, "cnames": [], "ip": None, "port": None,
                               "techs": [], "origins": [], "endpoints": [],
                               "params": [], "finds": osint_ids})
        if not chain_rows:
            item = self._node_items.get(target.id)
            if item:
                item.setPos(0, 0)
            target.x = target.y = 0.0
            return

        # ── Column geometry ───────────────────────────────────────────────────
        col_widths = [c[2] for c in _LANE_COLUMNS]
        col_labels = [c[1] for c in _LANE_COLUMNS]
        col_xs: list[float] = []
        cx = 0.0
        for w in col_widths:
            col_xs.append(cx); cx += w
        total_w = cx
        col_cxs = [col_xs[i] + col_widths[i] / 2.0 for i in range(len(col_widths))]

        # ── Row heights / Y positions ─────────────────────────────────────────
        header_y = float(-(_LANE_HEADER_H + _LANE_PAD_TOP))
        y = 0.0
        row_ys: list[float] = []
        row_hs: list[float] = []
        for row in chain_rows:
            max_nodes = max(1, len(row["cnames"]), len(row["techs"]), len(row["origins"]),
                            len(row["endpoints"]), len(row["params"]), len(row["finds"]))
            h = float(max(max_nodes * _LANE_NODE_GAP, _LANE_ROW_MIN_H))
            row_ys.append(y); row_hs.append(h)
            y += h + _LANE_ROW_GAP
        row_cys = [row_ys[i] + row_hs[i] / 2.0 for i in range(len(chain_rows))]

        sub_rows:   dict[str, list[int]] = {}
        cname_rows: dict[str, list[int]] = {}
        ip_rows:    dict[str, list[int]] = {}
        for i, row in enumerate(chain_rows):
            if row["sub"]:
                sub_rows.setdefault(row["sub"], []).append(i)
            for cn in row["cnames"]:
                cname_rows.setdefault(cn, []).append(i)
            if row["ip"]:
                ip_rows.setdefault(row["ip"], []).append(i)

        # ── Position structural nodes (shared across rows) ────────────────────
        placed: set[str] = set()

        def _place(node_id: str, px: float, py: float) -> None:
            n = nmap.get(node_id)
            if n is None:
                return
            n.x, n.y = px, py
            item = self._node_items.get(node_id)
            if item:
                item.setPos(px, py)
            placed.add(node_id)

        def _mean_cy(indices: list[int]) -> float:
            cys = [row_cys[i] for i in indices]
            return (min(cys) + max(cys)) / 2.0

        _place(target.id, col_cxs[0], _mean_cy(list(range(len(chain_rows)))))

        for i, row in enumerate(chain_rows):
            cy = row_cys[i]
            if row["sub"] and row["sub"] not in placed:
                _place(row["sub"], col_cxs[1], _mean_cy(sub_rows[row["sub"]]))
            # CNAME chain — col 2, stacked, placed once per node at centroid of sub's rows
            n_cn = len(row["cnames"])
            for j, cn in enumerate(row["cnames"]):
                if cn not in placed:
                    off = (j - (n_cn - 1) / 2.0) * _LANE_NODE_GAP
                    _place(cn, col_cxs[2], _mean_cy(cname_rows[cn]) + off)
            if row["ip"] and row["ip"] not in placed:
                _place(row["ip"], col_cxs[3], _mean_cy(ip_rows[row["ip"]]))
            if row["port"] and row["port"] not in placed:
                _place(row["port"], col_cxs[4], cy)

        # ── Per-row virtual clones for tech/CDN and findings columns ──────────
        # Every row gets its own independent NodeItem so nodes are NEVER shared.
        # Real tech/finds nodes are hidden; their original edges are suppressed.
        lane_col_real_ids: set[str] = set()   # real IDs replaced by virtuals
        virt_count = [0]

        def _clone(real_id: str, px: float, py: float,
                   parent_item, edge_kind: str):
            """Spawn a virtual clone NodeItem + connecting EdgeItem for one row.
            Returns the created NodeItem so callers can chain it as a parent."""
            real_n = nmap.get(real_id) or all_nmap.get(real_id)
            if real_n is None:
                return None
            lane_col_real_ids.add(real_id)
            virt_count[0] += 1
            virt_id = f"{real_id}:__lv__{virt_count[0]}"
            virt_n  = GraphNode(
                virt_id, real_n.kind, real_n.label,
                {**real_n.data, "_real_id": real_id},
                px, py,
            )
            virt_item = NodeItem(virt_n)
            virt_item.setFlag(QGraphicsItem.ItemIsMovable, False)
            virt_item.setFlag(QGraphicsItem.ItemSendsGeometryChanges, False)
            virt_item.setPos(px, py)
            self.addItem(virt_item)
            self._lane_virtual_items.append(virt_item)
            if parent_item is not None:
                ve = EdgeItem(parent_item, virt_item, edge_kind)
                self.addItem(ve)
                self._lane_virtual_items.append(ve)
            return virt_item

        self._lane_row_nodes = []

        for i, row in enumerate(chain_rows):
            cy = row_cys[i]
            parent_id   = row["port"] or row["ip"] or row["sub"]
            parent_item = self._node_items.get(parent_id) if parent_id else None

            # Track all node IDs that belong to this row (structural + virtual)
            row_node_set: set[str] = {target.id}
            for sid in (row["sub"], row["ip"], row["port"]):
                if sid:
                    row_node_set.add(sid)
            for cn in row["cnames"]:
                row_node_set.add(cn)

            def _clone_tracked(real_id, px, py, par, ek):
                vi = _clone(real_id, px, py, par, ek)
                if vi:
                    row_node_set.add(vi.node().id)   # virtual ID
                    row_node_set.add(real_id)         # real ID (for focus lookups)
                return vi

            # ── Tech / CDN column (index 5) ───────────────────────────────────
            cdn_virt_map: dict[str, object] = {}
            n_t = len(row["techs"])
            for j, tid in enumerate(row["techs"]):
                off = (j - (n_t - 1) / 2.0) * _LANE_NODE_GAP
                real_n = nmap.get(tid)
                ek = ("routes_through" if real_n and real_n.kind == "reverse_proxy"
                      else "proxied_by" if real_n and real_n.kind == "cdn"
                      else "uses_tech")
                vi = _clone_tracked(tid, col_cxs[5], cy + off, parent_item, ek)
                if vi and real_n and real_n.kind in ("cdn", "reverse_proxy"):
                    cdn_virt_map[tid] = vi

            # ── Origin Server column (index 6) ────────────────────────────────
            n_o = len(row["origins"])
            for j, oid in enumerate(row["origins"]):
                off = (j - (n_o - 1) / 2.0) * _LANE_NODE_GAP
                cdn_parent = None
                for cdn_id, cdn_vi in cdn_virt_map.items():
                    if oid in _kids(cdn_id, "origin_of"):
                        cdn_parent = cdn_vi
                        break
                if cdn_parent is None and cdn_virt_map:
                    cdn_parent = next(iter(cdn_virt_map.values()))
                _clone_tracked(oid, col_cxs[6], cy + off, cdn_parent, "origin_of")

            # ── Endpoints column (index 7) ─────────────────────────────────────
            # Only populated when the parent subdomain is in _expanded_nodes.
            ep_virt_map: dict[str, object] = {}   # real_ep_id → virt_item
            n_e = len(row["endpoints"])
            for j, ep_id in enumerate(row["endpoints"]):
                off = (j - (n_e - 1) / 2.0) * _LANE_NODE_GAP
                vi = _clone_tracked(ep_id, col_cxs[7], cy + off, parent_item, "has_endpoint")
                if vi:
                    ep_virt_map[ep_id] = vi

            # ── Parameters column (index 8) ────────────────────────────────────
            n_p = len(row["params"])
            for j, param_id in enumerate(row["params"]):
                off = (j - (n_p - 1) / 2.0) * _LANE_NODE_GAP
                # Edge from the endpoint clone that owns this param
                ep_parent = None
                for ep_id, ep_vi in ep_virt_map.items():
                    if param_id in _all_kids(ep_id, "has_param"):
                        ep_parent = ep_vi
                        break
                if ep_parent is None and ep_virt_map:
                    ep_parent = next(iter(ep_virt_map.values()))
                _clone_tracked(param_id, col_cxs[8], cy + off, ep_parent, "has_param")

            # ── Findings column (index 9) ─────────────────────────────────────
            n_f = len(row["finds"])
            for j, fid in enumerate(row["finds"]):
                off = (j - (n_f - 1) / 2.0) * _LANE_NODE_GAP
                real_n = nmap.get(fid)
                ek = ("has_vuln"  if real_n and real_n.kind == "vuln"
                      else "is_osint" if real_n and real_n.kind == "osint"
                      else "linked_to")
                _clone_tracked(fid, col_cxs[9], cy + off, parent_item, ek)

            self._lane_row_nodes.append(row_node_set)

        # Overflow: visible nodes not placed and not in lane columns
        overflow_y = y + 50.0
        k_ov = 0
        for n in data.nodes:
            if (n.id not in placed and n.id not in lane_col_real_ids
                    and n.kind not in _HIDDEN_BY_DEFAULT):
                _place(n.id, total_w + 90, overflow_y + k_ov * 60)
                k_ov += 1

        # ── Hide real tech/finds/origin nodes + their original edges ─────────────
        self._lane_hidden_node_ids = set(lane_col_real_ids)
        for real_id in lane_col_real_ids:
            item = self._node_items.get(real_id)
            if item and item.isVisible():
                item.setVisible(False)
                self._lane_hidden_items.append(item)

        for ei in self._edge_items:
            if ei.isVisible():
                src_id = ei._src.node().id
                tgt_id = ei._tgt.node().id
                if src_id in lane_col_real_ids or tgt_id in lane_col_real_ids:
                    ei.setVisible(False)
                    self._lane_hidden_items.append(ei)

        # Refresh geometry of still-visible real edges
        for ei in self._edge_items:
            if ei.isVisible():
                ei.adjust()

        # ── Decoration chrome ─────────────────────────────────────────────────
        row_rects = [(0.0, row_ys[i], total_w, row_hs[i]) for i in range(len(chain_rows))]
        deco = _LaneDecorationItem(
            row_rects  = row_rects,
            col_xs     = col_xs,
            col_widths = col_widths,
            col_labels = col_labels,
            total_w    = total_w,
            header_y   = header_y,
        )
        self.addItem(deco)
        self._lane_deco_items = [deco]
        self._lane_row_rects  = row_rects   # (x, y, w, h) per row — used by fit_first_rows

        total_h = y + 40
        self.setSceneRect(QRectF(-20, header_y - 10, total_w + 140, total_h - header_y + 20))
        self.update()

    # ── Background dot grid ───────────────────────────────────────────────────

    def drawBackground(self, painter: QPainter, rect: QRectF):
        import math
        painter.fillRect(rect, QColor("#181825"))

        l, t, r, b = rect.left(), rect.top(), rect.right(), rect.bottom()
        # Guard: scene rect can be NaN when empty, or astronomically large when zoomed out
        if not (math.isfinite(l) and math.isfinite(t) and
                math.isfinite(r) and math.isfinite(b)):
            return
        _MAX = 40_000
        l, t = max(l, -_MAX), max(t, -_MAX)
        r, b = min(r,  _MAX), min(b,  _MAX)

        gs = 40
        painter.setPen(QPen(QColor("#252538"), 1))
        lx = int(l) - (int(l) % gs)
        ty = int(t) - (int(t) % gs)
        x = lx
        while x < r:
            y = ty
            while y < b:
                painter.drawPoint(x, y)
                y += gs
            x += gs

