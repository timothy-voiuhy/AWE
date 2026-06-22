import math

from PySide6.QtCore import Qt, QPointF, QRectF
from PySide6.QtGui import QPainter, QPen, QBrush, QColor, QFont, QPolygonF
from PySide6.QtWidgets import QGraphicsItem, QMenu, QApplication

from ._models import GraphNode
from ._constants import _NS, _KIND_ICON, _MENU_SS


# ── NodeItem ──────────────────────────────────────────────────────────────────

class NodeItem(QGraphicsItem):
    def __init__(self, node: GraphNode):
        super().__init__()
        self._node   = node
        self._edges: list["EdgeItem"] = []
        self._hovered = False

        s = _NS[node.kind]
        self._r      = s["r"]
        self._fill   = QColor(s["fill"])
        self._border = QColor(s["border"])
        self._shape  = s["shape"]

        self.setFlags(
            QGraphicsItem.ItemIsMovable |
            QGraphicsItem.ItemIsSelectable |
            QGraphicsItem.ItemSendsGeometryChanges,
        )
        self.setAcceptHoverEvents(True)
        self.setPos(node.x, node.y)
        self.setZValue(1)
        self._search_match: bool | None = None   # None=no search, True=match, False=dim

    # expose for EdgeItem
    def kind(self) -> str: return self._node.kind
    def node(self) -> GraphNode: return self._node
    def add_edge(self, e: "EdgeItem"): self._edges.append(e)

    def boundingRect(self) -> QRectF:
        # +12 covers the halo (r+9); +26 extra on the bottom covers the label
        # which is drawn at y = r+14 with ~10px text height
        r = self._r + 12
        return QRectF(-r, -r, r * 2, r * 2 + 26)

    def paint(self, painter: QPainter, option, widget=None):
        painter.setRenderHint(QPainter.Antialiasing)
        r = self._r

        # glow halo on hover / selection
        if self._hovered or self.isSelected():
            halo = QColor(self._fill)
            halo.setAlpha(55)
            painter.setPen(Qt.NoPen)
            painter.setBrush(halo)
            er = r + 9
            painter.drawEllipse(QRectF(-er, -er, er * 2, er * 2))

        # selection ring
        if self.isSelected():
            painter.setPen(QPen(QColor("#CDD6F4"), 2, Qt.DotLine))
            painter.setBrush(Qt.NoBrush)
            sr = r + 5
            painter.drawEllipse(QRectF(-sr, -sr, sr * 2, sr * 2))

        fill   = self._fill.lighter(115) if self._hovered else self._fill
        bwidth = 2.5 if self._hovered else 1.5
        painter.setPen(QPen(self._border, bwidth))
        painter.setBrush(QBrush(fill))
        self._draw_shape(painter, r)

        # inner icon
        icon = _KIND_ICON.get(self._node.kind, "")
        if icon:
            f = QFont(); f.setPixelSize(max(8, r - 4))
            painter.setFont(f)
            painter.setPen(QColor("#1E1E2E"))
            fm = painter.fontMetrics()
            painter.drawText(
                QPointF(-fm.horizontalAdvance(icon) / 2, fm.ascent() / 2 - 1),
                icon,
            )

        # label below
        label = self._node.label
        if len(label) > 18:
            label = label[:16] + "…"
        f2 = QFont(); f2.setPixelSize(8 if r < 15 else 9)
        painter.setFont(f2)
        fm2 = painter.fontMetrics()
        painter.setPen(QColor("#BAC2DE"))
        painter.drawText(
            QPointF(-fm2.horizontalAdvance(label) / 2, r + 14),
            label,
        )

        # search highlight ring (drawn last so it is on top)
        if self._search_match is True:
            painter.setPen(QPen(QColor("#FAD866"), 2.5))
            painter.setBrush(Qt.NoBrush)
            rh = r + 7
            painter.drawEllipse(QRectF(-rh, -rh, rh * 2, rh * 2))

    def _draw_shape(self, p: QPainter, r: float):
        s = self._shape
        if s == "circle":
            p.drawEllipse(QRectF(-r, -r, r * 2, r * 2))
        elif s == "diamond":
            poly = QPolygonF([QPointF(0,-r), QPointF(r,0), QPointF(0,r), QPointF(-r,0)])
            p.drawPolygon(poly)
        elif s == "square":
            p.drawRoundedRect(QRectF(-r, -r, r * 2, r * 2), 4, 4)
        elif s == "hexagon":
            pts = [QPointF(r*math.cos(math.pi/6 + i*math.pi/3),
                           r*math.sin(math.pi/6 + i*math.pi/3)) for i in range(6)]
            p.drawPolygon(QPolygonF(pts))
        elif s == "triangle":
            pts = [QPointF(0,-r), QPointF(r*0.866, r*0.5), QPointF(-r*0.866, r*0.5)]
            p.drawPolygon(QPolygonF(pts))
        elif s == "shield":
            pts = [
                QPointF(-r,  -r * 0.65),
                QPointF( r,  -r * 0.65),
                QPointF( r,   r * 0.15),
                QPointF( 0,   r),
                QPointF(-r,   r * 0.15),
            ]
            p.drawPolygon(QPolygonF(pts))
        elif s == "note":
            # Rectangle with folded top-right corner (sticky-note silhouette)
            fold = r * 0.55
            body = QPolygonF([
                QPointF(-r, -r), QPointF(fold, -r),
                QPointF(r, -fold), QPointF(r, r),
                QPointF(-r, r),
            ])
            p.drawPolygon(body)
            # Folded corner triangle (slightly darker shade via border pen, no fill)
            old_brush = p.brush()
            p.setBrush(p.pen().color())
            p.drawPolygon(QPolygonF([
                QPointF(fold, -r), QPointF(r, -fold), QPointF(fold, -fold),
            ]))
            p.setBrush(old_brush)
        else:
            p.drawEllipse(QRectF(-r, -r, r * 2, r * 2))

    def itemChange(self, change, value):
        if change == QGraphicsItem.ItemPositionHasChanged:
            for e in self._edges:
                e.adjust()
            x, y = self.x(), self.y()
            self._node.x, self._node.y = x, y
            sc = self.scene()
            if sc is not None:
                sc._pos_cache[self._node.id] = (x, y)
                sc._save_timer.start()   # debounced: fires 1.5 s after last move
        return super().itemChange(change, value)

    def hoverEnterEvent(self, ev):
        self._hovered = True
        self.update()
        super().hoverEnterEvent(ev)

    def hoverLeaveEvent(self, ev):
        self._hovered = False
        self.update()
        super().hoverLeaveEvent(ev)

    def mousePressEvent(self, ev):
        if ev.button() == Qt.LeftButton:
            sc = self.scene()
            if sc and hasattr(sc, "nodeClicked"):
                sc.nodeClicked.emit(self._node)
        super().mousePressEvent(ev)

    def mouseReleaseEvent(self, ev):
        super().mouseReleaseEvent(ev)

    def contextMenuEvent(self, ev):
        kind = self._node.kind
        menu = QMenu()
        menu.setStyleSheet(_MENU_SS)

        sc = self.scene()
        nid = self._node.id

        # ── Kind-specific section ─────────────────────────────────────────────
        kind_actions: dict = {}   # QAction → callable
        copy_val: str | None = None

        if kind == "target":
            menu.addSection("Add to graph")
            kind_actions[menu.addAction("◉  Add Subdomain")] = \
                lambda: sc.addDataRequested.emit("add_subdomain", self._node)
            kind_actions[menu.addAction("△  Add OSINT Finding")] = \
                lambda: sc.addDataRequested.emit("add_osint", self._node)

        elif kind == "subdomain":
            menu.addSection(f"◉ {self._node.label}")
            kind_actions[menu.addAction("◆  Add IP Address")] = \
                lambda: sc.addDataRequested.emit("add_ip", self._node)
            kind_actions[menu.addAction("▣  Add Port / Service")] = \
                lambda: sc.addDataRequested.emit("add_port", self._node)
            kind_actions[menu.addAction("⬡  Add Technology")] = \
                lambda: sc.addDataRequested.emit("add_tech", self._node)
            kind_actions[menu.addAction("⚠  Add Vulnerability")] = \
                lambda: sc.addDataRequested.emit("add_vuln", self._node)
            kind_actions[menu.addAction("↗  Add Endpoint")] = \
                lambda: sc.addDataRequested.emit("add_endpoint", self._node)
            kind_actions[menu.addAction("⊕  Add CDN / Proxy")] = \
                lambda: sc.addDataRequested.emit("add_cdn", self._node)
            menu.addSeparator()
            kind_actions[menu.addAction("△  Add OSINT Finding")] = \
                lambda: sc.addDataRequested.emit("add_osint", self._node)

        elif kind == "ip":
            menu.addSection(f"◆ {self._node.label}")
            kind_actions[menu.addAction("▣  Add Port / Service")] = \
                lambda: sc.addDataRequested.emit("add_port", self._node)

        elif kind == "port":
            menu.addSection(f"▣ {self._node.label}")
            kind_actions[menu.addAction("⬡  Add Technology")] = \
                lambda: sc.addDataRequested.emit("add_tech", self._node)
            kind_actions[menu.addAction("⚠  Add Vulnerability")] = \
                lambda: sc.addDataRequested.emit("add_vuln", self._node)
            kind_actions[menu.addAction("↗  Add Endpoint")] = \
                lambda: sc.addDataRequested.emit("add_endpoint", self._node)

        elif kind in ("cdn", "reverse_proxy"):
            pt = self._node.data.get("proxy_type", "CDN")
            ico = "⇄" if kind == "reverse_proxy" else "⊕"
            menu.addSection(f"{ico}  {self._node.label}  [{pt}]")
            kind_actions[menu.addAction("↪  Add Origin Server")] = \
                lambda: sc.addDataRequested.emit("add_origin_server", self._node)
            copy_val = self._node.label

        elif kind == "endpoint":
            d = self._node.data
            menu.addSection(f"↗ {self._node.label}")
            is_exp = nid in getattr(sc, "_expanded_nodes", set())
            ep_lbl = "?  Hide Parameters" if is_exp else "?  Show Parameters"
            kind_actions[menu.addAction(ep_lbl)] = \
                lambda: sc.toggle_children(nid)
            copy_val = d.get("url", self._node.label)

        elif kind == "param":
            d = self._node.data
            menu.addSection(f"? {self._node.label}")
            copy_val = d.get("example", d.get("name", self._node.label))

        elif kind == "info":
            menu.addSection(f"✎  Note")
            kind_actions[menu.addAction("✎  Edit Note")] = \
                lambda: sc.addDataRequested.emit("edit_info", self._node)
            copy_val = self._node.data.get("content", "")

        elif kind == "custom":
            menu.addSection(f"＋  {self._node.label}")
            copy_val = self._node.data.get("description", self._node.label)

        else:
            # vuln / tech / osint
            copy_val = (self._node.data.get("value") or
                        self._node.data.get("tech") or
                        self._node.label)

        # ── Universal "Endpoints" toggle for subdomain ────────────────────────
        if kind == "subdomain" and sc is not None:
            is_exp = nid in getattr(sc, "_expanded_nodes", set())
            ep_lbl = "↗  Hide Endpoints" if is_exp else "↗  Show Endpoints"
            menu.addSeparator()
            kind_actions[menu.addAction(ep_lbl)] = \
                lambda: sc.toggle_children(nid)

        # ── Universal actions on every node ───────────────────────────────────
        menu.addSeparator()

        # Note: check if a note already exists for this node in the scene
        info_id = f"info:{nid}"
        has_note = info_id in getattr(sc, "_node_items", {})
        note_lbl = "✎  Edit Note" if has_note else "✎  Add Note"
        a_note = menu.addAction(note_lbl)

        # Don't offer "add custom node" on info/custom nodes themselves
        a_custom = None
        if kind not in ("info",):
            a_custom = menu.addAction("＋  Add Custom Node here")

        if copy_val is not None:
            a_copy = menu.addAction("⎘  Copy")
            kind_actions[a_copy] = lambda: QApplication.clipboard().setText(copy_val)

        menu.addSeparator()
        _real_id   = self._node.data.get("_real_id", nid)
        _focused   = getattr(sc, "_focused_id", None)
        is_focused = _focused in (nid, _real_id)
        a_focus = menu.addAction(
            "⊗  Unfocus (show all)" if is_focused else "◎  Focus: show only this + neighbors"
        )

        chosen = menu.exec(ev.screenPos())
        if chosen == a_focus:
            if is_focused:
                sc.unfocus()
            else:
                sc.focus_node(nid)
        elif chosen == a_note:
            sc.addDataRequested.emit(
                "edit_info" if has_note else "add_info", self._node
            )
        elif a_custom and chosen == a_custom:
            sc.addDataRequested.emit("add_custom", self._node)
        elif chosen in kind_actions:
            kind_actions[chosen]()

        ev.accept()

