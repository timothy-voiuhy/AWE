from PySide6.QtCore import Qt, QRectF, QPointF, QRect
from PySide6.QtGui import QPainter, QPen, QColor
from PySide6.QtWidgets import QGraphicsView, QFrame, QMenu

from .networkGraphScene import NetworkGraphScene
from .nodeItem import NodeItem
from ._constants import _MENU_SS


# ── View ──────────────────────────────────────────────────────────────────────

class NetworkGraphView(QGraphicsView):
    """
    Interaction layer on top of NetworkGraphScene.

    Mouse bindings
    ──────────────
    Middle-drag          Pan
    Wheel                Zoom in/out
    Shift+Left-drag      Lasso selection (rubber-band rect)
    Double-click canvas  Fit all

    Keyboard bindings
    ─────────────────
    F          Fit all
    + / =      Zoom in
    - / _      Zoom out
    Ctrl+0     Reset zoom to 100 %
    Escape     Clear lasso selection
    """

    # Factor applied per zoom step (wheel tick or button press)
    _ZOOM_IN  = 1.18
    _ZOOM_OUT = 1 / 1.18

    def __init__(self, scene: NetworkGraphScene, parent=None):
        super().__init__(scene, parent)
        self.setRenderHints(
            QPainter.Antialiasing |
            QPainter.TextAntialiasing |
            QPainter.SmoothPixmapTransform,
        )
        self.setViewportUpdateMode(QGraphicsView.FullViewportUpdate)
        self.setDragMode(QGraphicsView.NoDrag)
        self.setTransformationAnchor(QGraphicsView.AnchorUnderMouse)
        self.setResizeAnchor(QGraphicsView.AnchorViewCenter)
        self.setFrameShape(QFrame.NoFrame)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.setStyleSheet("""
            QScrollBar:horizontal {
                background: #181825;
                height: 10px;
                border: none;
                border-top: 1px solid #313244;
            }
            QScrollBar::handle:horizontal {
                background: #45475A;
                border-radius: 4px;
                min-width: 24px;
                margin: 2px 2px;
            }
            QScrollBar::handle:horizontal:hover { background: #585B70; }
            QScrollBar::handle:horizontal:pressed { background: #89B4FA; }
            QScrollBar::add-line:horizontal,
            QScrollBar::sub-line:horizontal { width: 0px; }
            QScrollBar::add-page:horizontal,
            QScrollBar::sub-page:horizontal { background: none; }

            QScrollBar:vertical {
                background: #181825;
                width: 10px;
                border: none;
                border-left: 1px solid #313244;
            }
            QScrollBar::handle:vertical {
                background: #45475A;
                border-radius: 4px;
                min-height: 24px;
                margin: 2px 2px;
            }
            QScrollBar::handle:vertical:hover { background: #585B70; }
            QScrollBar::handle:vertical:pressed { background: #89B4FA; }
            QScrollBar::add-line:vertical,
            QScrollBar::sub-line:vertical { height: 0px; }
            QScrollBar::add-page:vertical,
            QScrollBar::sub-page:vertical { background: none; }

            QScrollBar::corner { background: #181825; }
        """)

        # Pan state
        self._panning   = False
        self._pan_start = QPointF()

        # Lasso state
        self._lasso_active = False
        self._lasso_origin  = QPointF()   # view coordinates
        self._lasso_current = QPointF()

        # Zoom level tracking (1.0 = 100 %)
        self._zoom_level    = 1.0
        self._zoom_locked   = False  # when True, wheel scrolls instead of zooming
        self._zoom_observer = None   # callable(float) | None — set by NetworkPage

    # ── Public ────────────────────────────────────────────────────────────────

    def zoom_level(self) -> float:
        """Current zoom as a plain factor (1.0 = 100 %)."""
        return self._zoom_level

    def zoom_in(self):
        self._apply_zoom(self._ZOOM_IN)

    def zoom_out(self):
        self._apply_zoom(self._ZOOM_OUT)

    def zoom_reset(self):
        self._apply_zoom(1.0 / self._zoom_level)   # back to 1.0

    def fit_all(self):
        br = self.scene().itemsBoundingRect()
        if not br.isEmpty():
            self.fitInView(br.adjusted(-30, -30, 30, 30), Qt.KeepAspectRatio)
            # Recalculate _zoom_level from the transform matrix
            self._zoom_level = self.transform().m11()
            self._emit_zoom()

    # ── Wheel ─────────────────────────────────────────────────────────────────

    def wheelEvent(self, ev):
        if self._zoom_locked:
            # Route wheel to vertical scrollbar; Shift routes to horizontal
            delta = ev.angleDelta().y() or ev.angleDelta().x()
            if ev.modifiers() & Qt.ShiftModifier:
                bar = self.horizontalScrollBar()
            else:
                bar = self.verticalScrollBar()
            bar.setValue(bar.value() - delta)
            ev.accept()
            return
        factor = self._ZOOM_IN if ev.angleDelta().y() > 0 else self._ZOOM_OUT
        self._apply_zoom(factor)

    # ── Mouse press ───────────────────────────────────────────────────────────

    def mousePressEvent(self, ev):
        if ev.button() == Qt.MiddleButton:
            self._panning   = True
            self._pan_start = ev.position()
            self.setCursor(Qt.ClosedHandCursor)
            ev.accept()
            return

        if (ev.button() == Qt.LeftButton and
                ev.modifiers() & Qt.ShiftModifier and
                not self.itemAt(ev.pos())):
            # Start lasso on empty canvas with Shift held
            self._lasso_active  = True
            self._lasso_origin  = QPointF(ev.pos())
            self._lasso_current = QPointF(ev.pos())
            self.setCursor(Qt.CrossCursor)
            ev.accept()
            return

        super().mousePressEvent(ev)

    # ── Mouse move ────────────────────────────────────────────────────────────

    def mouseMoveEvent(self, ev):
        if self._panning:
            d = ev.position() - self._pan_start
            self._pan_start = ev.position()
            self.horizontalScrollBar().setValue(
                self.horizontalScrollBar().value() - int(d.x()))
            self.verticalScrollBar().setValue(
                self.verticalScrollBar().value() - int(d.y()))
            ev.accept()
            return

        if self._lasso_active:
            self._lasso_current = QPointF(ev.pos())
            self.viewport().update()   # trigger paintEvent for live rubber-band
            ev.accept()
            return

        super().mouseMoveEvent(ev)

    # ── Mouse release ─────────────────────────────────────────────────────────

    def mouseReleaseEvent(self, ev):
        if self._panning and ev.button() == Qt.MiddleButton:
            self._panning = False
            self.setCursor(Qt.ArrowCursor)
            ev.accept()
            return

        if self._lasso_active and ev.button() == Qt.LeftButton:
            self._lasso_active = False
            self.setCursor(Qt.ArrowCursor)
            self._apply_lasso_selection(ev.modifiers())
            self.viewport().update()
            ev.accept()
            return

        super().mouseReleaseEvent(ev)

    # ── Double click ──────────────────────────────────────────────────────────

    def mouseDoubleClickEvent(self, ev):
        if not self.itemAt(ev.pos()):
            self.fit_all()
        super().mouseDoubleClickEvent(ev)

    # ── Keyboard ──────────────────────────────────────────────────────────────

    def keyPressEvent(self, ev):
        key  = ev.key()
        mods = ev.modifiers()
        if key == Qt.Key_F:
            self.fit_all()
        elif key in (Qt.Key_Plus, Qt.Key_Equal):
            self._apply_zoom(self._ZOOM_IN)
        elif key in (Qt.Key_Minus, Qt.Key_Underscore):
            self._apply_zoom(self._ZOOM_OUT)
        elif key == Qt.Key_0 and mods & Qt.ControlModifier:
            self.zoom_reset()
        elif key == Qt.Key_Escape:
            self.scene().clearSelection()
        else:
            super().keyPressEvent(ev)

    # ── Context menu (canvas right-click) ─────────────────────────────────────

    def contextMenuEvent(self, ev):
        item = self.itemAt(ev.pos())
        if item is not None:
            super().contextMenuEvent(ev)
            return
        sc = self.scene()
        if not hasattr(sc, "addDataRequested"):
            return
        menu = QMenu(self)
        menu.setStyleSheet(_MENU_SS)
        menu.addSection("Add to graph")
        a_sub   = menu.addAction("◉  Add Subdomain")
        a_osint = menu.addAction("△  Add OSINT Finding")
        menu.addSeparator()
        a_vuln  = menu.addAction("⚠  Add Vulnerability")
        a_ep    = menu.addAction("↗  Add Endpoint")
        chosen = menu.exec(ev.globalPos())
        if chosen == a_sub:
            sc.addDataRequested.emit("add_subdomain", None)
        elif chosen == a_osint:
            sc.addDataRequested.emit("add_osint", None)
        elif chosen == a_vuln:
            sc.addDataRequested.emit("add_vuln", None)
        elif chosen == a_ep:
            sc.addDataRequested.emit("add_endpoint", None)

    # ── Lasso rubber-band overlay ─────────────────────────────────────────────

    def paintEvent(self, ev):
        super().paintEvent(ev)
        if not self._lasso_active:
            return
        p = QPainter(self.viewport())
        lasso_rect = QRect(
            self._lasso_origin.toPoint(),
            self._lasso_current.toPoint(),
        ).normalized()
        fill = QColor("#89B4FA")
        fill.setAlpha(28)
        p.fillRect(lasso_rect, fill)
        p.setPen(QPen(QColor("#89B4FA"), 1, Qt.DashLine))
        p.setBrush(Qt.NoBrush)
        p.drawRect(lasso_rect)
        p.end()

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _apply_zoom(self, factor: float):
        new_level = self._zoom_level * factor
        # Clamp: 5 % – 800 %
        new_level = max(0.05, min(8.0, new_level))
        actual_factor = new_level / self._zoom_level
        self._zoom_level = new_level
        self.scale(actual_factor, actual_factor)
        self._emit_zoom()

    def _emit_zoom(self):
        """Notify the registered zoom observer, if any."""
        if hasattr(self, "_zoom_observer") and self._zoom_observer:
            self._zoom_observer(self._zoom_level)

    def _apply_lasso_selection(self, modifiers):
        """Select all NodeItems inside the lasso rect.

        Without any modifier: replace selection.
        Shift (held on press) adds to existing selection.
        """
        rect = QRectF(
            self._lasso_origin,
            self._lasso_current,
        ).normalized()
        scene_rect = self.mapToScene(rect.toRect()).boundingRect()

        # Additive if Ctrl is held at release (Shift was used to initiate)
        additive = bool(modifiers & Qt.ControlModifier)
        if not additive:
            self.scene().clearSelection()

        for item in self.scene().items(scene_rect):
            if isinstance(item, NodeItem) and item.isVisible():
                item.setSelected(True)

