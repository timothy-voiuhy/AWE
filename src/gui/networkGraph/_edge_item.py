import math

from PySide6.QtCore import Qt, QRectF, QPointF
from PySide6.QtGui import QPainter, QPen, QBrush, QColor, QPolygonF, QFont
from PySide6.QtWidgets import QGraphicsItem

from .nodeItem import NodeItem
from ._constants import _NS, _EC, _DASHED, _LANE_HEADER_H


# ── EdgeItem ──────────────────────────────────────────────────────────────────

class EdgeItem(QGraphicsItem):
    def __init__(self, src: NodeItem, tgt: NodeItem, kind: str):
        super().__init__()
        self._src   = src
        self._tgt   = tgt
        self._kind  = kind
        self._color = QColor(_EC.get(kind, "#585B70"))
        self._sp    = QPointF()
        self._tp    = QPointF()
        self.setFlag(QGraphicsItem.ItemIsSelectable, False)
        self.setZValue(0)
        src.add_edge(self)
        tgt.add_edge(self)
        self.adjust()

    def adjust(self):
        self.prepareGeometryChange()
        self._sp = self._src.mapToScene(QPointF(0, 0))
        self._tp = self._tgt.mapToScene(QPointF(0, 0))

    def boundingRect(self) -> QRectF:
        x1, y1 = self._sp.x(), self._sp.y()
        x2, y2 = self._tp.x(), self._tp.y()
        return QRectF(
            min(x1, x2) - 12, min(y1, y2) - 12,
            abs(x2 - x1) + 24, abs(y2 - y1) + 24,
        )

    def paint(self, painter: QPainter, option, widget=None):
        painter.setRenderHint(QPainter.Antialiasing)
        sp, tp = self._sp, self._tp
        dx, dy = tp.x() - sp.x(), tp.y() - sp.y()
        d = math.hypot(dx, dy)
        if d < 1:
            return

        sr = _NS[self._src.kind()]["r"]
        tr = _NS[self._tgt.kind()]["r"]
        # offset endpoints to node edges
        x1 = sp.x() + dx / d * sr
        y1 = sp.y() + dy / d * sr
        x2 = tp.x() - dx / d * (tr + 8)
        y2 = tp.y() - dy / d * (tr + 8)

        pen = QPen(self._color, 1.2)
        if self._kind in _DASHED:
            pen.setStyle(Qt.DashLine)
        painter.setPen(pen)
        painter.setBrush(Qt.NoBrush)
        painter.drawLine(QPointF(x1, y1), QPointF(x2, y2))

        # arrowhead
        angle = math.atan2(dy, dx)
        aw = 7
        p1 = QPointF(x2 - aw * math.cos(angle - 0.4),
                     y2 - aw * math.sin(angle - 0.4))
        p2 = QPointF(x2 - aw * math.cos(angle + 0.4),
                     y2 - aw * math.sin(angle + 0.4))
        painter.setPen(Qt.NoPen)
        painter.setBrush(self._color)
        painter.drawPolygon(QPolygonF([QPointF(x2, y2), p1, p2]))


# ── Lane decoration item ──────────────────────────────────────────────────────

class _LaneDecorationItem(QGraphicsItem):
    """Draws tabular lane layout chrome: column headers, dividers, row bands."""

    def __init__(
        self,
        row_rects:  list[tuple[float, float, float, float]],
        col_xs:     list[float],
        col_widths: list[int],
        col_labels: list[str],
        total_w:    float,
        header_y:   float,
    ):
        super().__init__()
        self._row_rects  = row_rects   # (x, y, w, h) per row
        self._col_xs     = col_xs
        self._col_widths = col_widths
        self._col_labels = col_labels
        self._total_w    = total_w
        self._header_y   = header_y
        self.setZValue(-2)
        # Not interactive
        self.setFlag(QGraphicsItem.ItemIsMovable, False)
        self.setFlag(QGraphicsItem.ItemIsSelectable, False)
        self.setFlag(QGraphicsItem.ItemIsFocusable, False)

    def boundingRect(self) -> QRectF:
        if not self._row_rects:
            return QRectF()
        bot = max(r[1] + r[3] for r in self._row_rects) + 20
        return QRectF(0, self._header_y, self._total_w, bot - self._header_y)

    def paint(self, painter: QPainter, option, widget=None):
        painter.setRenderHint(QPainter.Antialiasing)

        EVEN     = QColor(24, 24, 42)
        ODD      = QColor(19, 19, 35)
        SEP      = QColor(37, 37, 65)
        BACKBONE = QColor(35, 35, 60)

        # ── Row bands ─────────────────────────────────────────────────────────
        for i, (x, y, w, h) in enumerate(self._row_rects):
            painter.fillRect(QRectF(x, y, w, h), EVEN if i % 2 == 0 else ODD)

            # Row bottom separator
            painter.setPen(QPen(SEP, 1))
            painter.drawLine(QPointF(x, y + h), QPointF(x + w, y + h))

            # Chain backbone: faint dotted horizontal at row midpoint,
            # spanning from the subdomain column rightward
            cy = y + h / 2.0
            x1 = self._col_xs[1] if len(self._col_xs) > 1 else 0.0
            pen_bb = QPen(BACKBONE, 1, Qt.DotLine)
            painter.setPen(pen_bb)
            painter.drawLine(QPointF(x1, cy), QPointF(x + w, cy))

            # Row-index badge on left margin
            f_idx = QFont(); f_idx.setPixelSize(8)
            painter.setFont(f_idx)
            painter.setPen(QColor(45, 45, 75))
            painter.drawText(QPointF(5, cy + 4), str(i + 1))

        # ── Column dividers (full row area height) ────────────────────────────
        if self._row_rects:
            top_y = self._row_rects[0][1]
            bot_y = max(r[1] + r[3] for r in self._row_rects)
            painter.setPen(QPen(SEP, 1))
            for cx in self._col_xs[1:]:
                painter.drawLine(QPointF(cx, top_y), QPointF(cx, bot_y))

        # ── Column header bar ─────────────────────────────────────────────────
        painter.fillRect(
            QRectF(0, self._header_y, self._total_w, _LANE_HEADER_H),
            QColor(13, 13, 22),
        )
        painter.setPen(QPen(QColor(49, 50, 68), 1))
        painter.drawLine(
            QPointF(0, self._header_y + _LANE_HEADER_H),
            QPointF(self._total_w, self._header_y + _LANE_HEADER_H),
        )

        # Per-column accent colors (mirrors _NS palette)
        HDR_COLORS = ["#CBA6F7", "#89B4FA", "#FAB387", "#A6E3A1", "#F9E2AF", "#89DCEB", "#F38BA8"]

        f_hdr = QFont(); f_hdr.setPixelSize(10); f_hdr.setBold(True)
        painter.setFont(f_hdr)
        fm = painter.fontMetrics()

        for i, (label, cx, cw) in enumerate(
            zip(self._col_labels, self._col_xs, self._col_widths)
        ):
            accent = QColor(HDR_COLORS[i] if i < len(HDR_COLORS) else "#CDD6F4")

            # Thin accent bar at the very top of this header cell
            painter.fillRect(QRectF(cx + 2, self._header_y, cw - 4, 3), accent)

            # Divider in header (same columns as body)
            if i > 0:
                painter.setPen(QPen(QColor(49, 50, 68), 1))
                painter.drawLine(
                    QPointF(cx, self._header_y + 3),
                    QPointF(cx, self._header_y + _LANE_HEADER_H),
                )

            # Column label, horizontally centered
            text_w = fm.horizontalAdvance(label)
            tx = cx + (cw - text_w) / 2.0
            ty = self._header_y + (_LANE_HEADER_H + fm.ascent() - fm.descent()) / 2.0
            painter.setPen(accent)
            painter.drawText(QPointF(tx, ty), label)

            # Flow arrow glyph between columns (placed near right edge of cell)
            if i < len(self._col_xs) - 1:
                arrow_x = cx + cw - 13
                arrow_y = ty
                painter.setPen(QColor(55, 55, 85))
                f_arr = QFont(); f_arr.setPixelSize(9)
                painter.setFont(f_arr)
                painter.drawText(QPointF(arrow_x, arrow_y), "›")
                painter.setFont(f_hdr)   # restore header font
