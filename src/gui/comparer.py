"""
ComparerPage — side-by-side HTTP diff tool.

Left and right panes each hold raw HTTP text (request or response).
Clicking Compare (or auto-triggering on content change) runs difflib and
colours lines:
    Red    (#3D1A1A bg) — lines only in left  (removed)
    Green  (#1A3D1A bg) — lines only in right (added)
    Yellow (#3D3A1A bg) — lines in both but changed
"""
from __future__ import annotations

import difflib

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QColor, QFont, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTextEdit, QSplitter, QFrame,
)

from gui.utilities.syntax_highlighter import SyntaxHighlighter

_RED    = QColor("#3D1A1A")
_GREEN  = QColor("#1A3D1A")
_YELLOW = QColor("#3D3A1A")

_BTN_SS = (
    "QPushButton{background:#313244;color:#CDD6F4;border:1px solid #45475A;"
    "border-radius:4px;padding:0 10px;min-height:24px;font-size:9px;}"
    "QPushButton:hover{background:#45475A;}"
)


class _DiffView(QTextEdit):
    """Read-only code viewer that can highlight arbitrary line ranges."""

    def __init__(self, label: str, accent: str, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setFont(QFont("Cascadia Code", 9))
        self.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        self.setStyleSheet(
            "QTextEdit{background:#11111B;color:#CDD6F4;border:none;padding:8px;}"
        )
        self._hl = SyntaxHighlighter(self.document())

        # Pane header
        self._label = label
        self._accent = accent

    def apply_colors(self, line_colors: dict[int, QColor]) -> None:
        """Apply per-line background colours via ExtraSelections."""
        sels = []
        doc  = self.document()
        for line_no, color in line_colors.items():
            block = doc.findBlockByLineNumber(line_no)
            if not block.isValid():
                continue
            fmt = QTextCharFormat()
            fmt.setBackground(color)
            sel = QTextEdit.ExtraSelection()
            cur = QTextCursor(block)
            cur.movePosition(QTextCursor.StartOfBlock)
            cur.movePosition(QTextCursor.EndOfBlock, QTextCursor.KeepAnchor)
            sel.cursor = cur
            sel.format  = fmt
            sels.append(sel)
        self.setExtraSelections(sels)

    def clear_colors(self) -> None:
        self.setExtraSelections([])


class ComparerPage(QWidget):
    """Side-by-side diff page embedded in the main nav stack."""

    def __init__(self, repository=None, parent=None):
        super().__init__(parent)
        self._repo = repository
        self._build_ui()
        self._debounce = QTimer(self)
        self._debounce.setSingleShot(True)
        self._debounce.setInterval(400)
        self._debounce.timeout.connect(self._run_diff)
        self._save_timer = QTimer(self)
        self._save_timer.setSingleShot(True)
        self._save_timer.setInterval(1500)
        self._save_timer.timeout.connect(self._save_state)
        self._left.textChanged.connect(self._save_timer.start)
        self._right.textChanged.connect(self._save_timer.start)
        self._restore_state()

    # ── public API ────────────────────────────────────────────────────────────

    def load_left(self, text: str) -> None:
        self._left.setPlainText(text)
        self._run_diff()

    def load_right(self, text: str) -> None:
        self._right.setPlainText(text)
        self._run_diff()

    # ── persistence ───────────────────────────────────────────────────────────

    def _save_state(self) -> None:
        if not self._repo:
            return
        try:
            self._repo.save_page_state("comparer", {
                "left":  self._left.toPlainText(),
                "right": self._right.toPlainText(),
            })
        except Exception:
            pass

    def _restore_state(self) -> None:
        if not self._repo:
            return
        try:
            state = self._repo.load_page_state("comparer")
        except Exception:
            return
        if not state:
            return
        if state.get("left"):
            self._left.setPlainText(state["left"])
        if state.get("right"):
            self._right.setPlainText(state["right"])
        if state.get("left") or state.get("right"):
            self._run_diff()

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Toolbar ───────────────────────────────────────────────────────────
        tb = QHBoxLayout()
        tb.setContentsMargins(8, 6, 8, 6)
        tb.setSpacing(8)

        title = QLabel("Comparer")
        title.setStyleSheet("color:#CDD6F4; font-weight:bold; font-size:11px;")
        tb.addWidget(title)
        tb.addStretch()

        self._stats_lbl = QLabel("")
        self._stats_lbl.setStyleSheet("color:#6C7086; font-size:9px;")
        tb.addWidget(self._stats_lbl)

        swap_btn = QPushButton("Swap ⇄")
        swap_btn.setFixedHeight(24)
        swap_btn.setStyleSheet(_BTN_SS)
        swap_btn.setToolTip("Swap left and right panes")
        swap_btn.clicked.connect(self._swap)
        tb.addWidget(swap_btn)

        clear_btn = QPushButton("Clear")
        clear_btn.setFixedHeight(24)
        clear_btn.setStyleSheet(_BTN_SS)
        clear_btn.clicked.connect(self._clear)
        tb.addWidget(clear_btn)

        root.addLayout(tb)

        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setFixedHeight(1)
        sep.setStyleSheet("background:#313244; border:none;")
        root.addWidget(sep)

        # ── Legend ────────────────────────────────────────────────────────────
        legend = QHBoxLayout()
        legend.setContentsMargins(8, 4, 8, 4)
        legend.setSpacing(16)
        legend.addWidget(_legend_chip("#3D1A1A", "#F38BA8", "Removed"))
        legend.addWidget(_legend_chip("#1A3D1A", "#A6E3A1", "Added"))
        legend.addWidget(_legend_chip("#3D3A1A", "#F9E2AF", "Changed"))
        legend.addStretch()
        root.addLayout(legend)

        sep2 = QFrame()
        sep2.setFrameShape(QFrame.HLine)
        sep2.setFixedHeight(1)
        sep2.setStyleSheet("background:#313244; border:none;")
        root.addWidget(sep2)

        # ── Pane headers ──────────────────────────────────────────────────────
        hdr_row = QHBoxLayout()
        hdr_row.setContentsMargins(0, 0, 0, 0)
        hdr_row.setSpacing(0)
        left_hdr  = _pane_header("LEFT",  "#89B4FA")
        right_hdr = _pane_header("RIGHT", "#A6E3A1")
        hdr_row.addWidget(left_hdr, stretch=1)
        hdr_row.addWidget(_vdiv(), 0)
        hdr_row.addWidget(right_hdr, stretch=1)
        root.addLayout(hdr_row)

        # ── Splitter ──────────────────────────────────────────────────────────
        splitter = QSplitter(Qt.Horizontal)
        splitter.setChildrenCollapsible(False)
        splitter.setStyleSheet("QSplitter::handle{background:#313244;width:3px;}")

        self._left  = _DiffView("LEFT",  "#89B4FA")
        self._right = _DiffView("RIGHT", "#A6E3A1")

        splitter.addWidget(self._left)
        splitter.addWidget(self._right)
        splitter.setSizes([500, 500])

        root.addWidget(splitter, stretch=1)

    # ── diff logic ────────────────────────────────────────────────────────────

    def _run_diff(self) -> None:
        left_lines  = self._left.toPlainText().splitlines()
        right_lines = self._right.toPlainText().splitlines()

        if not left_lines and not right_lines:
            self._left.clear_colors()
            self._right.clear_colors()
            self._stats_lbl.setText("")
            return

        sm = difflib.SequenceMatcher(None, left_lines, right_lines, autojunk=False)

        left_colors:  dict[int, QColor] = {}
        right_colors: dict[int, QColor] = {}
        n_removed = n_added = n_changed = 0

        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            if tag == 'replace':
                for ln in range(i1, i2):
                    left_colors[ln]  = _YELLOW
                for ln in range(j1, j2):
                    right_colors[ln] = _YELLOW
                n_changed += max(i2 - i1, j2 - j1)
            elif tag == 'delete':
                for ln in range(i1, i2):
                    left_colors[ln] = _RED
                n_removed += i2 - i1
            elif tag == 'insert':
                for ln in range(j1, j2):
                    right_colors[ln] = _GREEN
                n_added += j2 - j1

        self._left.apply_colors(left_colors)
        self._right.apply_colors(right_colors)

        parts = []
        if n_removed: parts.append(f"{n_removed} removed")
        if n_added:   parts.append(f"{n_added} added")
        if n_changed: parts.append(f"{n_changed} changed")
        self._stats_lbl.setText("  ·  ".join(parts) if parts else "identical")

    # ── actions ───────────────────────────────────────────────────────────────

    def _swap(self) -> None:
        l = self._left.toPlainText()
        r = self._right.toPlainText()
        self._left.setPlainText(r)
        self._right.setPlainText(l)
        self._run_diff()

    def _clear(self) -> None:
        self._left.clear()
        self._right.clear()
        self._left.clear_colors()
        self._right.clear_colors()
        self._stats_lbl.setText("")


# ── helpers ───────────────────────────────────────────────────────────────────

def _pane_header(label: str, accent: str) -> QWidget:
    w = QWidget()
    w.setFixedHeight(24)
    w.setStyleSheet(f"background:#181825; border-bottom:2px solid {accent};")
    hb = QHBoxLayout(w)
    hb.setContentsMargins(8, 0, 8, 0)
    lbl = QLabel(label)
    lbl.setStyleSheet(f"color:{accent}; font-size:9px; font-weight:bold; background:transparent;")
    hb.addWidget(lbl)
    hb.addStretch()
    return w


def _vdiv() -> QFrame:
    f = QFrame()
    f.setFrameShape(QFrame.VLine)
    f.setFixedWidth(1)
    f.setStyleSheet("background:#313244; border:none;")
    return f


def _legend_chip(bg: str, fg: str, label: str) -> QWidget:
    w = QWidget()
    w.setFixedHeight(18)
    hb = QHBoxLayout(w)
    hb.setContentsMargins(0, 0, 0, 0)
    hb.setSpacing(4)
    swatch = QFrame()
    swatch.setFixedSize(12, 12)
    swatch.setStyleSheet(f"background:{bg}; border:1px solid {fg}; border-radius:2px;")
    hb.addWidget(swatch)
    lbl = QLabel(label)
    lbl.setStyleSheet(f"color:{fg}; font-size:9px; background:transparent;")
    hb.addWidget(lbl)
    return w
