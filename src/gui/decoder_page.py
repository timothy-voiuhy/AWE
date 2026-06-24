"""
DecoderPage — chainable encode / decode workbench.

Input  →  [step1] → [step2] → … →  Output

Each step applies one transform (Base64, URL, Hex, …) in Encode or Decode
direction.  Output is recomputed on every keystroke (300 ms debounce) and
on every chain change.
"""
from __future__ import annotations

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTextEdit, QScrollArea, QFrame, QComboBox, QSizePolicy,
)

from gui.utilities.syntax_highlighter import SyntaxHighlighter
from gui.utilities.decode_dialog import decode_text
from gui.utilities.transforms import apply_transform, transform_directions, TRANSFORM_LABELS

# Ordered list of transform names for the combo box
_TRANSFORMS = list(TRANSFORM_LABELS.keys())

_BTN_SS = (
    "QPushButton{background:#313244;color:#CDD6F4;border:1px solid #45475A;"
    "border-radius:4px;padding:0 10px;min-height:24px;font-size:9px;}"
    "QPushButton:hover{background:#45475A;}"
)
_COMBO_SS = (
    "QComboBox{background:#1E1E2E;color:#CDD6F4;border:1px solid #45475A;"
    "border-radius:4px;padding:0 6px;min-height:24px;font-size:9px;}"
    "QComboBox:hover{border-color:#89B4FA;}"
    "QComboBox::drop-down{border:none;width:18px;}"
    "QComboBox QAbstractItemView{background:#1E1E2E;color:#CDD6F4;"
    "border:1px solid #45475A;selection-background-color:#313244;}"
)


class _ChainStep(QWidget):
    """One transform step: [Transform ▾] [Direction ▾] [✕]"""

    changed          = Signal()
    remove_requested = Signal(object)   # emits self

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(34)

        row = QHBoxLayout(self)
        row.setContentsMargins(6, 4, 4, 4)
        row.setSpacing(4)

        # Left accent bar
        bar = QFrame()
        bar.setFixedWidth(2)
        bar.setStyleSheet("background:#89B4FA; border-radius:1px;")
        row.addWidget(bar)

        self._transform_cb = QComboBox()
        self._transform_cb.setStyleSheet(_COMBO_SS)
        self._transform_cb.setFixedWidth(130)
        for name in _TRANSFORMS:
            self._transform_cb.addItem(TRANSFORM_LABELS[name], name)
        self._transform_cb.currentIndexChanged.connect(self._on_transform_changed)
        row.addWidget(self._transform_cb)

        self._dir_cb = QComboBox()
        self._dir_cb.setStyleSheet(_COMBO_SS)
        self._dir_cb.setFixedWidth(110)
        self._dir_cb.currentIndexChanged.connect(self.changed)
        row.addWidget(self._dir_cb)

        self._rm_btn = QPushButton("✕")
        self._rm_btn.setFixedSize(22, 22)
        self._rm_btn.setStyleSheet(
            "QPushButton{background:transparent;color:#6C7086;border:none;font-size:11px;}"
            "QPushButton:hover{color:#F38BA8;}"
        )
        self._rm_btn.clicked.connect(lambda: self.remove_requested.emit(self))
        row.addWidget(self._rm_btn)

        self._on_transform_changed()

    def _on_transform_changed(self):
        name = self._transform_cb.currentData()
        dirs = transform_directions(name)
        self._dir_cb.blockSignals(True)
        self._dir_cb.clear()
        for d in dirs:
            self._dir_cb.addItem(d)
        self._dir_cb.blockSignals(False)
        self.changed.emit()

    def transform(self) -> str:
        return self._transform_cb.currentData()

    def direction(self) -> str:
        return self._dir_cb.currentText()


class DecoderPage(QWidget):
    """Chainable encode/decode workbench."""

    def __init__(self, repository=None, parent=None):
        super().__init__(parent)
        self._repo = repository
        self._steps: list[_ChainStep] = []
        self._debounce = QTimer(self)
        self._debounce.setSingleShot(True)
        self._debounce.setInterval(300)
        self._debounce.timeout.connect(self._apply_chain)
        self._save_timer = QTimer(self)
        self._save_timer.setSingleShot(True)
        self._save_timer.setInterval(1500)
        self._save_timer.timeout.connect(self._save_state)
        self._build_ui()
        self._restore_state()

    # ── public API ────────────────────────────────────────────────────────────

    def load_text(self, text: str) -> None:
        """Populate the input box (called by TargetWindow on 'Send to Decoder')."""
        self._input_edit.setPlainText(text)

    # ── persistence ───────────────────────────────────────────────────────────

    def _schedule_save(self) -> None:
        if self._repo:
            self._save_timer.start()

    def _save_state(self) -> None:
        if not self._repo:
            return
        state = {
            "input": self._input_edit.toPlainText(),
            "chain": [{"transform": s.transform(), "direction": s.direction()}
                      for s in self._steps],
        }
        try:
            self._repo.save_page_state("decoder", state)
        except Exception:
            pass

    def _restore_state(self) -> None:
        if not self._repo:
            return
        try:
            state = self._repo.load_page_state("decoder")
        except Exception:
            return
        if not state:
            return
        for step_data in state.get("chain", []):
            self._add_step(
                transform=step_data.get("transform"),
                direction=step_data.get("direction"),
            )
        # Restore input last (triggers debounce → _apply_chain)
        saved_input = state.get("input", "")
        if saved_input:
            self._input_edit.setPlainText(saved_input)

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Toolbar ───────────────────────────────────────────────────────────
        tb = QHBoxLayout()
        tb.setContentsMargins(8, 6, 8, 6)
        tb.setSpacing(8)

        title = QLabel("Decoder / Encoder")
        title.setStyleSheet("color:#CDD6F4; font-weight:bold; font-size:11px;")
        tb.addWidget(title)
        tb.addStretch()

        smart_btn = QPushButton("Smart Decode")
        smart_btn.setFixedHeight(24)
        smart_btn.setStyleSheet(_BTN_SS)
        smart_btn.setToolTip("Auto-detect and decode the input text")
        smart_btn.clicked.connect(self._smart_decode)
        tb.addWidget(smart_btn)

        clear_btn = QPushButton("Clear")
        clear_btn.setFixedHeight(24)
        clear_btn.setStyleSheet(_BTN_SS)
        clear_btn.clicked.connect(self._clear_all)
        tb.addWidget(clear_btn)

        root.addLayout(tb)
        root.addWidget(_sep())

        # ── Input ─────────────────────────────────────────────────────────────
        in_hdr = _section_label("INPUT")
        root.addWidget(in_hdr)

        self._input_edit = QTextEdit()
        self._input_edit.setFont(QFont("Cascadia Code", 9))
        self._input_edit.setStyleSheet(
            "QTextEdit{background:#11111B;color:#CDD6F4;border:none;padding:8px;}"
        )
        self._input_edit.setPlaceholderText("Paste text to encode / decode…")
        SyntaxHighlighter(self._input_edit.document())
        self._input_edit.textChanged.connect(self._debounce.start)
        self._input_edit.textChanged.connect(self._schedule_save)
        root.addWidget(self._input_edit, stretch=2)

        root.addWidget(_sep())

        # ── Chain bar ─────────────────────────────────────────────────────────
        chain_hdr = QHBoxLayout()
        chain_hdr.setContentsMargins(8, 4, 8, 4)
        chain_hdr.setSpacing(6)
        chain_hdr.addWidget(_section_label("TRANSFORM CHAIN"))
        chain_hdr.addStretch()

        add_btn = QPushButton("+ Add Step")
        add_btn.setFixedHeight(24)
        add_btn.setStyleSheet(_BTN_SS)
        add_btn.clicked.connect(self._add_step)
        chain_hdr.addWidget(add_btn)
        root.addLayout(chain_hdr)

        # Horizontal scroll area for the steps
        self._chain_scroll = QScrollArea()
        self._chain_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self._chain_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self._chain_scroll.setWidgetResizable(True)
        self._chain_scroll.setFixedHeight(46)
        self._chain_scroll.setStyleSheet(
            "QScrollArea{background:#181825;border:none;"
            "border-top:1px solid #313244;border-bottom:1px solid #313244;}"
        )

        self._chain_inner = QWidget()
        self._chain_inner.setStyleSheet("background:#181825;")
        self._chain_row = QHBoxLayout(self._chain_inner)
        self._chain_row.setContentsMargins(4, 4, 4, 4)
        self._chain_row.setSpacing(6)
        self._chain_row.addStretch()        # pushes steps left

        self._chain_scroll.setWidget(self._chain_inner)
        root.addWidget(self._chain_scroll)

        # ── Error label ───────────────────────────────────────────────────────
        self._err_lbl = QLabel("")
        self._err_lbl.setStyleSheet(
            "color:#F38BA8; font-size:9px; padding:2px 8px; background:transparent;"
        )
        self._err_lbl.setVisible(False)
        root.addWidget(self._err_lbl)

        root.addWidget(_sep())

        # ── Output ────────────────────────────────────────────────────────────
        root.addWidget(_section_label("OUTPUT"))

        self._output_edit = QTextEdit()
        self._output_edit.setReadOnly(True)
        self._output_edit.setFont(QFont("Cascadia Code", 9))
        self._output_edit.setStyleSheet(
            "QTextEdit{background:#11111B;color:#CDD6F4;border:none;padding:8px;}"
        )
        SyntaxHighlighter(self._output_edit.document())
        root.addWidget(self._output_edit, stretch=2)

    # ── chain management ──────────────────────────────────────────────────────

    def _add_step(self, transform: str | None = None, direction: str | None = None) -> None:
        step = _ChainStep(self._chain_inner)
        if transform:
            idx = step._transform_cb.findData(transform)
            if idx >= 0:
                step._transform_cb.setCurrentIndex(idx)
        if direction:
            idx = step._dir_cb.findText(direction)
            if idx >= 0:
                step._dir_cb.setCurrentIndex(idx)
        step.changed.connect(self._apply_chain)
        step.changed.connect(self._schedule_save)
        step.remove_requested.connect(self._remove_step)
        self._steps.append(step)
        # Insert before the trailing stretch (always last item)
        self._chain_row.insertWidget(self._chain_row.count() - 1, step)
        self._apply_chain()

    def _remove_step(self, step: _ChainStep) -> None:
        if step in self._steps:
            self._steps.remove(step)
            self._chain_row.removeWidget(step)
            step.deleteLater()
            self._apply_chain()
            self._schedule_save()

    # ── processing ───────────────────────────────────────────────────────────

    def _apply_chain(self) -> None:
        text = self._input_edit.toPlainText()
        self._err_lbl.setVisible(False)

        if not self._steps:
            self._output_edit.setPlainText(text)
            return

        current = text
        for i, step in enumerate(self._steps):
            result, err = apply_transform(current, step.transform(), step.direction())
            if result is None:
                label = TRANSFORM_LABELS.get(step.transform(), step.transform())
                self._err_lbl.setText(
                    f"Step {i + 1} ({label} / {step.direction()}): {err or 'failed'}"
                )
                self._err_lbl.setVisible(True)
                self._output_edit.setPlainText(current)
                return
            current = result

        self._output_edit.setPlainText(current)

    def _smart_decode(self) -> None:
        text = self._input_edit.toPlainText().strip()
        if not text:
            return
        result, method = decode_text(text, 'auto')
        if result is None:
            self._err_lbl.setText("Smart Decode: could not determine encoding")
            self._err_lbl.setVisible(True)
        else:
            self._err_lbl.setVisible(False)
            self._output_edit.setPlainText(result)
            self._err_lbl.setText(f"Smart Decode detected: {method}")
            self._err_lbl.setStyleSheet(
                "color:#A6E3A1; font-size:9px; padding:2px 8px; background:transparent;"
            )
            self._err_lbl.setVisible(True)

    def _clear_all(self) -> None:
        self._input_edit.clear()
        self._output_edit.clear()
        self._err_lbl.setVisible(False)
        self._err_lbl.setStyleSheet(
            "color:#F38BA8; font-size:9px; padding:2px 8px; background:transparent;"
        )


# ── helpers ───────────────────────────────────────────────────────────────────

def _sep() -> QFrame:
    f = QFrame()
    f.setFrameShape(QFrame.HLine)
    f.setFixedHeight(1)
    f.setStyleSheet("background:#313244; border:none;")
    return f


def _section_label(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setStyleSheet(
        "color:#6C7086; font-size:8px; letter-spacing:1px; padding:2px 8px;"
        " background:transparent;"
    )
    return lbl
