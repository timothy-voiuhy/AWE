from __future__ import annotations

from typing import Callable

from PySide6.QtCore import QTimer
from PySide6.QtGui import QTextCursor, QSyntaxHighlighter
from PySide6.QtWidgets import QTextEdit


class VirtualTextEdit(QTextEdit):
    """
    QTextEdit-compatible large-text viewer.

    The widget keeps the complete text in memory for actions that need it, but
    renders large documents incrementally so UI pages do not pay the cost of
    inserting and highlighting multi-megabyte payloads at once.
    """

    def __init__(
        self,
        parent=None,
        *,
        virtual_threshold_chars: int = 250_000,
        initial_chars: int = 120_000,
        chunk_chars: int = 120_000,
        highlight_limit_chars: int = 260_000,
        highlighter_factory: Callable | None = None,
    ):
        super().__init__(parent)
        self._virtual_threshold_chars = virtual_threshold_chars
        self._initial_chars = initial_chars
        self._chunk_chars = chunk_chars
        self._highlight_limit_chars = highlight_limit_chars
        self._highlighter_factory = highlighter_factory
        self._highlighter: QSyntaxHighlighter | None = None

        self._full_text = ""
        self._virtual_mode = False
        self._loaded_chars = 0
        self._banner = ""
        self._loading_chunk = False

        self.verticalScrollBar().valueChanged.connect(self._maybe_load_more)
        self._ensure_highlighter()

    def set_highlighter_factory(self, factory: Callable | None) -> None:
        self._highlighter_factory = factory
        if self._highlighter is not None:
            self._highlighter.setDocument(None)
            self._highlighter = None
        self._ensure_highlighter()

    def set_virtual_text(self, text: str) -> None:
        self._full_text = text or ""
        self._virtual_mode = len(self._full_text) > self._virtual_threshold_chars
        self._loaded_chars = 0
        self._banner = ""

        if self._virtual_mode:
            self._banner = (
                f"[Large document: loading {len(self._full_text):,} characters "
                "incrementally. Scroll down to load more; full-text actions keep "
                "using the complete document.]\n\n"
            )
            self._load_more(reset=True)
            return

        self._ensure_highlighter()
        self.setPlainText(self._full_text)
        self._rehighlight_if_attached()

    def full_text(self) -> str:
        return self._full_text or self.toPlainText()

    def visible_text(self) -> str:
        return self.toPlainText()

    def is_virtualized(self) -> bool:
        return self._virtual_mode

    def loaded_chars(self) -> int:
        return self._loaded_chars if self._virtual_mode else len(self._full_text)

    def total_chars(self) -> int:
        return len(self._full_text)

    def load_all(self) -> None:
        if not self._virtual_mode:
            return
        self._loaded_chars = len(self._full_text)
        self.setPlainText(self._banner + self._full_text)
        self._update_highlighting()

    def _ensure_highlighter(self) -> None:
        if self._highlighter is None and self._highlighter_factory is not None:
            self._highlighter = self._highlighter_factory(self.document())
        elif self._highlighter is not None and self._highlighter.document() is not self.document():
            self._highlighter.setDocument(self.document())

    def _detach_highlighter(self) -> None:
        if self._highlighter is not None and self._highlighter.document() is not None:
            self._highlighter.setDocument(None)

    def _rehighlight_if_attached(self) -> None:
        if self._highlighter is not None and self._highlighter.document() is self.document():
            self._highlighter.rehighlight()

    def _update_highlighting(self) -> None:
        if self.loaded_chars() <= self._highlight_limit_chars:
            self._ensure_highlighter()
            self._rehighlight_if_attached()
        else:
            self._detach_highlighter()

    def _load_more(self, reset: bool = False) -> None:
        if not self._virtual_mode or self._loading_chunk:
            return
        if self._loaded_chars >= len(self._full_text):
            return

        self._loading_chunk = True
        try:
            old_scroll = self.verticalScrollBar().value()
            if reset:
                self._loaded_chars = min(self._initial_chars, len(self._full_text))
                self.setPlainText(self._banner + self._full_text[:self._loaded_chars])
                self.moveCursor(QTextCursor.MoveOperation.Start)
            else:
                start = self._loaded_chars
                self._loaded_chars = min(
                    self._loaded_chars + self._chunk_chars,
                    len(self._full_text),
                )
                cursor = self.textCursor()
                cursor.movePosition(QTextCursor.MoveOperation.End)
                cursor.insertText(self._full_text[start:self._loaded_chars])
                self.verticalScrollBar().setValue(old_scroll)
            self._update_highlighting()
        finally:
            self._loading_chunk = False

    def _maybe_load_more(self, value=None) -> None:
        if not self._virtual_mode:
            return
        bar = self.verticalScrollBar()
        if bar.maximum() - bar.value() < max(20, bar.pageStep()):
            QTimer.singleShot(0, self._load_more)
