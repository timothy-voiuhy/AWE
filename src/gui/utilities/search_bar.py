from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QPalette, QTextCharFormat
from PySide6.QtWidgets import (
    QWidget, QHBoxLayout, QLineEdit, QLabel, QPushButton, QTextEdit,
)


class SearchBar(QWidget):
    """
    Inline find-bar that attaches to a QTextEdit.
    Place it in a layout directly below the editor (or tab widget).
    Toggle visibility with activate(); hide with Escape or the ✕ button.

    Usage:
        bar = SearchBar(parent)
        layout.addWidget(bar)
        bar.set_editor(some_qtext_edit)   # call again when active editor changes
        bar.activate()                    # show + focus (Ctrl+F handler)
    """

    _MATCH_BG  = "#F9E2AF"  # all matches — yellow
    _CUR_BG    = "#FAB387"  # current match — peach
    _MATCH_FG  = "#1E1E2E"

    def __init__(self, parent=None):
        super().__init__(parent)
        self._editor  = None
        self._matches: list[QTextCursor] = []
        self._idx     = -1
        self._build_ui()
        self.hide()

    # ── public ────────────────────────────────────────────────────────────────

    def set_editor(self, editor: QTextEdit) -> None:
        """Switch the target editor (e.g. when the user changes tab)."""
        if self._editor is editor:
            return
        if self._editor is not None:
            self._editor.setExtraSelections([])
        self._editor = editor
        if self.isVisible() and self._input.text():
            self._do_search(self._input.text())

    def activate(self) -> None:
        """Show the bar and put focus in the search field."""
        self.show()
        self._input.setFocus()
        self._input.selectAll()

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        self.setFixedHeight(30)
        self.setAutoFillBackground(True)
        pal = self.palette()
        pal.setColor(QPalette.ColorRole.Window, QColor("#181825"))
        self.setPalette(pal)

        lay = QHBoxLayout(self)
        lay.setContentsMargins(8, 3, 8, 3)
        lay.setSpacing(4)

        _inp_ss = (
            "QLineEdit{background:#1E1E2E;color:#CDD6F4;"
            "border:1px solid #45475A;border-radius:3px;padding:0 6px;}"
            "QLineEdit:focus{border-color:#89B4FA;}"
        )
        _btn_ss = (
            "QPushButton{background:transparent;color:#6C7086;border:none;"
            "padding:0 5px;font-size:11px;min-width:22px;min-height:22px;}"
            "QPushButton:hover{color:#CDD6F4;background:#313244;border-radius:3px;}"
            "QPushButton:disabled{color:#45475A;}"
        )
        _lbl_ss = "QLabel{color:#6C7086;font-size:9px;min-width:52px;}"

        self._input = QLineEdit()
        self._input.setPlaceholderText("Find…")
        self._input.setFixedHeight(22)
        self._input.setStyleSheet(_inp_ss)
        self._input.textChanged.connect(self._do_search)
        self._input.returnPressed.connect(self._next)
        lay.addWidget(self._input, stretch=1)

        self._count_lbl = QLabel("")
        self._count_lbl.setStyleSheet(_lbl_ss)
        lay.addWidget(self._count_lbl)

        prev_btn = QPushButton("▲")
        prev_btn.setToolTip("Previous (Shift+Enter)")
        prev_btn.setFixedSize(22, 22)
        prev_btn.setStyleSheet(_btn_ss)
        prev_btn.clicked.connect(self._prev)
        lay.addWidget(prev_btn)
        self._prev_btn = prev_btn

        next_btn = QPushButton("▼")
        next_btn.setToolTip("Next (Enter)")
        next_btn.setFixedSize(22, 22)
        next_btn.setStyleSheet(_btn_ss)
        next_btn.clicked.connect(self._next)
        lay.addWidget(next_btn)
        self._next_btn = next_btn

        close_btn = QPushButton("✕")
        close_btn.setToolTip("Close (Esc)")
        close_btn.setFixedSize(22, 22)
        close_btn.setStyleSheet(_btn_ss)
        close_btn.clicked.connect(self._close)
        lay.addWidget(close_btn)

    # ── search logic ──────────────────────────────────────────────────────────

    def _do_search(self, text: str) -> None:
        if self._editor is None:
            return
        self._matches.clear()
        self._idx = -1

        if not text:
            self._editor.setExtraSelections([])
            self._update_count()
            return

        from PySide6.QtGui import QTextCursor
        doc    = self._editor.document()
        cursor = QTextCursor(doc)
        while True:
            cursor = doc.find(text, cursor)
            if cursor.isNull():
                break
            self._matches.append(QTextCursor(cursor))

        if self._matches:
            self._idx = 0

        self._rebuild_selections()
        self._update_count()

    def _rebuild_selections(self) -> None:
        """Repaint all highlights; current match gets the peach colour."""
        if self._editor is None:
            return

        match_fmt = QTextCharFormat()
        match_fmt.setBackground(QColor(self._MATCH_BG))
        match_fmt.setForeground(QColor(self._MATCH_FG))

        cur_fmt = QTextCharFormat()
        cur_fmt.setBackground(QColor(self._CUR_BG))
        cur_fmt.setForeground(QColor(self._MATCH_FG))

        sels = []
        for i, c in enumerate(self._matches):
            sel        = QTextEdit.ExtraSelection()
            sel.cursor = c
            sel.format = cur_fmt if i == self._idx else match_fmt
            sels.append(sel)

        self._editor.setExtraSelections(sels)

        if 0 <= self._idx < len(self._matches):
            self._editor.setTextCursor(self._matches[self._idx])
            self._editor.ensureCursorVisible()

    def _next(self) -> None:
        if not self._matches:
            return
        self._idx = (self._idx + 1) % len(self._matches)
        self._rebuild_selections()
        self._update_count()

    def _prev(self) -> None:
        if not self._matches:
            return
        self._idx = (self._idx - 1) % len(self._matches)
        self._rebuild_selections()
        self._update_count()

    def _update_count(self) -> None:
        n = len(self._matches)
        if not self._input.text():
            self._count_lbl.setText("")
        elif n == 0:
            self._count_lbl.setStyleSheet("QLabel{color:#F38BA8;font-size:9px;min-width:52px;}")
            self._count_lbl.setText("no results")
        else:
            self._count_lbl.setStyleSheet("QLabel{color:#6C7086;font-size:9px;min-width:52px;}")
            self._count_lbl.setText(f"{self._idx + 1} / {n}")
        nav_ok = bool(self._matches)
        self._prev_btn.setEnabled(nav_ok)
        self._next_btn.setEnabled(nav_ok)

    def _close(self) -> None:
        if self._editor is not None:
            self._editor.setExtraSelections([])
        self._matches.clear()
        self._idx = -1
        self._input.clear()
        self.hide()
        if self._editor is not None:
            self._editor.setFocus()

    def keyPressEvent(self, event) -> None:
        if event.key() == Qt.Key_Escape:
            self._close()
        elif event.key() in (Qt.Key_Return, Qt.Key_Enter):
            if event.modifiers() & Qt.ShiftModifier:
                self._prev()
            else:
                self._next()
        else:
            super().keyPressEvent(event)
