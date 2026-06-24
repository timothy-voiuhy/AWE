"""
SessionManagerWidget — Named session factory for AWE.

A session stores a set of headers and optional URL params that can be
applied to requests in Repeater and Intruder with one click.
"""
from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QListWidget, QListWidgetItem, QPushButton, QLabel,
    QLineEdit, QTableWidget, QTableWidgetItem, QHeaderView,
    QFrame, QDialog, QTextEdit,
)

from gui.guiUtilities import parse_http_headers

_BTN = (
    "QPushButton{background:#313244;color:#CDD6F4;border:1px solid #45475A;"
    "border-radius:4px;padding:0 10px;min-height:24px;font-size:9px;}"
    "QPushButton:hover{background:#45475A;}"
)
_BTN_GREEN = (
    "QPushButton{background:#1E3A2F;color:#A6E3A1;border:1px solid #A6E3A1;"
    "border-radius:4px;padding:0 14px;min-height:24px;font-size:9px;font-weight:bold;}"
    "QPushButton:hover{background:#2A4A3F;}"
)
_BTN_RED = (
    "QPushButton{background:#3A1E1E;color:#F38BA8;border:1px solid #F38BA8;"
    "border-radius:4px;padding:0 10px;min-height:24px;font-size:9px;}"
    "QPushButton:hover{background:#4A2A2A;}"
)
_TABLE_SS = """
    QTableWidget {
        background:#11111B; color:#CDD6F4;
        gridline-color:#313244; border:1px solid #313244;
        font-size:9px; font-family:'Cascadia Code';
    }
    QTableWidget::item { padding:3px; }
    QTableWidget::item:selected { background:#313244; }
    QHeaderView::section {
        background:#181825; color:#6C7086;
        border:none; border-right:1px solid #313244;
        padding:3px 6px; font-size:9px;
    }
"""


class SessionManagerWidget(QWidget):
    """CRUD manager for named sessions (headers + URL params)."""

    sessions_changed = Signal()

    def __init__(self, repo=None, parent=None):
        super().__init__(parent)
        self._repo = repo
        self._current_id: str | None = None
        self._build_ui()
        self._load_list()

    # ── public ────────────────────────────────────────────────────────────────

    def sessions(self) -> list[dict]:
        """Return all sessions from DB (or empty list if no repo)."""
        if self._repo:
            try:
                return self._repo.list_auth_sessions()
            except Exception:
                pass
        return []

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # Toolbar
        tb = QHBoxLayout()
        tb.setContentsMargins(8, 6, 8, 6)
        tb.setSpacing(6)
        title = QLabel("⚿  Sessions")
        title.setStyleSheet("color:#FAB387; font-size:11px; font-weight:bold;")
        tb.addWidget(title)
        tb.addStretch()
        new_btn = QPushButton("+ New")
        new_btn.setFixedHeight(26)
        new_btn.setStyleSheet(_BTN_GREEN)
        new_btn.clicked.connect(self._new_session)
        tb.addWidget(new_btn)
        root.addLayout(tb)

        div = QFrame()
        div.setFrameShape(QFrame.HLine)
        div.setFixedHeight(1)
        div.setStyleSheet("background:#313244; border:none;")
        root.addWidget(div)

        splitter = QSplitter(Qt.Horizontal)
        splitter.setChildrenCollapsible(False)
        splitter.setStyleSheet(
            "QSplitter::handle{background:#313244;width:3px;}"
            "QSplitter::handle:hover{background:#6C7086;}"
        )

        # Left: list
        left = QWidget()
        left.setStyleSheet("background:#181825;")
        left_vb = QVBoxLayout(left)
        left_vb.setContentsMargins(4, 4, 4, 4)
        left_vb.setSpacing(4)

        self._list = QListWidget()
        self._list.setStyleSheet(
            "QListWidget{background:#11111B;border:none;color:#CDD6F4;}"
            "QListWidget::item{padding:5px 8px;font-size:10px;}"
            "QListWidget::item:selected{background:#313244;}"
            "QListWidget::item:hover{background:#1E2040;}"
        )
        self._list.setFont(QFont("Cascadia Code", 9))
        self._list.currentItemChanged.connect(self._on_session_selected)
        left_vb.addWidget(self._list, stretch=1)

        del_btn = QPushButton("Delete Selected")
        del_btn.setFixedHeight(24)
        del_btn.setStyleSheet(_BTN_RED)
        del_btn.clicked.connect(self._delete_session)
        left_vb.addWidget(del_btn)
        splitter.addWidget(left)

        # Right: editor
        right = QWidget()
        right.setStyleSheet("background:#1E1E2E;")
        right_vb = QVBoxLayout(right)
        right_vb.setContentsMargins(10, 8, 10, 8)
        right_vb.setSpacing(6)

        # Name field
        name_row = QHBoxLayout()
        name_lbl = QLabel("Name:")
        name_lbl.setStyleSheet("color:#6C7086; font-size:9px;")
        name_lbl.setFixedWidth(38)
        self._name_edit = QLineEdit()
        self._name_edit.setPlaceholderText("e.g. Admin, User, Guest…")
        self._name_edit.setStyleSheet(
            "QLineEdit{background:#11111B;color:#CDD6F4;border:1px solid #45475A;"
            "border-radius:4px;padding:3px 6px;font-size:10px;}"
            "QLineEdit:focus{border-color:#FAB387;}"
        )
        self._name_edit.setFont(QFont("Cascadia Code", 9))
        name_row.addWidget(name_lbl)
        name_row.addWidget(self._name_edit, stretch=1)
        right_vb.addLayout(name_row)

        # Headers section
        hdr_sec = QLabel("HEADERS")
        hdr_sec.setStyleSheet(
            "color:#FAB387; font-size:8px; letter-spacing:1.2px;"
            "border-bottom:1px solid #313244; padding-bottom:2px; margin-top:4px;"
        )
        right_vb.addWidget(hdr_sec)

        self._hdr_table = _EditableTable(["Header Name", "Header Value"])
        right_vb.addWidget(self._hdr_table, stretch=2)

        hdr_btns = QHBoxLayout()
        hdr_btns.setSpacing(4)
        add_h = QPushButton("+ Header")
        add_h.setFixedHeight(22)
        add_h.setStyleSheet(_BTN)
        add_h.clicked.connect(self._hdr_table.add_row)
        hdr_btns.addWidget(add_h)
        clip_btn = QPushButton("Import from Clipboard")
        clip_btn.setFixedHeight(22)
        clip_btn.setStyleSheet(_BTN)
        clip_btn.setToolTip("Import headers copied via Copy Headers → All Headers")
        clip_btn.clicked.connect(self._import_clipboard)
        hdr_btns.addWidget(clip_btn)
        cap_btn = QPushButton("Capture from Request")
        cap_btn.setFixedHeight(22)
        cap_btn.setStyleSheet(_BTN)
        cap_btn.clicked.connect(self._capture_request)
        hdr_btns.addWidget(cap_btn)
        hdr_btns.addStretch()
        right_vb.addLayout(hdr_btns)

        # Params section
        par_sec = QLabel("URL PARAMS")
        par_sec.setStyleSheet(
            "color:#89DCEB; font-size:8px; letter-spacing:1.2px;"
            "border-bottom:1px solid #313244; padding-bottom:2px; margin-top:4px;"
        )
        right_vb.addWidget(par_sec)

        self._par_table = _EditableTable(["Param Key", "Param Value"])
        right_vb.addWidget(self._par_table, stretch=1)

        par_btns = QHBoxLayout()
        add_p = QPushButton("+ Param")
        add_p.setFixedHeight(22)
        add_p.setStyleSheet(_BTN)
        add_p.clicked.connect(self._par_table.add_row)
        par_btns.addWidget(add_p)
        par_btns.addStretch()
        right_vb.addLayout(par_btns)

        # Save button
        save_btn = QPushButton("Save Session")
        save_btn.setFixedHeight(28)
        save_btn.setStyleSheet(_BTN_GREEN)
        save_btn.clicked.connect(self._save_session)
        right_vb.addWidget(save_btn)

        splitter.addWidget(right)
        splitter.setSizes([170, 520])
        root.addWidget(splitter, stretch=1)

    # ── data operations ───────────────────────────────────────────────────────

    def _load_list(self) -> None:
        self._list.clear()
        for sess in self.sessions():
            item = QListWidgetItem(sess.get("name", "Unnamed"))
            item.setData(Qt.UserRole, sess.get("id", ""))
            self._list.addItem(item)

    def _on_session_selected(self, item: QListWidgetItem | None) -> None:
        if not item:
            self._current_id = None
            return
        self._current_id = item.data(Qt.UserRole)
        if not self._current_id or not self._repo:
            return
        try:
            sess = self._repo.get_auth_session(self._current_id)
        except Exception:
            return
        if not sess:
            return
        self._name_edit.setText(sess.get("name", ""))
        self._hdr_table.set_rows(sess.get("headers") or [])
        self._par_table.set_rows(sess.get("params") or [])

    def _new_session(self) -> None:
        self._current_id = None
        self._list.clearSelection()
        self._name_edit.setText("New Session")
        self._hdr_table.set_rows([])
        self._par_table.set_rows([])
        self._name_edit.setFocus()
        self._name_edit.selectAll()

    def _save_session(self) -> None:
        name    = self._name_edit.text().strip() or "Unnamed"
        headers = self._hdr_table.get_rows()
        params  = self._par_table.get_rows()
        if not self._repo:
            return
        try:
            if self._current_id:
                self._repo.update_auth_session(self._current_id, name, headers, params)
                for i in range(self._list.count()):
                    if self._list.item(i).data(Qt.UserRole) == self._current_id:
                        self._list.item(i).setText(name)
                        break
            else:
                new_id = self._repo.create_auth_session(name, headers, params)
                self._current_id = new_id
                item = QListWidgetItem(name)
                item.setData(Qt.UserRole, new_id)
                self._list.addItem(item)
                self._list.setCurrentItem(item)
        except Exception:
            pass
        self.sessions_changed.emit()

    def _delete_session(self) -> None:
        if not self._current_id or not self._repo:
            return
        try:
            self._repo.delete_auth_session(self._current_id)
        except Exception:
            pass
        row = self._list.currentRow()
        self._list.takeItem(row)
        self._current_id = None
        self._name_edit.clear()
        self._hdr_table.set_rows([])
        self._par_table.set_rows([])
        self.sessions_changed.emit()

    def _import_clipboard(self) -> None:
        try:
            from gui.utilities.header_clipboard import _HEADER_CLIPBOARD
            headers = list(_HEADER_CLIPBOARD)
        except Exception:
            return
        if not headers:
            return
        existing = self._hdr_table.get_rows()
        existing_names = {r[0].lower() for r in existing if r and r[0]}
        for name, value in headers:
            if name.lower() not in existing_names:
                existing.append([name, value])
                existing_names.add(name.lower())
        self._hdr_table.set_rows(existing)

    def _capture_request(self) -> None:
        dlg = _CaptureDialog(parent=self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            hdrs = dlg.captured_headers()
            if not hdrs:
                return
            existing = self._hdr_table.get_rows()
            existing_names = {r[0].lower() for r in existing if r and r[0]}
            for name, value in hdrs:
                if name.lower() not in existing_names:
                    existing.append([name, value])
                    existing_names.add(name.lower())
            self._hdr_table.set_rows(existing)


class _EditableTable(QTableWidget):
    """Two-column editable table for headers / params."""

    def __init__(self, col_labels: list[str], parent=None):
        super().__init__(0, 2, parent)
        self.setHorizontalHeaderLabels(col_labels)
        self.setStyleSheet(_TABLE_SS)
        self.setFont(QFont("Cascadia Code", 9))
        self.horizontalHeader().setStretchLastSection(True)
        self.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.verticalHeader().setVisible(False)
        self.setSelectionBehavior(QTableWidget.SelectRows)
        self.setAlternatingRowColors(True)
        self.setStyleSheet(
            _TABLE_SS +
            "QTableWidget {alternate-background-color:#181825;}"
        )

    def add_row(self) -> None:
        r = self.rowCount()
        self.insertRow(r)
        self.setItem(r, 0, QTableWidgetItem(""))
        self.setItem(r, 1, QTableWidgetItem(""))
        self.editItem(self.item(r, 0))

    def set_rows(self, rows: list) -> None:
        self.setRowCount(0)
        for entry in rows:
            if isinstance(entry, (list, tuple)) and len(entry) >= 2:
                name, value = str(entry[0]), str(entry[1])
            elif isinstance(entry, dict):
                name  = str(entry.get("name", entry.get("key", "")))
                value = str(entry.get("value", ""))
            else:
                continue
            r = self.rowCount()
            self.insertRow(r)
            self.setItem(r, 0, QTableWidgetItem(name))
            self.setItem(r, 1, QTableWidgetItem(value))

    def get_rows(self) -> list[list[str]]:
        result = []
        for r in range(self.rowCount()):
            name  = (self.item(r, 0) or QTableWidgetItem()).text().strip()
            value = (self.item(r, 1) or QTableWidgetItem()).text().strip()
            if name:
                result.append([name, value])
        return result


class _CaptureDialog(QDialog):
    """Paste a raw HTTP request to extract its headers."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Capture Headers from Request")
        self.resize(540, 360)
        self.setStyleSheet(
            "QDialog{background:#1E1E2E;}"
            "QLabel{color:#6C7086;font-size:9px;background:transparent;}"
        )
        vb = QVBoxLayout(self)
        vb.setSpacing(8)
        vb.addWidget(QLabel(
            "Paste a raw HTTP request below — all headers will be extracted:"
        ))
        self._edit = QTextEdit()
        self._edit.setFont(QFont("Cascadia Code", 9))
        self._edit.setStyleSheet(
            "QTextEdit{background:#11111B;color:#CDD6F4;"
            "border:1px solid #45475A;border-radius:4px;padding:6px;}"
        )
        vb.addWidget(self._edit, stretch=1)

        btn_row = QHBoxLayout()
        btn_row.addStretch()
        ok_btn = QPushButton("Extract Headers")
        ok_btn.setStyleSheet(
            "QPushButton{background:#1E3A2F;color:#A6E3A1;border:1px solid #A6E3A1;"
            "border-radius:4px;padding:0 14px;min-height:24px;font-size:9px;}"
            "QPushButton:hover{background:#2A4A3F;}"
        )
        ok_btn.clicked.connect(self.accept)
        btn_row.addWidget(ok_btn)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setStyleSheet(_BTN)
        cancel_btn.clicked.connect(self.reject)
        btn_row.addWidget(cancel_btn)
        vb.addLayout(btn_row)

    def captured_headers(self) -> list[tuple[str, str]]:
        return parse_http_headers(self._edit.toPlainText())
