from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QScrollArea, QWidget,
    QCheckBox, QLabel, QPushButton,
)


_HEADER_CLIPBOARD: list[tuple[str, str]] = []


def parse_http_headers(text: str) -> list[tuple[str, str]]:
    """Return all headers from an HTTP message as [(name, value), …]."""
    lines = text.split('\n')
    hdrs: list[tuple[str, str]] = []
    for line in lines[1:]:          # skip request/status line
        if not line.strip():
            break
        if ':' in line:
            name, _, value = line.partition(':')
            hdrs.append((name.strip(), value.strip()))
    return hdrs


def set_header_clipboard(headers: list[tuple[str, str]]) -> None:
    global _HEADER_CLIPBOARD
    _HEADER_CLIPBOARD = headers


def copy_headers_from_text(text: str) -> int:
    """Copy ALL headers from *text* into the header clipboard. Returns count."""
    hdrs = parse_http_headers(text)
    set_header_clipboard(hdrs)
    return len(hdrs)


def paste_headers(text: str, mode: str) -> str | None:
    """
    Apply the header clipboard to *text*.
    mode='replace' → discard existing headers, insert copied ones.
    mode='add'     → keep existing headers, append any that aren't already
                     present (matched case-insensitively by name).
    Returns the modified HTTP message, or None when the clipboard is empty.
    """
    if not _HEADER_CLIPBOARD:
        return None

    lines   = text.split('\n')
    if not lines:
        return None

    req_line = lines[0]
    existing: list[str] = []
    body_idx = len(lines)

    for i, line in enumerate(lines[1:], 1):
        if not line.strip():
            body_idx = i
            break
        existing.append(line)

    body = '\n'.join(lines[body_idx:])

    if mode == 'replace':
        new_hdrs = [f"{n}: {v}" for n, v in _HEADER_CLIPBOARD]
    else:  # 'add'
        existing_names = {ln.partition(':')[0].strip().lower() for ln in existing}
        new_hdrs = list(existing)
        for n, v in _HEADER_CLIPBOARD:
            if n.lower() not in existing_names:
                new_hdrs.append(f"{n}: {v}")

    parts = [req_line] + new_hdrs + ['']
    if body.strip():
        parts.append(body)
    return '\n'.join(parts)


def has_copied_headers() -> bool:
    return bool(_HEADER_CLIPBOARD)


class HeaderSelectorDialog(QDialog):
    """Checkbox list that lets the user pick which headers to copy."""

    def __init__(self, headers: list[tuple[str, str]], parent=None):
        super().__init__(parent)
        self.setWindowTitle("Select Headers to Copy")
        self.setMinimumSize(520, 380)
        self._checks: list[tuple[QCheckBox, tuple[str, str]]] = []
        self._build_ui(headers)

    def selected_headers(self) -> list[tuple[str, str]]:
        return [hdr for cb, hdr in self._checks if cb.isChecked()]

    def _build_ui(self, headers: list[tuple[str, str]]) -> None:
        self.setStyleSheet(
            "QDialog{background:#1E1E2E;}"
            "QLabel{color:#6C7086;font-size:9px;background:transparent;}"
            "QCheckBox{color:#CDD6F4;font-family:'Cascadia Code';font-size:9px;spacing:6px;}"
            "QCheckBox::indicator{width:13px;height:13px;"
            "border:1px solid #45475A;border-radius:2px;background:#181825;}"
            "QCheckBox::indicator:checked{background:#89B4FA;border-color:#89B4FA;}"
            "QScrollArea{border:1px solid #313244;border-radius:4px;}"
            "QPushButton{background:#313244;color:#CDD6F4;border:1px solid #45475A;"
            "border-radius:4px;padding:0 12px;min-height:24px;font-size:9px;}"
            "QPushButton:hover{background:#45475A;}"
        )
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 10, 12, 10)
        root.setSpacing(8)

        root.addWidget(QLabel(
            f"{len(headers)} header{'s' if len(headers) != 1 else ''} found"
            " — uncheck any you don't want to copy:"
        ))

        scroll  = QScrollArea()
        scroll.setWidgetResizable(True)
        inner   = QWidget()
        inner.setStyleSheet("QWidget{background:#11111B;}")
        inner_vb = QVBoxLayout(inner)
        inner_vb.setContentsMargins(8, 8, 8, 8)
        inner_vb.setSpacing(3)

        for name, value in headers:
            label = f"{name}: {value[:120]}{'…' if len(value) > 120 else ''}"
            cb    = QCheckBox(label)
            cb.setChecked(True)
            cb.setToolTip(f"{name}: {value}")
            inner_vb.addWidget(cb)
            self._checks.append((cb, (name, value)))

        inner_vb.addStretch()
        scroll.setWidget(inner)
        root.addWidget(scroll, stretch=1)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(6)

        sel_btn = QPushButton("Select All")
        sel_btn.clicked.connect(lambda: [cb.setChecked(True)  for cb, _ in self._checks])
        btn_row.addWidget(sel_btn)

        desel_btn = QPushButton("Deselect All")
        desel_btn.clicked.connect(lambda: [cb.setChecked(False) for cb, _ in self._checks])
        btn_row.addWidget(desel_btn)

        btn_row.addStretch()

        ok_btn = QPushButton("Copy Selected")
        ok_btn.setStyleSheet(
            "QPushButton{background:#1E3A2F;color:#A6E3A1;border:1px solid #A6E3A1;"
            "border-radius:4px;padding:0 14px;min-height:24px;font-size:9px;}"
            "QPushButton:hover{background:#2A4A3F;}"
        )
        ok_btn.clicked.connect(self.accept)
        btn_row.addWidget(ok_btn)

        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        btn_row.addWidget(cancel_btn)

        root.addLayout(btn_row)

    def keyPressEvent(self, event) -> None:
        if event.key() == Qt.Key_Escape:
            self.reject()
        else:
            super().keyPressEvent(event)
