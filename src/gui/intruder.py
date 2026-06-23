"""
IntruderPage — Burp Suite-style HTTP fuzzer embedded in the Target nav bar.

Attack modes
────────────
  Sniper       One payload set, cycles through each §position§ one at a time.
  Battering Ram  One payload set, same payload inserted into every position.
  Pitchfork    N payload sets (one per position), iterated in lock-step (zip).
  Cluster Bomb N payload sets, every combination (itertools.product).

Position syntax: wrap any text in the request with §markers§.
  e.g.  GET /search?q=§hello§&page=§1§ HTTP/1.1

Payloads can come from:
  • Paste / Type  — one entry per line in a QTextEdit
  • Load from File — any .txt wordlist
  • Built-in Wordlist — bundled lists in resources/wordlists/

Results are persisted to MongoDB (intruder_runs + intruder_results collections)
and displayed in a live-updated, sortable QTableView with request/response preview.

Public API used by callers:
    page.load_request(request_text)   # pre-populate from History / SiteMap / Repeater
"""
from __future__ import annotations

import itertools
import logging
import re
from datetime import datetime, timezone
from pathlib import Path

import httpx
from PySide6.QtCore import (
    Qt, QRegularExpression, QSortFilterProxyModel, QThread, QTimer, Signal,
)
from PySide6.QtGui import (
    QColor, QFont, QStandardItem, QStandardItemModel, QTextCharFormat, QTextCursor,
)
from PySide6.QtWidgets import (
    QAbstractItemView, QComboBox, QFileDialog, QFormLayout, QFrame,
    QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMessageBox, QProgressBar,
    QPushButton, QSpinBox, QSplitter, QStackedWidget, QTabWidget,
    QTableView, QTextEdit, QVBoxLayout, QWidget, QCheckBox,
)

from config.config import RUNDIR
from gui.guiUtilities import SyntaxHighlighter
from gui.repeater import _CodeEdit, _PaneWrapper, _parse_raw_request

log = logging.getLogger(__name__)

# ── constants ─────────────────────────────────────────────────────────────────

POSITION_RE = re.compile(r'§([^§]*)§')
_WORDLISTS_DIR = Path(RUNDIR) / "resources" / "wordlists"

_ATTACK_MODES = ["Sniper", "Battering Ram", "Pitchfork", "Cluster Bomb"]

_STATUS_COLORS = {
    2: "#A6E3A1",  # 2xx green
    3: "#89B4FA",  # 3xx blue
    4: "#F9E2AF",  # 4xx yellow
    5: "#F38BA8",  # 5xx red
}

_SKIP_HEADERS = frozenset({
    "content-length", "transfer-encoding", "connection",
    "proxy-connection", "keep-alive", "te", "trailers",
})


# ── position utilities ────────────────────────────────────────────────────────

def _split_positions(template: str) -> tuple[list[str], list[str]]:
    """Split template by §...§ markers.

    Returns (parts, originals) where:
      parts      — static text segments, len = len(originals) + 1
      originals  — the original placeholder values between each § pair
    """
    parts = POSITION_RE.split(template)
    # split() with a capturing group interleaves static and captured; extract evens/odds
    static   = parts[0::2]
    captured = parts[1::2]
    return static, captured


def _apply_payloads(parts: list[str], payload_values: list[str]) -> str:
    """Interleave static parts with payload values to reconstruct the request."""
    result = []
    for i, static in enumerate(parts[:-1]):
        result.append(static)
        if i < len(payload_values):
            result.append(payload_values[i])
    result.append(parts[-1])
    return "".join(result)


def _auto_mark_positions(request_text: str) -> str:
    """Wrap query-param and form-body values in §§ markers."""
    lines = request_text.replace('\r\n', '\n').split('\n')
    if not lines:
        return request_text

    # First line: METHOD URL [HTTP/version]
    first_parts = lines[0].split(' ', 2)
    if len(first_parts) >= 2:
        url = first_parts[1]
        if '?' in url:
            path, _, qs = url.partition('?')
            marked_qs = re.sub(r'=([^&\s#]+)', r'=§\1§', qs)
            url = f"{path}?{marked_qs}"
            lines[0] = ' '.join([first_parts[0], url] + ([first_parts[2]] if len(first_parts) > 2 else []))

    # Find headers block end → body start
    sep_idx = None
    for i in range(1, len(lines)):
        if lines[i].strip() == '':
            sep_idx = i
            break

    if sep_idx is not None:
        # Detect content-type
        content_type = ''
        for line in lines[1:sep_idx]:
            if ':' in line:
                k, _, v = line.partition(':')
                if k.strip().lower() == 'content-type':
                    content_type = v.strip().lower()

        body_lines = lines[sep_idx + 1:]
        body = '\n'.join(body_lines)

        if body.strip() and 'application/x-www-form-urlencoded' in content_type:
            marked_body = re.sub(r'=([^&\s]+)', r'=§\1§', body)
            lines = lines[:sep_idx + 1] + [marked_body]

    return '\n'.join(lines)


def _generate_requests(
    mode: str,
    template: str,
    payload_sets: list[list[str]],
) -> list[tuple[list[str], str]]:
    """Generate (payloads_used, request_text) for every attack request.

    mode — "sniper" | "battering_ram" | "pitchfork" | "cluster_bomb"
    """
    parts, originals = _split_positions(template)
    n = len(originals)
    if n == 0:
        return []
    results: list[tuple[list[str], str]] = []

    if mode == "sniper":
        payloads = payload_sets[0] if payload_sets else []
        for pos_idx in range(n):
            for payload in payloads:
                vals = list(originals)
                vals[pos_idx] = payload
                results.append(([payload], _apply_payloads(parts, vals)))

    elif mode == "battering_ram":
        payloads = payload_sets[0] if payload_sets else []
        for payload in payloads:
            vals = [payload] * n
            results.append(([payload], _apply_payloads(parts, vals)))

    elif mode == "pitchfork":
        sets = [payload_sets[i] if i < len(payload_sets) else [] for i in range(n)]
        for tup in zip(*sets):
            vals = list(tup)
            results.append((vals, _apply_payloads(parts, vals)))

    elif mode == "cluster_bomb":
        sets = [payload_sets[i] if i < len(payload_sets) else [""] for i in range(n)]
        for tup in itertools.product(*sets):
            vals = list(tup)
            results.append((vals, _apply_payloads(parts, vals)))

    return results


def _fmt_response(r: httpx.Response) -> str:
    """Serialize an httpx.Response to raw HTTP text."""
    version = r.http_version or "HTTP/1.1"
    lines = [f"{version} {r.status_code} {r.reason_phrase}"]
    for k, v in r.headers.multi_items():
        lines.append(f"{k}: {v}")
    lines.append("")
    lines.append(r.content.decode("utf-8", errors="replace"))
    return "\n".join(lines)


# ── syntax highlighter with §§ support ───────────────────────────────────────

class _PositionHighlighter(SyntaxHighlighter):
    """Extends SyntaxHighlighter with an amber rule for §...§ position markers."""

    def __init__(self, parent=None):
        super().__init__(parent)
        amber = QTextCharFormat()
        amber.setForeground(QColor("#F9E2AF"))
        amber.setBackground(QColor("#2A2800"))
        amber.setFontWeight(QFont.Weight.Bold)
        self._rules.append((QRegularExpression(r'§[^§]*§'), amber, 0))


# ── position editor ───────────────────────────────────────────────────────────

class _PositionEditor(QWidget):
    """Raw HTTP request editor with §§ position-marking controls."""

    textChanged = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        vb = QVBoxLayout(self)
        vb.setContentsMargins(0, 0, 0, 0)
        vb.setSpacing(2)

        # Button row
        btn_row = QHBoxLayout()
        btn_row.setContentsMargins(0, 0, 0, 0)
        btn_row.setSpacing(4)
        _SS = (
            "QPushButton{background:#252540;color:#9399B2;border:1px solid #313244;"
            "border-radius:3px;font-size:9px;padding:0 10px;min-height:20px;max-height:20px;}"
            "QPushButton:hover{background:#313244;color:#CDD6F4;border-color:#6C7086;}"
        )
        auto_btn  = QPushButton("Auto §")
        auto_btn.setStyleSheet(_SS)
        auto_btn.setToolTip("Auto-detect parameter values and wrap them in § markers")
        auto_btn.clicked.connect(self._auto_mark)
        btn_row.addWidget(auto_btn)

        add_btn = QPushButton("Add §")
        add_btn.setStyleSheet(_SS)
        add_btn.setToolTip("Wrap the current selection in § markers")
        add_btn.clicked.connect(self._add_marks)
        btn_row.addWidget(add_btn)

        clear_btn = QPushButton("Clear §")
        clear_btn.setStyleSheet(_SS)
        clear_btn.setToolTip("Remove all § markers from the request")
        clear_btn.clicked.connect(self._clear_marks)
        btn_row.addWidget(clear_btn)

        btn_row.addStretch()
        self._pos_count_lbl = QLabel("0 positions")
        self._pos_count_lbl.setStyleSheet("color:#6C7086; font-size:9px;")
        btn_row.addWidget(self._pos_count_lbl)
        vb.addLayout(btn_row)

        # Code editor — detach its built-in SyntaxHighlighter then attach ours,
        # which inherits all HTTP/JSON rules and adds the §§ amber rule.
        self._edit = _CodeEdit(read_only=False)
        self._edit._hl.setDocument(None)   # detach the default highlighter
        self._hl = _PositionHighlighter(self._edit.document())
        self._edit.textChanged.connect(self._on_text_changed)
        vb.addWidget(self._edit, stretch=1)

    def toPlainText(self) -> str:
        return self._edit.toPlainText()

    def setPlainText(self, text: str) -> None:
        self._edit.setPlainText(text)

    def position_count(self) -> int:
        return len(POSITION_RE.findall(self._edit.toPlainText()))

    def _on_text_changed(self):
        n = self.position_count()
        self._pos_count_lbl.setText(f"{n} position{'s' if n != 1 else ''}")
        self.textChanged.emit()

    def _auto_mark(self):
        text = self._edit.toPlainText()
        if not text.strip():
            return
        marked = _auto_mark_positions(text)
        self._edit.setPlainText(marked)

    def _add_marks(self):
        cursor = self._edit.textCursor()
        if cursor.hasSelection():
            selected = cursor.selectedText()
            cursor.insertText(f'§{selected}§')

    def _clear_marks(self):
        text = self._edit.toPlainText().replace('§', '')
        self._edit.setPlainText(text)


# ── payload set editor ────────────────────────────────────────────────────────

class _PayloadSetEditor(QWidget):
    """Editor for one payload set — paste, file, or built-in list."""

    def __init__(self, set_num: int = 1, parent=None):
        super().__init__(parent)
        self._set_num = set_num
        self._file_payloads: list[str] = []
        self._builtin_payloads: list[str] = []

        vb = QVBoxLayout(self)
        vb.setContentsMargins(4, 4, 4, 4)
        vb.setSpacing(6)

        # Source selector
        src_row = QHBoxLayout()
        src_row.addWidget(QLabel("Source:"))
        self._src_combo = QComboBox()
        self._src_combo.addItems(["Paste / Type", "Load from File", "Built-in Wordlist"])
        self._src_combo.currentIndexChanged.connect(self._on_source_changed)
        src_row.addWidget(self._src_combo, stretch=1)
        vb.addLayout(src_row)

        # Stacked pages
        self._stack = QStackedWidget()

        # ── Page 0: paste ─────────────────────────────────────────────────────
        paste_page = QWidget()
        paste_vb = QVBoxLayout(paste_page)
        paste_vb.setContentsMargins(0, 0, 0, 0)
        hint = QLabel("One payload per line:")
        hint.setStyleSheet("color:#6C7086; font-size:9px;")
        paste_vb.addWidget(hint)
        self._paste_edit = QTextEdit()
        self._paste_edit.setFont(QFont("Cascadia Code", 9))
        self._paste_edit.setPlaceholderText("admin\npassword\n123456\n…")
        self._paste_edit.setStyleSheet(
            "QTextEdit{background:#11111B; color:#CDD6F4; border:1px solid #313244; "
            "border-radius:4px; padding:6px;}")
        self._paste_edit.textChanged.connect(self._update_count)
        paste_vb.addWidget(self._paste_edit, stretch=1)
        self._stack.addWidget(paste_page)

        # ── Page 1: file ──────────────────────────────────────────────────────
        file_page = QWidget()
        file_vb = QVBoxLayout(file_page)
        file_vb.setContentsMargins(0, 0, 0, 0)
        self._file_lbl = QLabel("No file selected")
        self._file_lbl.setStyleSheet("color:#6C7086; font-size:9px;")
        file_vb.addWidget(self._file_lbl)
        browse_btn = QPushButton("Browse…")
        browse_btn.clicked.connect(self._browse_file)
        file_vb.addWidget(browse_btn)
        file_vb.addStretch()
        self._stack.addWidget(file_page)

        # ── Page 2: built-in ─────────────────────────────────────────────────
        builtin_page = QWidget()
        builtin_vb = QVBoxLayout(builtin_page)
        builtin_vb.setContentsMargins(0, 0, 0, 0)
        self._builtin_combo = QComboBox()
        self._builtin_files: dict[str, Path] = {}
        for p in sorted(_WORDLISTS_DIR.glob("*.txt")):
            self._builtin_files[p.stem] = p
            self._builtin_combo.addItem(p.stem)
        self._builtin_combo.currentIndexChanged.connect(self._load_builtin)
        builtin_vb.addWidget(self._builtin_combo)
        self._builtin_count_lbl = QLabel("")
        self._builtin_count_lbl.setStyleSheet("color:#6C7086; font-size:9px;")
        builtin_vb.addWidget(self._builtin_count_lbl)
        builtin_vb.addStretch()
        if self._builtin_combo.count():
            self._load_builtin()
        self._stack.addWidget(builtin_page)

        vb.addWidget(self._stack, stretch=1)

        # Count label
        self._count_lbl = QLabel("0 payloads")
        self._count_lbl.setStyleSheet("color:#6C7086; font-size:9px;")
        vb.addWidget(self._count_lbl)

    def get_payloads(self) -> list[str]:
        idx = self._src_combo.currentIndex()
        if idx == 0:
            return [l for l in self._paste_edit.toPlainText().splitlines() if l.strip()]
        elif idx == 1:
            return self._file_payloads
        else:
            return self._builtin_payloads

    def _on_source_changed(self, idx: int):
        self._stack.setCurrentIndex(idx)
        self._update_count()

    def _update_count(self):
        n = len(self.get_payloads())
        self._count_lbl.setText(f"{n} payload{'s' if n != 1 else ''}")

    def _browse_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Load Payload File", "", "Text files (*.txt);;All files (*)"
        )
        if path:
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    self._file_payloads = [l.rstrip('\n') for l in fh if l.strip()]
                self._file_lbl.setText(f"{Path(path).name}  ({len(self._file_payloads)} lines)")
                self._update_count()
            except Exception as exc:
                QMessageBox.warning(self, "Load Error", str(exc))

    def _load_builtin(self):
        stem = self._builtin_combo.currentText()
        path = self._builtin_files.get(stem)
        if not path:
            return
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                self._builtin_payloads = [l.rstrip('\n') for l in fh if l.strip()]
            self._builtin_count_lbl.setText(f"{len(self._builtin_payloads)} entries")
            self._update_count()
        except Exception:
            pass


# ── attack worker ─────────────────────────────────────────────────────────────

class _AttackWorker(QThread):
    result   = Signal(dict)     # one dict per completed request
    progress = Signal(int, int) # (done, total)
    finished = Signal()

    def __init__(
        self,
        requests: list[tuple[list[str], str]],
        proxy_port: int,
        run_id: str,
        repo: "IntruderRepository",
        timeout: float = 30.0,
        follow_redirects: bool = False,
    ):
        super().__init__()
        self._requests        = requests
        self._proxy_port      = proxy_port
        self._run_id          = run_id
        self._repo            = repo
        self._timeout         = timeout
        self._follow_redirects = follow_redirects
        self._stop            = False

    def stop(self):
        self._stop = True

    def run(self):
        total = len(self._requests)
        try:
            with httpx.Client(
                proxy=f"http://127.0.0.1:{self._proxy_port}",
                verify=False,
                follow_redirects=self._follow_redirects,
                timeout=self._timeout,
            ) as client:
                for idx, (payloads, req_text) in enumerate(self._requests):
                    if self._stop:
                        break
                    method, url, headers, body = _parse_raw_request(req_text)
                    clean_headers = {k: v for k, v in headers.items()
                                     if k.lower() not in _SKIP_HEADERS}
                    t0 = datetime.now(timezone.utc)
                    try:
                        r = client.request(
                            method, url, headers=clean_headers, content=body
                        )
                        elapsed_ms = round(
                            (datetime.now(timezone.utc) - t0).total_seconds() * 1000
                        )
                        doc: dict = {
                            "seq":           idx + 1,
                            "payloads":      payloads,
                            "status":        r.status_code,
                            "length":        len(r.content),
                            "elapsed_ms":    elapsed_ms,
                            "error":         "",
                            "request_text":  req_text,
                            "response_text": _fmt_response(r),
                        }
                    except Exception as exc:
                        elapsed_ms = round(
                            (datetime.now(timezone.utc) - t0).total_seconds() * 1000
                        )
                        doc = {
                            "seq":           idx + 1,
                            "payloads":      payloads,
                            "status":        0,
                            "length":        0,
                            "elapsed_ms":    elapsed_ms,
                            "error":         str(exc)[:200],
                            "request_text":  req_text,
                            "response_text": "",
                        }
                    try:
                        self._repo.add_result(self._run_id, doc)
                    except Exception:
                        pass
                    self.result.emit(doc)
                    self.progress.emit(idx + 1, total)
        except Exception as exc:
            log.error("IntruderWorker crashed: %s", exc)
        self.finished.emit()


# ── MongoDB repository ────────────────────────────────────────────────────────

class IntruderRepository:
    def __init__(self, project_dir: str):
        from database.mongo import get_db
        self._db = get_db(project_dir)
        self._ensure_indexes()

    def _ensure_indexes(self):
        try:
            self._db.intruder_runs.create_index("project_dir")
            self._db.intruder_runs.create_index("created_at")
            self._db.intruder_results.create_index("run_id")
            self._db.intruder_results.create_index([("run_id", 1), ("seq", 1)])
        except Exception:
            pass

    def create_run(
        self,
        mode: str,
        template: str,
        payload_sets: list[list[str]],
        project_dir: str,
        total_requests: int = 0,
    ) -> str:
        doc = {
            "project_dir":     project_dir,
            "mode":            mode,
            "template":        template,
            "payload_sets":    payload_sets,
            "status":          "running",
            "created_at":      datetime.now(timezone.utc).isoformat(),
            "completed_at":    None,
            "total_requests":  total_requests,
        }
        from bson import ObjectId
        result = self._db.intruder_runs.insert_one(doc)
        return str(result.inserted_id)

    def update_run(self, run_id: str, status: str, total_requests: int = 0):
        try:
            from bson import ObjectId
            self._db.intruder_runs.update_one(
                {"_id": ObjectId(run_id)},
                {"$set": {
                    "status":          status,
                    "completed_at":    datetime.now(timezone.utc).isoformat(),
                    "total_requests":  total_requests,
                }},
            )
        except Exception as exc:
            log.warning("IntruderRepository.update_run: %s", exc)

    def add_result(self, run_id: str, doc: dict):
        payload = {"run_id": run_id}
        payload.update(doc)
        self._db.intruder_results.insert_one(payload)

    def list_runs(self, project_dir: str, limit: int = 50) -> list[dict]:
        try:
            cursor = self._db.intruder_runs.find(
                {"project_dir": project_dir},
                sort=[("created_at", -1)],
                limit=limit,
            )
            return [_flatten_doc(d) for d in cursor]
        except Exception:
            return []

    def get_results(self, run_id: str) -> list[dict]:
        try:
            return [
                _flatten_doc(d)
                for d in self._db.intruder_results.find(
                    {"run_id": run_id}, sort=[("seq", 1)]
                )
            ]
        except Exception:
            return []

    def delete_run(self, run_id: str):
        try:
            from bson import ObjectId
            self._db.intruder_results.delete_many({"run_id": run_id})
            self._db.intruder_runs.delete_one({"_id": ObjectId(run_id)})
        except Exception as exc:
            log.warning("IntruderRepository.delete_run: %s", exc)


def _flatten_doc(doc: dict) -> dict:
    out = dict(doc)
    _id = out.pop("_id", None)
    if _id is not None:
        out["id"] = str(_id)
    return out


# ── main intruder page ────────────────────────────────────────────────────────

class IntruderPage(QWidget):
    """Per-target Intruder page.  Added to the Target nav bar at index 10."""

    send_to_repeater = Signal(str)  # emit request text to open in Repeater

    def __init__(self, proxy_port: int = 8080, project_dir: str = "", parent=None):
        super().__init__(parent)
        self._proxy_port   = proxy_port
        self._project_dir  = project_dir
        self._worker: _AttackWorker | None = None
        self._run_id: str = ""
        self._current_results: dict[int, dict] = {}  # seq → result doc
        self._payload_editors: list[_PayloadSetEditor] = []
        self._debounce = QTimer(self)
        self._debounce.setSingleShot(True)
        self._debounce.setInterval(400)
        self._debounce.timeout.connect(self._sync_payload_sets)

        try:
            self._repo = IntruderRepository(project_dir)
        except Exception as exc:
            log.warning("IntruderRepository unavailable: %s", exc)
            self._repo = None  # type: ignore[assignment]

        self._build_ui()

    # ── public API ────────────────────────────────────────────────────────────

    def load_request(self, request_text: str) -> None:
        """Pre-populate the position editor and navigate to Positions tab."""
        self._pos_editor.setPlainText(request_text)
        self._attack_tabs.setCurrentIndex(0)

    # ── UI construction ───────────────────────────────────────────────────────

    def _build_ui(self):
        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        splitter = QSplitter(Qt.Horizontal)
        splitter.setChildrenCollapsible(False)
        splitter.setStyleSheet(
            "QSplitter::handle{background:#313244;width:3px;}"
            "QSplitter::handle:hover{background:#6C7086;}"
        )
        splitter.addWidget(self._build_config_panel())
        splitter.addWidget(self._build_results_panel())
        splitter.setSizes([430, 800])
        root.addWidget(splitter)

    def _build_config_panel(self) -> QWidget:
        w = QWidget()
        vb = QVBoxLayout(w)
        vb.setContentsMargins(0, 0, 0, 0)
        vb.setSpacing(0)

        # ── toolbar ───────────────────────────────────────────────────────────
        tb = QHBoxLayout()
        tb.setContentsMargins(8, 6, 8, 6)
        tb.setSpacing(6)

        title = QLabel("⊛  Intruder")
        title.setStyleSheet("color:#EE99A0; font-size:11px; font-weight:bold;")
        tb.addWidget(title)
        tb.addStretch()

        self._start_btn = QPushButton("▶  Start Attack")
        self._start_btn.setFixedHeight(26)
        self._start_btn.setStyleSheet(
            "QPushButton{background:#1E3A2F;color:#A6E3A1;border:1px solid #A6E3A1;"
            "border-radius:4px;padding:0 14px;font-size:10px;font-weight:bold;}"
            "QPushButton:hover{background:#2A4A3F;}"
            "QPushButton:disabled{background:#181825;color:#45475A;border-color:#313244;}"
        )
        self._start_btn.clicked.connect(self._start_attack)
        tb.addWidget(self._start_btn)

        self._stop_btn = QPushButton("■  Stop")
        self._stop_btn.setFixedHeight(26)
        self._stop_btn.setStyleSheet(
            "QPushButton{background:#3A1E1E;color:#F38BA8;border:1px solid #F38BA8;"
            "border-radius:4px;padding:0 14px;font-size:10px;font-weight:bold;}"
            "QPushButton:hover{background:#4A2A2A;}"
            "QPushButton:disabled{background:#181825;color:#45475A;border-color:#313244;}"
        )
        self._stop_btn.setEnabled(False)
        self._stop_btn.clicked.connect(self._stop_attack)
        tb.addWidget(self._stop_btn)
        vb.addLayout(tb)

        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setFixedHeight(1)
        sep.setStyleSheet("background:#313244; border:none;")
        vb.addWidget(sep)

        # ── tab widget ────────────────────────────────────────────────────────
        self._attack_tabs = QTabWidget()
        self._attack_tabs.setStyleSheet(
            "QTabBar::tab{background:#181825;color:#6C7086;padding:5px 14px;"
            "border:none;border-radius:4px 4px 0 0;}"
            "QTabBar::tab:selected{background:#1E1E2E;color:#CDD6F4;"
            "border-bottom:2px solid #EE99A0;}"
            "QTabBar::tab:hover{background:#313244;color:#CDD6F4;}"
            "QTabWidget::pane{border:none;border-top:1px solid #313244;}"
        )
        self._attack_tabs.addTab(self._build_positions_tab(), "Positions")
        self._attack_tabs.addTab(self._build_payloads_tab(),  "Payloads")
        self._attack_tabs.addTab(self._build_options_tab(),   "Options")
        vb.addWidget(self._attack_tabs, stretch=1)
        return w

    def _build_positions_tab(self) -> QWidget:
        w = QWidget()
        vb = QVBoxLayout(w)
        vb.setContentsMargins(6, 6, 6, 6)
        vb.setSpacing(6)

        mode_row = QHBoxLayout()
        mode_row.addWidget(QLabel("Attack mode:"))
        self._mode_combo = QComboBox()
        self._mode_combo.addItems(_ATTACK_MODES)
        self._mode_combo.currentIndexChanged.connect(self._on_mode_changed)
        mode_row.addWidget(self._mode_combo, stretch=1)
        vb.addLayout(mode_row)

        sep = QFrame(); sep.setFrameShape(QFrame.HLine)
        sep.setStyleSheet("background:#313244; border:none;"); sep.setFixedHeight(1)
        vb.addWidget(sep)

        self._pos_editor = _PositionEditor()
        self._pos_editor.textChanged.connect(self._debounce.start)
        vb.addWidget(self._pos_editor, stretch=1)
        return w

    def _build_payloads_tab(self) -> QWidget:
        w = QWidget()
        vb = QVBoxLayout(w)
        vb.setContentsMargins(6, 6, 6, 6)
        vb.setSpacing(6)

        set_row = QHBoxLayout()
        set_row.addWidget(QLabel("Payload set:"))
        self._set_combo = QComboBox()
        self._set_combo.currentIndexChanged.connect(self._on_set_selected)
        set_row.addWidget(self._set_combo, stretch=1)
        vb.addLayout(set_row)

        sep = QFrame(); sep.setFrameShape(QFrame.HLine)
        sep.setStyleSheet("background:#313244; border:none;"); sep.setFixedHeight(1)
        vb.addWidget(sep)

        self._editor_stack = QStackedWidget()
        vb.addWidget(self._editor_stack, stretch=1)

        # Ensure at least 1 editor
        self._update_payload_sets(1)
        return w

    def _build_options_tab(self) -> QWidget:
        w = QWidget()
        vb = QVBoxLayout(w)
        vb.setContentsMargins(10, 10, 10, 10)
        vb.setSpacing(10)

        form = QFormLayout()
        form.setSpacing(8)

        self._threads_spin = QSpinBox()
        self._threads_spin.setRange(1, 50)
        self._threads_spin.setValue(10)
        form.addRow("Threads:", self._threads_spin)

        self._timeout_spin = QSpinBox()
        self._timeout_spin.setRange(5, 120)
        self._timeout_spin.setValue(30)
        self._timeout_spin.setSuffix(" s")
        form.addRow("Timeout:", self._timeout_spin)

        self._follow_chk = QCheckBox("Follow redirects")
        form.addRow("", self._follow_chk)

        vb.addLayout(form)
        vb.addStretch()
        return w

    def _build_results_panel(self) -> QWidget:
        w = QWidget()
        vb = QVBoxLayout(w)
        vb.setContentsMargins(0, 0, 0, 0)
        vb.setSpacing(0)

        # Progress bar (hidden until attack starts)
        self._progress_bar = QProgressBar()
        self._progress_bar.setRange(0, 100)
        self._progress_bar.setFixedHeight(4)
        self._progress_bar.setTextVisible(False)
        self._progress_bar.setStyleSheet(
            "QProgressBar{background:#181825;border:none;border-radius:0;}"
            "QProgressBar::chunk{background:#EE99A0;border-radius:0;}"
        )
        self._progress_bar.setVisible(False)
        vb.addWidget(self._progress_bar)

        splitter = QSplitter(Qt.Vertical)
        splitter.setChildrenCollapsible(False)
        splitter.setStyleSheet("QSplitter::handle{background:#313244;height:4px;}")

        # Top: results table
        top_w = QWidget()
        top_vb = QVBoxLayout(top_w)
        top_vb.setContentsMargins(4, 4, 4, 4)
        top_vb.setSpacing(4)

        filter_row = QHBoxLayout()
        filter_row.setSpacing(6)

        self._status_lbl = QLabel("Ready")
        self._status_lbl.setStyleSheet("color:#6C7086; font-size:9px;")
        filter_row.addWidget(self._status_lbl)
        filter_row.addStretch()

        filter_row.addWidget(QLabel("Filter:"))
        self._filter_edit = QLineEdit()
        self._filter_edit.setPlaceholderText("search results…")
        self._filter_edit.setFixedWidth(180)
        self._filter_edit.textChanged.connect(self._on_filter_changed)
        filter_row.addWidget(self._filter_edit)

        export_btn = QPushButton("↓ Export CSV")
        export_btn.setFixedHeight(24)
        export_btn.clicked.connect(self._export_csv)
        filter_row.addWidget(export_btn)
        top_vb.addLayout(filter_row)

        self._model = QStandardItemModel()
        self._model.setHorizontalHeaderLabels(
            ["#", "Payload(s)", "Status", "Length", "Time(ms)", "Error"]
        )
        self._proxy_model = QSortFilterProxyModel()
        self._proxy_model.setSourceModel(self._model)
        self._proxy_model.setFilterCaseSensitivity(Qt.CaseInsensitive)
        self._proxy_model.setFilterKeyColumn(-1)

        self._table = QTableView()
        self._table.setModel(self._proxy_model)
        self._table.setSortingEnabled(True)
        self._table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        self._table.setFont(QFont("Cascadia Code", 9))
        self._table.setStyleSheet(
            "QTableView{background:#1E1E2E;gridline-color:#313244;alternate-background-color:#181825;}"
            "QTableView::item:selected{background:#313244;}"
        )
        hdr = self._table.horizontalHeader()
        hdr.setSectionResizeMode(1, QHeaderView.Stretch)
        for col, w_px in [(0, 40), (2, 60), (3, 75), (4, 75), (5, 130)]:
            self._table.setColumnWidth(col, w_px)
        self._table.selectionModel().currentRowChanged.connect(self._on_row_changed)
        self._table.setContextMenuPolicy(Qt.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._on_table_context_menu)
        top_vb.addWidget(self._table)
        splitter.addWidget(top_w)

        # Bottom: request/response preview
        bottom_tabs = QTabWidget()
        bottom_tabs.setStyleSheet(
            "QTabBar::tab{background:#181825;color:#6C7086;padding:4px 12px;border:none;}"
            "QTabBar::tab:selected{background:#1E1E2E;color:#CDD6F4;}"
            "QTabWidget::pane{border:none;border-top:1px solid #313244;}"
        )

        req_pane  = _PaneWrapper("Request",  "#89B4FA")
        self._req_view = _CodeEdit(read_only=True)
        req_pane.body_layout().addWidget(self._req_view)
        bottom_tabs.addTab(req_pane, "Request")

        resp_pane = _PaneWrapper("Response", "#6C7086")
        self._resp_view = _CodeEdit(read_only=True)
        resp_pane.body_layout().addWidget(self._resp_view)
        bottom_tabs.addTab(resp_pane, "Response")

        splitter.addWidget(bottom_tabs)
        splitter.setSizes([420, 240])
        vb.addWidget(splitter, stretch=1)
        return w

    # ── payload set management ────────────────────────────────────────────────

    def _update_payload_sets(self, n: int):
        """Ensure exactly n payload editors exist and update the set combo."""
        while len(self._payload_editors) < n:
            idx = len(self._payload_editors) + 1
            ed  = _PayloadSetEditor(set_num=idx)
            self._payload_editors.append(ed)
            self._editor_stack.addWidget(ed)

        # Rebuild set combo without clearing existing selection
        self._set_combo.blockSignals(True)
        cur = self._set_combo.currentIndex()
        self._set_combo.clear()
        for i in range(n):
            self._set_combo.addItem(f"Set {i + 1}")
        new_cur = min(cur, n - 1) if cur >= 0 else 0
        self._set_combo.setCurrentIndex(new_cur)
        self._set_combo.blockSignals(False)
        self._editor_stack.setCurrentIndex(new_cur)

    def _sync_payload_sets(self):
        """Called (debounced) when positions change — update set count for multi-set modes."""
        mode_name = self._mode_combo.currentText()
        n_pos     = self._pos_editor.position_count()
        if mode_name in ("Pitchfork", "Cluster Bomb") and n_pos > 0:
            self._update_payload_sets(n_pos)
        else:
            self._update_payload_sets(1)

    def _on_mode_changed(self):
        self._sync_payload_sets()

    def _on_set_selected(self, idx: int):
        if 0 <= idx < self._editor_stack.count():
            self._editor_stack.setCurrentIndex(idx)

    # ── attack control ────────────────────────────────────────────────────────

    def _start_attack(self):
        template = self._pos_editor.toPlainText().strip()
        if not template:
            QMessageBox.warning(self, "No Request", "Paste an HTTP request in the Positions tab.")
            return

        n_pos = len(POSITION_RE.findall(template))
        if n_pos == 0:
            QMessageBox.warning(
                self, "No Positions",
                "Mark at least one position using § markers.\n"
                "Select text and click 'Add §', or click 'Auto §' to detect parameters."
            )
            return

        mode_name = self._mode_combo.currentText()
        mode_key  = mode_name.lower().replace(' ', '_')

        n_sets = n_pos if mode_name in ("Pitchfork", "Cluster Bomb") else 1
        payload_sets = [self._payload_editors[i].get_payloads()
                        if i < len(self._payload_editors) else []
                        for i in range(n_sets)]

        if not any(payload_sets):
            QMessageBox.warning(self, "No Payloads", "Add at least one payload in the Payloads tab.")
            return

        requests = _generate_requests(mode_key, template, payload_sets)
        if not requests:
            QMessageBox.warning(self, "No Requests", "Could not generate any requests. Check positions and payloads.")
            return

        # Reset results
        self._model.removeRows(0, self._model.rowCount())
        self._current_results.clear()
        self._req_view.clear()
        self._resp_view.clear()

        # Persist run to MongoDB
        run_id = ""
        if self._repo:
            try:
                run_id = self._repo.create_run(
                    mode=mode_key,
                    template=template,
                    payload_sets=payload_sets,
                    project_dir=self._project_dir,
                    total_requests=len(requests),
                )
            except Exception as exc:
                log.warning("Could not create intruder run in DB: %s", exc)
        self._run_id = run_id

        # Update UI
        self._start_btn.setEnabled(False)
        self._stop_btn.setEnabled(True)
        self._progress_bar.setVisible(True)
        self._progress_bar.setValue(0)
        self._status_lbl.setText(f"Running — 0/{len(requests)}")

        self._worker = _AttackWorker(
            requests         = requests,
            proxy_port       = self._proxy_port,
            run_id           = run_id,
            repo             = self._repo,  # type: ignore[arg-type]
            timeout          = float(self._timeout_spin.value()),
            follow_redirects = self._follow_chk.isChecked(),
        )
        self._worker.result.connect(self._on_result)
        self._worker.progress.connect(self._on_progress)
        self._worker.finished.connect(self._on_finished)
        self._worker.start()

    def _stop_attack(self):
        if self._worker:
            self._worker.stop()
        self._stop_btn.setEnabled(False)

    # ── worker signal handlers ────────────────────────────────────────────────

    def _on_result(self, doc: dict):
        seq         = doc["seq"]
        payloads    = doc["payloads"]
        status      = doc["status"]
        length      = doc["length"]
        elapsed     = doc["elapsed_ms"]
        error       = doc.get("error", "")

        self._current_results[seq] = doc

        payload_str = " | ".join(str(p) for p in payloads)

        items = [
            QStandardItem(str(seq)),
            QStandardItem(payload_str),
            QStandardItem(str(status) if status else "—"),
            QStandardItem(str(length)),
            QStandardItem(str(elapsed)),
            QStandardItem(error[:80] if error else ""),
        ]

        # Color the status cell
        cls = status // 100 if status else 0
        color = _STATUS_COLORS.get(cls, "#F38BA8" if error else "#6C7086")
        items[2].setForeground(QColor(color))
        if error:
            items[5].setForeground(QColor("#F38BA8"))

        # Make seq sortable as integer
        items[0].setData(seq, Qt.UserRole)

        self._model.appendRow(items)

    def _on_progress(self, done: int, total: int):
        pct = int(done / total * 100) if total else 0
        self._progress_bar.setValue(pct)
        self._status_lbl.setText(f"Running — {done}/{total}")

    def _on_finished(self):
        total = self._model.rowCount()
        self._start_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        self._progress_bar.setVisible(False)
        self._status_lbl.setText(f"Done — {total} request{'s' if total != 1 else ''}")
        if self._repo and self._run_id:
            try:
                self._repo.update_run(self._run_id, "completed", total)
            except Exception:
                pass

    # ── result selection ──────────────────────────────────────────────────────

    def _on_row_changed(self, current, _previous):
        if not current.isValid():
            return
        src = self._proxy_model.mapToSource(current)
        seq_item = self._model.item(src.row(), 0)
        if seq_item is None:
            return
        seq = seq_item.data(Qt.UserRole)
        doc = self._current_results.get(seq)
        if doc:
            self._req_view.setPlainText(doc.get("request_text", ""))
            self._resp_view.setPlainText(doc.get("response_text", ""))

    def _on_filter_changed(self, text: str):
        self._proxy_model.setFilterFixedString(text)

    def _on_table_context_menu(self, pos):
        from PySide6.QtWidgets import QMenu
        idx = self._table.indexAt(pos)
        if not idx.isValid():
            return
        src  = self._proxy_model.mapToSource(idx)
        seq_item = self._model.item(src.row(), 0)
        if seq_item is None:
            return
        seq = seq_item.data(Qt.UserRole)
        doc = self._current_results.get(seq)
        if not doc:
            return
        menu     = QMenu(self)
        rep_act  = menu.addAction("Send to Repeater")
        chosen   = menu.exec(self._table.mapToGlobal(pos))
        if chosen is rep_act:
            self.send_to_repeater.emit(doc.get("request_text", ""))

    # ── export ────────────────────────────────────────────────────────────────

    def _export_csv(self):
        import csv
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Results", "intruder_results.csv", "CSV (*.csv)"
        )
        if not path:
            return
        headers = ["#", "Payload(s)", "Status", "Length", "Time(ms)", "Error"]
        with open(path, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(headers)
            for row_idx in range(self._proxy_model.rowCount()):
                row = []
                for col in range(self._model.columnCount()):
                    src = self._proxy_model.mapToSource(
                        self._proxy_model.index(row_idx, col)
                    )
                    item = self._model.item(src.row(), src.column())
                    row.append(item.text() if item else "")
                w.writerow(row)
        self._status_lbl.setText(f"Exported → {path}")
