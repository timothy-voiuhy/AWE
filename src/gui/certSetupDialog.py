import os
import shutil
import subprocess
import sys
from pathlib import Path

from PySide6.QtCore import QThread, Signal, Qt
from PySide6.QtGui import QFont, QColor
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTextEdit, QFrame, QApplication, QSizePolicy, QWidget, QScrollArea,
)

from config.config import CERT_CACHE_DIR, CERT_KEYS_DIR, CERTIFICATE_FILE, HOST_CERTS_DIR, ROOT_CERT_FILE


# ── background worker ────────────────────────────────────────────────────────

class _CertWorker(QThread):
    log = Signal(str)
    done = Signal(bool, str)   # success, message

    def __init__(self, action):
        super().__init__()
        self.action = action  # "generate" | "system_trust" | "chrome_trust" | "firefox_trust"

    def run(self):
        try:
            if self.action == "generate":
                self._generate()
            elif self.action == "system_trust":
                self._system_trust()
            elif self.action == "chrome_trust":
                self._nss_trust("Chrome/Chromium", self._chrome_nss_dbs())
            elif self.action == "firefox_trust":
                self._nss_trust("Firefox", self._firefox_nss_dbs())
        except Exception as exc:
            self.done.emit(False, str(exc))

    def _generate(self):
        from proxy._ca import CertificateAuthority
        self.log.emit("Creating cert directories…")
        for d in (CERT_CACHE_DIR, CERT_KEYS_DIR, HOST_CERTS_DIR,
                  str(Path(ROOT_CERT_FILE).parent)):
            os.makedirs(d, exist_ok=True)

        # Remove stale per-hostname certs so they're re-signed by the new root
        cache_dir = Path(CERT_CACHE_DIR)
        stale = list(cache_dir.glob("*.pem")) if cache_dir.exists() else []
        for f in stale:
            try:
                f.unlink()
            except OSError:
                pass
        if stale:
            self.log.emit(f"Cleared {len(stale)} cached host certificate(s).")

        self.log.emit("Generating root CA certificate…")
        try:
            ca = CertificateAuthority(ca_name="AWE Proxy CA")
        except Exception as exc:
            self.done.emit(False, f"CA generation failed:\n{exc}")
            return

        self.log.emit(f"Root CA PEM written to:\n  {ROOT_CERT_FILE}")
        self.log.emit(f"Certificate file:\n  {CERTIFICATE_FILE}")
        self.done.emit(True, "Certificate generated successfully.")

    def _system_trust(self):
        if not Path(CERTIFICATE_FILE).exists():
            self.done.emit(False, "Certificate not found. Generate it first.")
            return

        if sys.platform == "linux":
            dest = "/usr/local/share/ca-certificates/awe_proxy_ca.crt"
            self.log.emit(f"Copying cert to {dest}…")
            cmd = (
                f"cp '{CERTIFICATE_FILE}' '{dest}' && update-ca-certificates"
            )
            # Try pkexec for a graphical password prompt, fall back to sudo
            runner = shutil.which("pkexec") or shutil.which("sudo")
            if runner is None:
                self.done.emit(False, "Neither pkexec nor sudo found.")
                return
            self.log.emit(f"Requesting privilege elevation via {Path(runner).name}…")
            r = subprocess.run([runner, "sh", "-c", cmd],
                               capture_output=True, text=True)
            if r.returncode != 0:
                self.done.emit(False, f"System trust failed:\n{r.stderr.strip() or r.stdout.strip()}")
                return
            self.log.emit(r.stdout.strip() or "Done.")
            self.done.emit(True, "Certificate trusted by system.")

        elif sys.platform == "win32":
            self.log.emit("Importing certificate into Windows certificate store…")
            r = subprocess.run(
                ["certutil", "-addstore", "Root", CERTIFICATE_FILE],
                capture_output=True, text=True,
            )
            if r.returncode != 0:
                self.done.emit(False, f"certutil failed:\n{r.stderr.strip()}")
                return
            self.log.emit(r.stdout.strip())
            self.done.emit(True, "Certificate trusted by system.")
        else:
            self.done.emit(False, f"Unsupported platform: {sys.platform}")

    # ── NSS browser trust (Chrome + Firefox on Linux) ─────────────────────────

    def _nss_trust(self, browser_name: str, db_dirs: list[str]) -> None:
        """Install the AWE CA into each NSS database directory found."""
        certutil = shutil.which("certutil")
        if not certutil:
            self.done.emit(
                False,
                f"'certutil' not found.\n"
                f"Install it with:  sudo apt install libnss3-tools"
            )
            return

        if not db_dirs:
            self.done.emit(False, f"No {browser_name} NSS database found.\n"
                                  f"Launch {browser_name} at least once first.")
            return

        ok_count = 0
        for db in db_dirs:
            self.log.emit(f"Installing into {db} …")
            # Remove old entry first (ignore errors — may not exist yet)
            subprocess.run(
                [certutil, "-d", f"sql:{db}", "-D", "-n", "AWE Proxy CA"],
                capture_output=True,
            )
            r = subprocess.run(
                [certutil, "-d", f"sql:{db}", "-A",
                 "-t", "CT,,", "-n", "AWE Proxy CA", "-i", CERTIFICATE_FILE],
                capture_output=True, text=True,
            )
            if r.returncode == 0:
                self.log.emit(f"  ✓ {db}")
                ok_count += 1
            else:
                self.log.emit(f"  ✗ {db}: {r.stderr.strip() or r.stdout.strip()}")

        if ok_count:
            self.done.emit(True,
                f"Trusted in {ok_count} {browser_name} profile(s).\n"
                f"Restart {browser_name} for the change to take effect.")
        else:
            self.done.emit(False,
                f"Failed to trust certificate in any {browser_name} profile.")

    @staticmethod
    def _chrome_nss_dbs() -> list[str]:
        """Return existing Chrome/Chromium NSS database directories."""
        candidates = [
            Path.home() / ".pki" / "nssdb",
            Path.home() / ".local" / "share" / "pki" / "nssdb",
            # Snap-packaged Chrome
            Path.home() / "snap" / "chromium" / "current" / ".pki" / "nssdb",
        ]
        found = [str(p) for p in candidates if p.is_dir()]
        # Auto-create the default NSS db if Chrome has never been opened yet
        if not found:
            default = Path.home() / ".pki" / "nssdb"
            try:
                default.mkdir(parents=True, exist_ok=True)
                subprocess.run(
                    ["certutil", "-d", f"sql:{default}", "-N", "--empty-password"],
                    capture_output=True,
                )
                if default.is_dir():
                    found = [str(default)]
            except Exception:
                pass
        return found

    @staticmethod
    def _firefox_nss_dbs() -> list[str]:
        """Return existing Firefox profile NSS database directories."""
        import glob
        patterns = [
            str(Path.home() / ".mozilla" / "firefox" / "*.default*"),
            str(Path.home() / ".mozilla" / "firefox" / "*.esr"),
            # Flatpak Firefox
            str(Path.home() / ".var" / "app" / "org.mozilla.firefox"
                / ".mozilla" / "firefox" / "*.default*"),
            # Snap Firefox
            str(Path.home() / "snap" / "firefox" / "current"
                / ".mozilla" / "firefox" / "*.default*"),
        ]
        dirs = []
        for pat in patterns:
            dirs.extend(p for p in glob.glob(pat) if Path(p).is_dir())
        return dirs


# ── dialog ───────────────────────────────────────────────────────────────────

class CertSetupDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Proxy Certificate Setup")
        self.setMinimumSize(560, 420)
        self.resize(640, 640)
        self.setWindowFlags(Qt.Dialog | Qt.WindowCloseButtonHint)
        self._worker = None
        self._build_ui()
        self._refresh_status()

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build_ui(self):
        # Outer layout: scroll area (grows) + log + close (pinned at bottom)
        root = QVBoxLayout(self)
        root.setSpacing(0)
        root.setContentsMargins(0, 0, 0, 0)

        # ── Scrollable content ────────────────────────────────────────────────
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setStyleSheet(
            "QScrollArea{background:#1E1E2E; border:none;}"
            "QScrollBar:vertical{background:#181825; width:8px; border:none;}"
            "QScrollBar::handle:vertical{background:#313244; border-radius:4px; min-height:20px;}"
        )

        body = QWidget()
        body.setStyleSheet("background:#1E1E2E;")
        vb = QVBoxLayout(body)
        vb.setSpacing(12)
        vb.setContentsMargins(20, 20, 20, 16)

        # Header
        title = QLabel("Proxy Certificate Setup")
        title.setObjectName("certDialogTitle")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title.setFont(title_font)
        vb.addWidget(title)

        subtitle = QLabel(
            "The proxy intercepts HTTPS traffic using a local CA certificate.\n"
            "Complete the steps below to generate and trust it."
        )
        subtitle.setWordWrap(True)
        subtitle.setObjectName("certDialogSubtitle")
        vb.addWidget(subtitle)

        vb.addWidget(self._divider())

        # Status row
        self.statusLabel = QLabel()
        self.statusLabel.setObjectName("certStatusLabel")
        vb.addWidget(self.statusLabel)

        vb.addWidget(self._divider())

        # Step 1 – Generate
        vb.addWidget(self._step_header("Step 1", "Generate the CA Certificate"))
        step1_body = QHBoxLayout()
        self.generateBtn = QPushButton("Generate Certificate")
        self.generateBtn.setObjectName("primaryButton")
        self.generateBtn.setFixedHeight(32)
        self.generateBtn.clicked.connect(self._on_generate)
        step1_body.addWidget(self.generateBtn)
        step1_body.addStretch()
        vb.addLayout(step1_body)

        vb.addWidget(self._divider())

        # Step 2 – System trust
        vb.addWidget(self._step_header("Step 2", "Trust in System"))
        step2_body = QVBoxLayout()
        step2_body.setSpacing(6)

        cert_row = QHBoxLayout()
        self.certPathLabel = QLabel()
        self.certPathLabel.setObjectName("certPathLabel")
        self.certPathLabel.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.certPathLabel.setWordWrap(True)
        cert_row.addWidget(self.certPathLabel, 1)
        copyBtn = QPushButton("Copy Path")
        copyBtn.setFixedHeight(28)
        copyBtn.clicked.connect(self._copy_cert_path)
        cert_row.addWidget(copyBtn)
        step2_body.addLayout(cert_row)

        trust_row = QHBoxLayout()
        self.trustBtn = QPushButton("Install to System  (requires admin)")
        self.trustBtn.setObjectName("primaryButton")
        self.trustBtn.setFixedHeight(32)
        self.trustBtn.clicked.connect(self._on_system_trust)
        trust_row.addWidget(self.trustBtn)
        trust_row.addStretch()
        step2_body.addLayout(trust_row)
        vb.addLayout(step2_body)

        vb.addWidget(self._divider())

        # Step 3 – Browser trust
        vb.addWidget(self._step_header("Step 3", "Trust in Browser  (HTTPS interception)"))

        browser_note = QLabel(
            "Installs the CA into the browser's NSS certificate database automatically.\n"
            "Requires <b>libnss3-tools</b>  (<code>sudo apt install libnss3-tools</code>).\n"
            "Restart the browser after installing."
        )
        browser_note.setWordWrap(True)
        browser_note.setTextFormat(Qt.RichText)
        browser_note.setStyleSheet("color:#BAC2DE; font-size:10px; background:transparent;")
        vb.addWidget(browser_note)

        browser_btns = QHBoxLayout()
        browser_btns.setSpacing(8)

        self.chromeTrustBtn = QPushButton("Trust in Chrome / Chromium")
        self.chromeTrustBtn.setObjectName("primaryButton")
        self.chromeTrustBtn.setFixedHeight(32)
        self.chromeTrustBtn.clicked.connect(self._on_chrome_trust)
        browser_btns.addWidget(self.chromeTrustBtn)

        self.firefoxTrustBtn = QPushButton("Trust in Firefox")
        self.firefoxTrustBtn.setObjectName("primaryButton")
        self.firefoxTrustBtn.setFixedHeight(32)
        self.firefoxTrustBtn.clicked.connect(self._on_firefox_trust)
        browser_btns.addWidget(self.firefoxTrustBtn)

        browser_btns.addStretch()
        vb.addLayout(browser_btns)

        # Manual fallback note for Windows / macOS
        manual_note = QLabel(
            "On Windows / macOS or if the above buttons fail: open the browser's certificate manager "
            "and import the <b>.crt</b> file as a trusted CA."
        )
        manual_note.setWordWrap(True)
        manual_note.setTextFormat(Qt.RichText)
        manual_note.setStyleSheet("color:#6C7086; font-size:9px; background:transparent;")
        vb.addWidget(manual_note)

        vb.addStretch()
        scroll.setWidget(body)
        root.addWidget(scroll, stretch=1)

        # ── Pinned bottom: log + close ────────────────────────────────────────
        bottom = QWidget()
        bottom.setStyleSheet("background:#181825;")
        bottom_vb = QVBoxLayout(bottom)
        bottom_vb.setContentsMargins(20, 8, 20, 16)
        bottom_vb.setSpacing(8)

        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setStyleSheet("background:#313244; border:none;")
        sep.setFixedHeight(1)
        bottom_vb.addWidget(sep)

        self.logView = QTextEdit()
        self.logView.setObjectName("certLogView")
        self.logView.setReadOnly(True)
        self.logView.setFixedHeight(110)
        mono = QFont("Cascadia Code", 9)
        self.logView.setFont(mono)
        self.logView.setPlaceholderText("Activity log…")
        self.logView.setStyleSheet(
            "QTextEdit{background:#11111B; color:#CDD6F4; border:none; padding:6px;}"
        )
        bottom_vb.addWidget(self.logView)

        close_row = QHBoxLayout()
        close_row.addStretch()
        closeBtn = QPushButton("Close")
        closeBtn.setFixedHeight(32)
        closeBtn.clicked.connect(self.accept)
        close_row.addWidget(closeBtn)
        bottom_vb.addLayout(close_row)

        root.addWidget(bottom)

    @staticmethod
    def _divider():
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setObjectName("certDivider")
        return line

    @staticmethod
    def _step_header(step_num: str, label: str) -> QWidget:
        w = QWidget()
        row = QHBoxLayout(w)
        row.setContentsMargins(0, 4, 0, 4)
        row.setSpacing(8)
        badge = QLabel(step_num)
        badge.setObjectName("certStepBadge")
        badge.setFixedSize(52, 22)
        badge.setAlignment(Qt.AlignCenter)
        lbl = QLabel(label)
        lbl.setObjectName("certStepLabel")
        row.addWidget(badge)
        row.addWidget(lbl)
        row.addStretch()
        return w

    # ── state ─────────────────────────────────────────────────────────────────

    def _refresh_status(self):
        pem_ok = Path(ROOT_CERT_FILE).exists()
        crt_ok = Path(CERTIFICATE_FILE).exists()
        trusted = self._is_system_trusted()

        if not pem_ok:
            status = "Not generated"
            color = "#F38BA8"
        elif not trusted:
            status = "Generated — not yet trusted by system"
            color = "#FAB387"
        else:
            status = "Generated and trusted by system"
            color = "#A6E3A1"

        self.statusLabel.setText(f"Status:  <span style='color:{color}'><b>{status}</b></span>")
        self.statusLabel.setTextFormat(Qt.RichText)
        self.certPathLabel.setText(CERTIFICATE_FILE if crt_ok else "(not generated yet)")
        self.generateBtn.setText("Regenerate Certificate" if pem_ok else "Generate Certificate")
        self.generateBtn.setEnabled(True)
        self.trustBtn.setEnabled(crt_ok and not trusted)
        self.chromeTrustBtn.setEnabled(crt_ok)
        self.firefoxTrustBtn.setEnabled(crt_ok)

    @staticmethod
    def _is_system_trusted() -> bool:
        if sys.platform == "linux":
            dest = Path("/usr/local/share/ca-certificates/awe_proxy_ca.crt")
            if not dest.exists():
                return False
            # File exists but may be from a previous (now replaced) CA — compare content
            try:
                return dest.read_bytes() == Path(CERTIFICATE_FILE).read_bytes()
            except OSError:
                return False
        elif sys.platform == "win32":
            r = subprocess.run(
                ["certutil", "-verifystore", "Root", CERTIFICATE_FILE],
                capture_output=True,
            )
            return r.returncode == 0
        return False

    # ── actions ───────────────────────────────────────────────────────────────

    def _on_generate(self):
        self._run_worker("generate")

    def _on_system_trust(self):
        self._run_worker("system_trust")

    def _on_chrome_trust(self):
        self._run_worker("chrome_trust")

    def _on_firefox_trust(self):
        self._run_worker("firefox_trust")

    def _run_worker(self, action):
        if self._worker and self._worker.isRunning():
            return
        # Disable all action buttons while work is in progress
        for btn in (self.generateBtn, self.trustBtn, self.chromeTrustBtn, self.firefoxTrustBtn):
            btn.setEnabled(False)
        self.logView.clear()
        self._worker = _CertWorker(action)
        self._worker.log.connect(self._append_log)
        self._worker.done.connect(self._on_done)
        self._worker.start()

    def _append_log(self, text: str):
        self.logView.append(text)

    def _on_done(self, success: bool, msg: str):
        color = "#A6E3A1" if success else "#F38BA8"
        self.logView.append(f"<span style='color:{color}'>{msg}</span>")
        self._refresh_status()

    def _copy_cert_path(self):
        QApplication.clipboard().setText(CERTIFICATE_FILE)
        self._append_log(f"Copied: {CERTIFICATE_FILE}")
