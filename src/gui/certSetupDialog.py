import os
import shutil
import subprocess
import sys
from pathlib import Path

from PySide6.QtCore import QThread, Signal, Qt
from PySide6.QtGui import QFont, QColor
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTextEdit, QFrame, QApplication, QSizePolicy, QWidget,
)

from config.config import CERT_CACHE_DIR, CERT_KEYS_DIR, CERTIFICATE_FILE, HOST_CERTS_DIR, ROOT_CERT_FILE


# ── background worker ────────────────────────────────────────────────────────

class _CertWorker(QThread):
    log = Signal(str)
    done = Signal(bool, str)   # success, message

    def __init__(self, action):
        super().__init__()
        self.action = action  # "generate" | "system_trust"

    def run(self):
        try:
            if self.action == "generate":
                self._generate()
            elif self.action == "system_trust":
                self._system_trust()
        except Exception as exc:
            self.done.emit(False, str(exc))

    def _generate(self):
        from certauth.certauth import CertificateAuthority
        self.log.emit("Creating cert directories…")
        for d in (CERT_CACHE_DIR, CERT_KEYS_DIR, HOST_CERTS_DIR,
                  str(Path(ROOT_CERT_FILE).parent)):
            os.makedirs(d, exist_ok=True)

        self.log.emit("Initialising certificate authority…")
        ca = CertificateAuthority(ca_name="AWE Proxy CA",
                                  cert_cache=CERT_CACHE_DIR,
                                  ca_file_cache=ROOT_CERT_FILE)

        self.log.emit(f"Root CA PEM written to:\n  {ROOT_CERT_FILE}")

        if not Path(CERTIFICATE_FILE).exists():
            self.log.emit("Converting PEM → CRT…")
            r = subprocess.run(
                ["openssl", "x509", "-in", ROOT_CERT_FILE, "-out", CERTIFICATE_FILE],
                capture_output=True, text=True,
            )
            if r.returncode != 0:
                self.done.emit(False, f"openssl failed:\n{r.stderr.strip()}")
                return

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


# ── dialog ───────────────────────────────────────────────────────────────────

class CertSetupDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Proxy Certificate Setup")
        self.setMinimumSize(620, 560)
        self.setWindowFlags(Qt.Dialog | Qt.WindowCloseButtonHint)
        self._worker = None
        self._build_ui()
        self._refresh_status()

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setSpacing(12)
        root.setContentsMargins(20, 20, 20, 20)

        # Header
        title = QLabel("Proxy Certificate Setup")
        title.setObjectName("certDialogTitle")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title.setFont(title_font)
        root.addWidget(title)

        subtitle = QLabel(
            "The proxy intercepts HTTPS traffic using a local CA certificate.\n"
            "Complete the steps below to generate and trust it."
        )
        subtitle.setWordWrap(True)
        subtitle.setObjectName("certDialogSubtitle")
        root.addWidget(subtitle)

        root.addWidget(self._divider())

        # Status row
        self.statusLabel = QLabel()
        self.statusLabel.setObjectName("certStatusLabel")
        root.addWidget(self.statusLabel)

        root.addWidget(self._divider())

        # Step 1 – Generate
        root.addWidget(self._step_header("Step 1", "Generate the CA Certificate"))
        step1_body = QHBoxLayout()
        self.generateBtn = QPushButton("Generate Certificate")
        self.generateBtn.setObjectName("primaryButton")
        self.generateBtn.setFixedHeight(32)
        self.generateBtn.clicked.connect(self._on_generate)
        step1_body.addWidget(self.generateBtn)
        step1_body.addStretch()
        root.addLayout(step1_body)

        root.addWidget(self._divider())

        # Step 2 – System trust
        root.addWidget(self._step_header("Step 2", "Trust in System"))
        step2_body = QVBoxLayout()
        step2_body.setSpacing(6)

        cert_row = QHBoxLayout()
        self.certPathLabel = QLabel()
        self.certPathLabel.setObjectName("certPathLabel")
        self.certPathLabel.setTextInteractionFlags(Qt.TextSelectableByMouse)
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
        root.addLayout(step2_body)

        root.addWidget(self._divider())

        # Step 3 – Browser trust
        root.addWidget(self._step_header("Step 3", "Trust in Browser  (HTTPS interception)"))
        browser_info = QLabel(
            "<b>Chrome / Chromium:</b>  Settings → Privacy &amp; Security → "
            "Manage Certificates → Authorities → Import<br>"
            "<b>Firefox:</b>  Settings → Privacy &amp; Security → "
            "View Certificates → Authorities → Import<br><br>"
            "Import the <b>.crt</b> file shown above and check "
            "<i>Trust this CA to identify websites</i>."
        )
        browser_info.setWordWrap(True)
        browser_info.setTextFormat(Qt.RichText)
        browser_info.setObjectName("certBrowserInfo")
        root.addWidget(browser_info)

        browser_btns = QHBoxLayout()
        openChromeBtn = QPushButton("Open Chrome Settings")
        openChromeBtn.setFixedHeight(28)
        openChromeBtn.clicked.connect(lambda: self._open_url(
            "chrome://settings/certificates" if sys.platform == "win32"
            else "chrome://settings/certificates"))
        openFirefoxBtn = QPushButton("Open Firefox Settings")
        openFirefoxBtn.setFixedHeight(28)
        openFirefoxBtn.clicked.connect(lambda: self._open_url(
            "about:preferences#privacy"))
        browser_btns.addWidget(openChromeBtn)
        browser_btns.addWidget(openFirefoxBtn)
        browser_btns.addStretch()
        root.addLayout(browser_btns)

        root.addWidget(self._divider())

        # Log output
        self.logView = QTextEdit()
        self.logView.setObjectName("certLogView")
        self.logView.setReadOnly(True)
        self.logView.setMaximumHeight(120)
        mono = QFont("Cascadia Code", 9)
        self.logView.setFont(mono)
        self.logView.setPlaceholderText("Activity log…")
        root.addWidget(self.logView)

        # Close button
        close_row = QHBoxLayout()
        close_row.addStretch()
        closeBtn = QPushButton("Close")
        closeBtn.setFixedHeight(32)
        closeBtn.clicked.connect(self.accept)
        close_row.addWidget(closeBtn)
        root.addLayout(close_row)

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
        self.generateBtn.setEnabled(not pem_ok)
        self.trustBtn.setEnabled(crt_ok and not trusted)

    @staticmethod
    def _is_system_trusted() -> bool:
        if sys.platform == "linux":
            dest = Path("/usr/local/share/ca-certificates/awe_proxy_ca.crt")
            return dest.exists()
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

    def _run_worker(self, action):
        if self._worker and self._worker.isRunning():
            return
        self.generateBtn.setEnabled(False)
        self.trustBtn.setEnabled(False)
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

    @staticmethod
    def _open_url(url: str):
        import webbrowser
        webbrowser.open(url)
