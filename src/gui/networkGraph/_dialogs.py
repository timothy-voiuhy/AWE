from PySide6.QtGui import QIntValidator
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QFormLayout,
    QLineEdit, QComboBox, QTextEdit, QLabel, QFrame, QPushButton,
)
from ._constants import _DLG_SS


# ── Dialog builder helpers ────────────────────────────────────────────────────

def _dlg_header(vb: QVBoxLayout, icon: str, title: str, color: str):
    h = QHBoxLayout()
    il = QLabel(icon)
    il.setStyleSheet(f"color:{color}; font-size:20px;")
    h.addWidget(il)
    tl = QLabel(title)
    tl.setStyleSheet(f"color:{color}; font-size:12px; font-weight:bold;")
    h.addWidget(tl)
    h.addStretch()
    vb.addLayout(h)
    div = QFrame(); div.setFrameShape(QFrame.HLine)
    div.setStyleSheet("background:#313244; border:none;"); div.setFixedHeight(1)
    vb.addWidget(div)


def _form_row(form: QFormLayout, label: str, widget):
    lbl = QLabel(label)
    lbl.setStyleSheet("color:#6C7086; font-size:9px;")
    form.addRow(lbl, widget)
    return widget


def _dlg_buttons(vb: QVBoxLayout, ok_text: str,
                 dialog: QDialog) -> QPushButton:
    div = QFrame(); div.setFrameShape(QFrame.HLine)
    div.setStyleSheet("background:#313244; border:none;"); div.setFixedHeight(1)
    vb.addWidget(div)
    row = QHBoxLayout()
    row.addStretch()
    c = QPushButton("Cancel")
    c.clicked.connect(dialog.reject)
    row.addWidget(c)
    ok = QPushButton(ok_text)
    ok.setObjectName("okBtn")
    ok.clicked.connect(dialog.accept)
    row.addWidget(ok)
    vb.addLayout(row)
    return ok


# ── Manual-entry dialogs ──────────────────────────────────────────────────────

class _AddSubdomainDlg(QDialog):
    def __init__(self, parent=None, prefill_domain: str = ""):
        super().__init__(parent)
        self.setWindowTitle("Add Subdomain")
        self.setMinimumWidth(400)
        self.setModal(True)
        self.setStyleSheet(_DLG_SS)
        vb = QVBoxLayout(self)
        vb.setSpacing(10)
        vb.setContentsMargins(16, 14, 16, 14)
        _dlg_header(vb, "◉", "Add Subdomain", "#89B4FA")
        form = QFormLayout(); form.setSpacing(8)
        self._domain = _form_row(form, "Domain *", QLineEdit(prefill_domain))
        self._ips    = _form_row(form, "IP(s)", QLineEdit())
        self._ips.setPlaceholderText("1.2.3.4, 5.6.7.8  (comma separated, optional)")
        vb.addLayout(form)
        vb.addStretch()
        ok = _dlg_buttons(vb, "Add Subdomain", self)
        ok.clicked.disconnect()
        ok.clicked.connect(self._on_ok)

    def _on_ok(self):
        d = self._domain.text().strip()
        if not d:
            self._domain.setProperty("error", "true")
            self._domain.setStyleSheet("border-color:#F38BA8;")
            return
        self.accept()

    def values(self) -> tuple[str, list[str]]:
        domain = self._domain.text().strip()
        ips = [ip.strip() for ip in self._ips.text().split(",") if ip.strip()]
        return domain, ips


class _AddPortDlg(QDialog):
    def __init__(self, parent=None, prefill_host: str = ""):
        super().__init__(parent)
        self.setWindowTitle("Add Port")
        self.setMinimumWidth(380)
        self.setModal(True)
        self.setStyleSheet(_DLG_SS)
        vb = QVBoxLayout(self)
        vb.setSpacing(10)
        vb.setContentsMargins(16, 14, 16, 14)
        _dlg_header(vb, "▣", "Add Port / Service", "#A6E3A1")
        form = QFormLayout(); form.setSpacing(8)
        self._host    = _form_row(form, "Host *", QLineEdit(prefill_host))
        self._port    = _form_row(form, "Port *", QLineEdit())
        self._port.setPlaceholderText("443")
        self._port.setValidator(QIntValidator(1, 65535))
        self._proto   = _form_row(form, "Protocol", QComboBox())
        self._proto.addItems(["tcp", "udp"])
        self._service = _form_row(form, "Service", QLineEdit())
        self._service.setPlaceholderText("https / ssh / ftp …")
        self._version = _form_row(form, "Version", QLineEdit())
        self._version.setPlaceholderText("nginx/1.18.0  (optional)")
        vb.addLayout(form)
        vb.addStretch()
        ok = _dlg_buttons(vb, "Add Port", self)
        ok.clicked.disconnect()
        ok.clicked.connect(self._on_ok)

    def _on_ok(self):
        host = self._host.text().strip()
        port = self._port.text().strip()
        err = False
        if not host:
            self._host.setStyleSheet("border-color:#F38BA8;"); err = True
        if not port:
            self._port.setStyleSheet("border-color:#F38BA8;"); err = True
        if not err:
            self.accept()

    def values(self) -> tuple[str, int, str, str, str]:
        return (self._host.text().strip(),
                int(self._port.text() or "0"),
                self._proto.currentText(),
                self._service.text().strip(),
                self._version.text().strip())


class _AddTechDlg(QDialog):
    def __init__(self, parent=None, prefill_url: str = ""):
        super().__init__(parent)
        self.setWindowTitle("Add Technology")
        self.setMinimumWidth(400)
        self.setModal(True)
        self.setStyleSheet(_DLG_SS)
        vb = QVBoxLayout(self)
        vb.setSpacing(10)
        vb.setContentsMargins(16, 14, 16, 14)
        _dlg_header(vb, "⬡", "Add Technology", "#F9E2AF")
        form = QFormLayout(); form.setSpacing(8)
        self._url    = _form_row(form, "URL *", QLineEdit(prefill_url))
        self._url.setPlaceholderText("https://api.example.com")
        self._tech   = _form_row(form, "Technology *", QLineEdit())
        self._tech.setPlaceholderText("Nginx / React / WordPress …")
        self._status = _form_row(form, "Status Code", QLineEdit("200"))
        self._status.setValidator(QIntValidator(0, 999))
        self._title  = _form_row(form, "Page Title", QLineEdit())
        vb.addLayout(form)
        vb.addStretch()
        ok = _dlg_buttons(vb, "Add Technology", self)
        ok.clicked.disconnect()
        ok.clicked.connect(self._on_ok)

    def _on_ok(self):
        err = False
        if not self._url.text().strip():
            self._url.setStyleSheet("border-color:#F38BA8;"); err = True
        if not self._tech.text().strip():
            self._tech.setStyleSheet("border-color:#F38BA8;"); err = True
        if not err:
            self.accept()

    def values(self) -> tuple[str, str, int, str]:
        return (self._url.text().strip(),
                self._tech.text().strip(),
                int(self._status.text() or "0"),
                self._title.text().strip())


class _AddVulnDlg(QDialog):
    def __init__(self, parent=None, prefill_url: str = ""):
        super().__init__(parent)
        self.setWindowTitle("Add Vulnerability")
        self.setMinimumWidth(420)
        self.setModal(True)
        self.setStyleSheet(_DLG_SS)
        vb = QVBoxLayout(self)
        vb.setSpacing(10)
        vb.setContentsMargins(16, 14, 16, 14)
        _dlg_header(vb, "⚠", "Add Vulnerability", "#F38BA8")
        form = QFormLayout(); form.setSpacing(8)
        self._name  = _form_row(form, "Name *", QLineEdit())
        self._name.setPlaceholderText("XSS in /search, SQLi in login …")
        self._sev   = _form_row(form, "Severity", QComboBox())
        self._sev.addItems(["critical", "high", "medium", "low", "info"])
        self._url   = _form_row(form, "URL", QLineEdit(prefill_url))
        self._url.setPlaceholderText("https://example.com/vuln-path")
        self._tid   = _form_row(form, "Template ID", QLineEdit("manual"))
        self._desc  = _form_row(form, "Description", QTextEdit())
        self._desc.setFixedHeight(64)
        self._desc.setPlaceholderText("Evidence, payload, notes …")
        vb.addLayout(form)
        vb.addStretch()
        ok = _dlg_buttons(vb, "Add Vulnerability", self)
        ok.clicked.disconnect()
        ok.clicked.connect(self._on_ok)

    def _on_ok(self):
        if not self._name.text().strip():
            self._name.setStyleSheet("border-color:#F38BA8;")
            return
        self.accept()

    def values(self) -> tuple[str, str, str, str, str]:
        return (self._name.text().strip(),
                self._sev.currentText(),
                self._url.text().strip(),
                self._desc.toPlainText().strip(),
                self._tid.text().strip() or "manual")


class _AddEndpointDlg(QDialog):
    def __init__(self, parent=None, prefill_url: str = ""):
        super().__init__(parent)
        self.setWindowTitle("Add Endpoint")
        self.setMinimumWidth(400)
        self.setModal(True)
        self.setStyleSheet(_DLG_SS)
        vb = QVBoxLayout(self)
        vb.setSpacing(10)
        vb.setContentsMargins(16, 14, 16, 14)
        _dlg_header(vb, "↗", "Add Endpoint", "#FAB387")
        form = QFormLayout(); form.setSpacing(8)
        self._url    = _form_row(form, "URL *", QLineEdit(prefill_url))
        self._url.setPlaceholderText("https://api.example.com/v1/users")
        self._method = _form_row(form, "Method", QComboBox())
        self._method.addItems(["GET", "POST", "PUT", "PATCH", "DELETE",
                                "HEAD", "OPTIONS"])
        self._status = _form_row(form, "Status Code", QLineEdit("200"))
        self._status.setValidator(QIntValidator(0, 999))
        vb.addLayout(form)
        vb.addStretch()
        ok = _dlg_buttons(vb, "Add Endpoint", self)
        ok.clicked.disconnect()
        ok.clicked.connect(self._on_ok)

    def _on_ok(self):
        if not self._url.text().strip():
            self._url.setStyleSheet("border-color:#F38BA8;")
            return
        self.accept()

    def values(self) -> tuple[str, str, int]:
        return (self._url.text().strip(),
                self._method.currentText(),
                int(self._status.text() or "0"))


class _AddOSINTDlg(QDialog):
    _TYPES = [
        "cloud_bucket", "github_endpoint", "asn", "netblock", "ip",
        "email", "pastebin", "github_secret", "domain", "other",
    ]
    _PROVIDERS = ["", "aws", "azure", "gcp", "github", "digitalocean", "other"]

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add OSINT Finding")
        self.setMinimumWidth(400)
        self.setModal(True)
        self.setStyleSheet(_DLG_SS)
        vb = QVBoxLayout(self)
        vb.setSpacing(10)
        vb.setContentsMargins(16, 14, 16, 14)
        _dlg_header(vb, "△", "Add OSINT Finding", "#94E2D5")
        form = QFormLayout(); form.setSpacing(8)
        self._rtype    = _form_row(form, "Type *", QComboBox())
        self._rtype.addItems(self._TYPES)
        self._value    = _form_row(form, "Value *", QLineEdit())
        self._value.setPlaceholderText("bucket-name.s3.amazonaws.com")
        self._extra    = _form_row(form, "Extra", QLineEdit())
        self._extra.setPlaceholderText("Public, readable / CIDR / org …")
        self._provider = _form_row(form, "Provider", QComboBox())
        self._provider.addItems(self._PROVIDERS)
        vb.addLayout(form)
        vb.addStretch()
        ok = _dlg_buttons(vb, "Add Finding", self)
        ok.clicked.disconnect()
        ok.clicked.connect(self._on_ok)

    def _on_ok(self):
        if not self._value.text().strip():
            self._value.setStyleSheet("border-color:#F38BA8;")
            return
        self.accept()

    def values(self) -> tuple[str, str, str, str]:
        return (self._rtype.currentText(),
                self._value.text().strip(),
                self._extra.text().strip(),
                self._provider.currentText())


class _AddCdnDlg(QDialog):
    _PROVIDERS = [
        "Cloudflare", "Akamai", "Fastly", "CloudFront", "Imperva",
        "Sucuri", "DDoS-Guard", "Varnish", "BunnyCDN", "KeyCDN",
        "StackPath", "CDN77", "Other",
    ]
    _TYPES = ["CDN", "Reverse Proxy", "CDN/Reverse Proxy", "WAF", "CDN/WAF", "DDoS Protection"]

    def __init__(self, parent=None, prefill_subdomain: str = ""):
        super().__init__(parent)
        self.setWindowTitle("Add CDN / Cloud Proxy")
        self.setMinimumWidth(430)
        self.setModal(True)
        self.setStyleSheet(_DLG_SS)
        vb = QVBoxLayout(self)
        vb.setSpacing(10)
        vb.setContentsMargins(16, 14, 16, 14)
        _dlg_header(vb, "⊕", "Add CDN / Cloud Proxy", "#89DCEB")
        form = QFormLayout(); form.setSpacing(8)
        self._subdomain = _form_row(form, "Subdomain *", QLineEdit(prefill_subdomain))
        self._subdomain.setPlaceholderText("api.example.com")
        self._provider  = _form_row(form, "Provider *", QComboBox())
        self._provider.addItems(self._PROVIDERS)
        self._ptype     = _form_row(form, "Type", QComboBox())
        self._ptype.addItems(self._TYPES)
        self._origins   = _form_row(form, "Origin IPs", QLineEdit())
        self._origins.setPlaceholderText("1.2.3.4, 5.6.7.8 (if known)")
        self._hints     = _form_row(form, "Bypass Hints", QTextEdit())
        self._hints.setPlaceholderText(
            "DNS history lookup\nCertificate transparency logs\nShodan/Censys direct IP scan …"
        )
        self._hints.setFixedHeight(72)
        vb.addLayout(form)
        vb.addStretch()
        ok = _dlg_buttons(vb, "Add CDN Node", self)
        ok.clicked.disconnect()
        ok.clicked.connect(self._on_ok)

    def _on_ok(self):
        if not self._subdomain.text().strip():
            self._subdomain.setProperty("error", "true")
            self._subdomain.setStyleSheet("border-color:#F38BA8;")
            return
        self.accept()

    def values(self) -> tuple[str, str, str, list[str], list[str]]:
        origins = [ip.strip() for ip in self._origins.text().split(",") if ip.strip()]
        hints   = [h.strip() for h in self._hints.toPlainText().splitlines() if h.strip()]
        return (
            self._subdomain.text().strip(),
            self._provider.currentText(),
            self._ptype.currentText(),
            origins,
            hints,
        )


class _InfoNoteDlg(QDialog):
    """Multi-line note editor attached to a graph node."""

    def __init__(self, parent=None, node_label: str = "", prefill: str = ""):
        super().__init__(parent)
        editing = bool(prefill)
        self.setWindowTitle("Edit Note" if editing else "Add Note")
        self.setMinimumSize(440, 280)
        self.setModal(True)
        self.setStyleSheet(_DLG_SS)

        vb = QVBoxLayout(self)
        vb.setSpacing(10)
        vb.setContentsMargins(16, 14, 16, 14)
        _dlg_header(vb, "✎", ("Edit" if editing else "Add") + f" Note — {node_label}", "#F9E2AF")

        self._edit = QTextEdit()
        self._edit.setPlaceholderText("Write anything — findings, ideas, reminders …")
        self._edit.setMinimumHeight(160)
        self._edit.setStyleSheet(
            "QTextEdit{background:#1E1E2E;color:#CDD6F4;"
            "border:1px solid #45475A;border-radius:4px;"
            "padding:6px;font-size:10px;}"
            "QTextEdit:focus{border-color:#F9E2AF;}"
        )
        if prefill:
            self._edit.setPlainText(prefill)
        vb.addWidget(self._edit, stretch=1)

        ok = _dlg_buttons(vb, "Save Note", self)
        ok.clicked.disconnect()
        ok.clicked.connect(self._on_ok)

    def _on_ok(self):
        if self._edit.toPlainText().strip():
            self.accept()

    def content(self) -> str:
        return self._edit.toPlainText().strip()


class _AddCustomNodeDlg(QDialog):
    """Dialog to create a free-form custom node."""

    def __init__(self, parent=None, parent_node_label: str = ""):
        super().__init__(parent)
        self.setWindowTitle("Add Custom Node")
        self.setMinimumWidth(400)
        self.setModal(True)
        self.setStyleSheet(_DLG_SS)

        vb = QVBoxLayout(self)
        vb.setSpacing(10)
        vb.setContentsMargins(16, 14, 16, 14)
        _dlg_header(vb, "＋", "Add Custom Node", "#A6E3A1")

        if parent_node_label:
            ctx = QLabel(f"Connects to: {parent_node_label}")
            ctx.setStyleSheet("color:#6C7086; font-size:9px;")
            vb.addWidget(ctx)

        form = QFormLayout()
        form.setSpacing(8)
        self._label = _form_row(form, "Label *", QLineEdit())
        self._label.setPlaceholderText("e.g.  Internal tool  /  VPN gateway  /  AWS account")
        self._desc  = _form_row(form, "Notes", QTextEdit())
        self._desc.setPlaceholderText("Optional — any details you want to record")
        self._desc.setFixedHeight(80)
        vb.addLayout(form)
        vb.addStretch()

        ok = _dlg_buttons(vb, "Add Node", self)
        ok.clicked.disconnect()
        ok.clicked.connect(self._on_ok)

    def _on_ok(self):
        if not self._label.text().strip():
            self._label.setStyleSheet("border-color:#F38BA8;")
            return
        self.accept()

    def values(self) -> tuple[str, str]:
        return self._label.text().strip(), self._desc.toPlainText().strip()


class _AddOriginServerDlg(QDialog):
    """Minimal dialog to record an origin server behind a CDN / reverse proxy node."""

    _PROVIDERS = [
        "Cloudflare", "Akamai", "Fastly", "CloudFront", "Imperva",
        "Sucuri", "DDoS-Guard", "Varnish", "BunnyCDN", "KeyCDN",
        "StackPath", "CDN77", "Other",
    ]

    def __init__(self, parent=None, provider: str = "", subdomain: str = ""):
        super().__init__(parent)
        self.setWindowTitle("Add Origin Server")
        self.setMinimumWidth(380)
        self.setModal(True)
        self.setStyleSheet(_DLG_SS)

        vb = QVBoxLayout(self)
        vb.setSpacing(10)
        vb.setContentsMargins(16, 14, 16, 14)
        _dlg_header(vb, "↪", "Add Origin Server", "#FAB387")

        form = QFormLayout()
        form.setSpacing(8)

        self._origin = _form_row(form, "Origin IP / Host *", QLineEdit())
        self._origin.setPlaceholderText("203.0.113.42  or  origin.example.com")

        self._subdomain = _form_row(form, "Proxied subdomain *", QLineEdit(subdomain))
        self._subdomain.setPlaceholderText("api.example.com")

        self._provider = _form_row(form, "Provider", QComboBox())
        self._provider.addItems(self._PROVIDERS)
        if provider in self._PROVIDERS:
            self._provider.setCurrentText(provider)

        vb.addLayout(form)
        vb.addStretch()

        ok = _dlg_buttons(vb, "Save Origin", self)
        ok.clicked.disconnect()
        ok.clicked.connect(self._on_ok)

    def _on_ok(self):
        ok = True
        if not self._origin.text().strip():
            self._origin.setStyleSheet("border-color:#F38BA8;")
            ok = False
        if not self._subdomain.text().strip():
            self._subdomain.setStyleSheet("border-color:#F38BA8;")
            ok = False
        if ok:
            self.accept()

    def values(self) -> tuple[str, str, str]:
        """Return (origin_ip, subdomain, provider)."""
        return (
            self._origin.text().strip(),
            self._subdomain.text().strip(),
            self._provider.currentText(),
        )
