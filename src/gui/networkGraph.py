"""
Network attack-surface graph visualisation for AWE.
Embed NetworkPage as the Network nav page in TargetWindow.
"""
import logging
import math

from dataclasses import dataclass, field
from PySide6.QtCore import Qt, QRectF, QPointF, QTimer, Signal, QThread
from PySide6.QtGui import (
    QPainter, QPen, QBrush, QColor, QFont, QPolygonF, QIntValidator,
)
from PySide6.QtWidgets import (
    QGraphicsItem, QGraphicsScene, QGraphicsView,
    QWidget, QHBoxLayout, QVBoxLayout, QSplitter,
    QPushButton, QLabel, QFrame, QScrollArea, QApplication,
    QMenu, QDialog, QFormLayout, QLineEdit, QComboBox, QTextEdit,
    QMessageBox,
)

logger = logging.getLogger(__name__)

# ── Visual config ─────────────────────────────────────────────────────────────

_NS: dict[str, dict] = {
    "target":    {"fill": "#CBA6F7", "border": "#D8B4FE", "r": 26, "shape": "circle"},
    "subdomain": {"fill": "#89B4FA", "border": "#BAD5FF", "r": 18, "shape": "circle"},
    "ip":        {"fill": "#FAB387", "border": "#FCC9A8", "r": 14, "shape": "diamond"},
    "port":      {"fill": "#A6E3A1", "border": "#C8F0C5", "r": 12, "shape": "square"},
    "tech":      {"fill": "#F9E2AF", "border": "#FAF0D0", "r": 11, "shape": "hexagon"},
    "vuln":      {"fill": "#F38BA8", "border": "#F8B4C8", "r": 13, "shape": "circle"},
    "osint":     {"fill": "#94E2D5", "border": "#B6EEE7", "r": 11, "shape": "triangle"},
    "cdn":           {"fill": "#89DCEB", "border": "#B4BEFE", "r": 16, "shape": "shield"},
    "reverse_proxy": {"fill": "#F5A97F", "border": "#FE640B", "r": 16, "shape": "shield"},
    "endpoint":      {"fill": "#313244", "border": "#6C7086", "r": 10, "shape": "hexagon"},
    "param":         {"fill": "#1E1E2E", "border": "#45475A", "r":  8, "shape": "square"},
    "custom":        {"fill": "#A6E3A1", "border": "#40A02B", "r": 14, "shape": "circle"},
    "info":          {"fill": "#F9E2AF", "border": "#DF8E1D", "r": 10, "shape": "note"},
}

_EC: dict[str, str] = {
    "has_subdomain": "#45475A",
    "resolves_to":   "#89B4FA",
    "has_port":      "#A6E3A1",
    "uses_tech":     "#F9E2AF",
    "has_vuln":      "#F38BA8",
    "is_osint":      "#94E2D5",
    "proxied_by":    "#89DCEB",
    "routes_through":"#F5A97F",
    "origin_of":     "#FAB387",
    "has_endpoint":  "#45475A",
    "has_param":     "#313244",
    "annotates":     "#F9E2AF",
    "linked_to":     "#A6E3A1",
}

_KIND_ICON = {
    "target": "◎", "subdomain": "◉", "ip": "◆",
    "port": "▣",   "tech": "⬡",      "vuln": "⚠", "osint": "△",
    "cdn":           "⊕",
    "reverse_proxy": "⇄",
    "endpoint":      "↗",
    "param":         "?",
    "custom":        "＋",
    "info":          "✎",
}

_DASHED = {"uses_tech", "has_vuln", "is_osint"}

# Node kinds that are hidden by default (only shown on explicit user request)
_HIDDEN_BY_DEFAULT: frozenset[str] = frozenset({"endpoint", "param"})

# Edge kinds that connect visible nodes to hidden-by-default children
_CHILD_EDGE_KINDS: frozenset[str] = frozenset({"has_endpoint", "has_param"})

# Technology name substrings that indicate a CDN/proxy layer (checked case-insensitively)
_CDN_TECH_MAP: dict[str, tuple[str, str]] = {
    "cloudflare":  ("Cloudflare",  "CDN/WAF"),
    "akamai":      ("Akamai",      "CDN"),
    "fastly":      ("Fastly",      "CDN"),
    "cloudfront":  ("CloudFront",  "CDN"),
    "incapsula":   ("Imperva",     "WAF/CDN"),
    "imperva":     ("Imperva",     "WAF/CDN"),
    "sucuri":      ("Sucuri",      "WAF/CDN"),
    "ddos-guard":  ("DDoS-Guard",  "DDoS Protection"),
    "varnish":     ("Varnish",     "Reverse Proxy"),
    "cdn77":       ("CDN77",       "CDN"),
    "bunnycdn":    ("BunnyCDN",    "CDN"),
    "keycdn":      ("KeyCDN",      "CDN"),
    "stackpath":   ("StackPath",   "CDN/WAF"),
}


def _cdn_node_kind(proxy_type: str) -> str:
    """Map a CdnResult.proxy_type string to a graph node kind.

    "Reverse Proxy" and any combined type that includes reverse-proxy
    behaviour ("CDN/Reverse Proxy") become `reverse_proxy` nodes.
    Everything else (pure CDN, WAF, DDoS protection) stays `cdn`.
    """
    return "reverse_proxy" if "reverse proxy" in proxy_type.lower() else "cdn"


# ── Shared UI constants ───────────────────────────────────────────────────────

_MENU_SS = """
    QMenu {
        background:#1E1E2E; color:#CDD6F4;
        border:1px solid #313244; border-radius:6px;
        padding:4px; font-size:10px;
    }
    QMenu::item { padding:5px 20px 5px 10px; border-radius:3px; }
    QMenu::item:selected { background:#313244; }
    QMenu::item:disabled { color:#45475A; }
    QMenu::separator { height:1px; background:#313244; margin:4px 6px; }
"""

_DLG_SS = """
    QDialog { background:#181825; }
    QLabel { color:#CDD6F4; font-size:10px; background:transparent; }
    QLineEdit, QComboBox, QTextEdit {
        background:#1E1E2E; color:#CDD6F4;
        border:1px solid #45475A; border-radius:4px;
        padding:4px 8px; font-size:10px; min-height:26px;
    }
    QLineEdit:focus, QComboBox:focus, QTextEdit:focus { border-color:#89B4FA; }
    QLineEdit[error="true"] { border-color:#F38BA8; }
    QPushButton {
        background:#313244; color:#CDD6F4;
        border:1px solid #45475A; border-radius:4px;
        padding:4px 16px; font-size:10px; min-height:28px;
    }
    QPushButton:hover { background:#45475A; }
    QPushButton#okBtn {
        background:#1E3A5F; border-color:#89B4FA; color:#89B4FA;
    }
    QPushButton#okBtn:hover { background:#2A4A7F; }
"""


# ── Manual data repository ────────────────────────────────────────────────────

class ManualDataRepository:
    """Thin wrapper around AweRepository that maintains a 'manual' session
    so the user can write arbitrary nodes directly into the database."""

    _PIPELINE_KEY = "manual"

    def __init__(self, project_dir: str, target: str):
        self._project_dir = project_dir
        self._target      = target
        self._session_id: str | None  = None
        self._run_id:     str | None  = None

    def _ensure_session(self):
        if self._session_id:
            return
        from database.repository import AweRepository
        repo = AweRepository(self._project_dir)
        for s in repo.list_sessions(limit=200):
            if s.get("pipeline_key") == self._PIPELINE_KEY:
                self._session_id = s["id"]
                break
        if not self._session_id:
            self._session_id = repo.create_session(
                pipeline_key=self._PIPELINE_KEY,
                pipeline_name="Manual Additions",
                target=self._target,
                output_dir="",
            )
        for run in repo.get_tool_runs(self._session_id):
            if run.get("tool_key") == "manual":
                self._run_id = run["id"]
                return
        self._run_id = repo.create_tool_run(
            self._session_id, "manual", "Manual Entry", "manual", stage=0,
        )
        repo.update_tool_run_started(self._run_id)

    def _repo(self):
        from database.repository import AweRepository
        return AweRepository(self._project_dir)

    def add_subdomain(self, domain: str, ips: list[str] = None) -> bool:
        from containers.results.models import SubdomainResult
        self._ensure_session()
        r = SubdomainResult(domain=domain, ip_addresses=[i for i in (ips or []) if i])
        r.add_source("manual")
        self._repo().upsert_results(self._session_id, self._run_id, "subdomain", [r])
        return True

    def add_port(self, host: str, port: int, protocol: str = "tcp",
                 service: str = "", version: str = "") -> bool:
        from containers.results.models import PortResult
        self._ensure_session()
        r = PortResult(host=host, port=port, protocol=protocol,
                       service=service, version=version)
        r.add_source("manual")
        self._repo().upsert_results(self._session_id, self._run_id, "portscan", [r])
        return True

    def add_tech(self, url: str, tech: str,
                 status_code: int = 0, title: str = "") -> bool:
        from containers.results.models import LiveHost
        self._ensure_session()
        r = LiveHost(url=url, technologies=[tech],
                     status_code=status_code, title=title)
        r.add_source("manual")
        self._repo().upsert_results(self._session_id, self._run_id, "http", [r])
        return True

    def add_vuln(self, name: str, severity: str, url: str,
                 description: str = "", template_id: str = "manual") -> bool:
        from containers.results.models import VulnFinding
        self._ensure_session()
        r = VulnFinding(template_id=template_id, name=name,
                        severity=severity, url=url, description=description)
        r.add_source("manual")
        self._repo().upsert_results(self._session_id, self._run_id, "vuln", [r])
        return True

    def add_endpoint(self, url: str, method: str = "GET",
                     status_code: int = 0) -> bool:
        from containers.results.models import EndpointResult
        self._ensure_session()
        r = EndpointResult(url=url, method=method, status_code=status_code)
        r.add_source("manual")
        self._repo().upsert_results(self._session_id, self._run_id, "crawl", [r])
        return True

    def add_osint(self, result_type: str, value: str,
                  extra: str = "", provider: str = "") -> bool:
        from containers.results.models import OSINTResult
        self._ensure_session()
        r = OSINTResult(result_type=result_type, value=value,
                        extra=extra, provider=provider)
        r.add_source("manual")
        self._repo().upsert_results(self._session_id, self._run_id, "osint", [r])
        return True

    def add_cdn(self, subdomain: str, provider: str,
                proxy_type: str = "CDN",
                origin_ips: list[str] = None,
                bypass_hints: list[str] = None) -> bool:
        from containers.results.models import CdnResult
        self._ensure_session()
        r = CdnResult(
            subdomain=subdomain,
            provider=provider,
            proxy_type=proxy_type,
            origin_masked=True,
            origin_ips=[ip for ip in (origin_ips or []) if ip],
            bypass_hints=[h for h in (bypass_hints or []) if h],
        )
        r.add_source("manual")
        self._repo().upsert_results(self._session_id, self._run_id, "cdn", [r])
        return True

    def save_info_note(self, parent_node_id: str, content: str) -> None:
        """Insert or replace the note attached to a graph node."""
        from datetime import datetime, timezone
        self._ensure_session()
        result_key = f"info:{parent_node_id}"
        self._repo()._db.results.update_one(
            {
                "session_id": self._session_id,
                "category":   "info",
                "result_key": result_key,
            },
            {
                "$set": {
                    "data":    {"parent_node_id": parent_node_id, "content": content},
                    "sources": ["manual"],
                },
                "$setOnInsert": {
                    "session_id":  self._session_id,
                    "tool_run_id": self._run_id,
                    "category":    "info",
                    "result_key":  result_key,
                    "created_at":  datetime.now(timezone.utc).isoformat(),
                },
            },
            upsert=True,
        )

    def get_info_note(self, parent_node_id: str) -> str:
        """Return existing note content for a node, or ''."""
        result_key = f"info:{parent_node_id}"
        try:
            doc = self._repo()._db.results.find_one(
                {"session_id": self._session_id,
                 "category": "info", "result_key": result_key},
                {"data.content": 1},
            )
            return (doc or {}).get("data", {}).get("content", "") if doc else ""
        except Exception:
            return ""

    def add_custom_node(
        self, parent_node_id: str, label: str, description: str = ""
    ) -> None:
        from containers.results.models import CustomNode
        self._ensure_session()
        r = CustomNode(
            parent_node_id=parent_node_id,
            label=label,
            description=description,
        )
        r.add_source("manual")
        self._repo().upsert_results(self._session_id, self._run_id, "custom", [r])

    def add_origin_to_cdn(
        self, subdomain: str, provider: str, origin_ip: str
    ) -> bool:
        """Append an origin IP to an existing CDN/RP result, or create one.

        `upsert_results` uses $setOnInsert so it won't touch existing data.
        We need a targeted $addToSet on data.origin_ips for the existing doc.
        """
        if not origin_ip:
            return False
        from containers.results.models import CdnResult
        self._ensure_session()
        repo = self._repo()
        result_key = CdnResult(subdomain=subdomain, provider=provider).key

        # Try to update any existing document across all sessions
        res = repo._db.results.update_one(
            {"category": "cdn", "result_key": result_key},
            {"$addToSet": {"data.origin_ips": origin_ip}},
        )
        if res.matched_count == 0:
            # No existing record anywhere — create one in the manual session
            r = CdnResult(
                subdomain=subdomain, provider=provider,
                origin_masked=True, origin_ips=[origin_ip],
            )
            r.add_source("manual")
            repo.upsert_results(self._session_id, self._run_id, "cdn", [r])
        return True


# ── Manual-entry dialogs ──────────────────────────────────────────────────────

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

    def __init__(
        self,
        parent=None,
        provider: str = "",
        subdomain: str = "",
    ):
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


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class GraphNode:
    id:    str
    kind:  str
    label: str
    data:  dict  = field(default_factory=dict)
    x:     float = 0.0
    y:     float = 0.0


@dataclass
class GraphEdge:
    source_id: str
    target_id: str
    kind:      str
    label:     str = ""


@dataclass
class GraphData:
    nodes: list[GraphNode] = field(default_factory=list)
    edges: list[GraphEdge] = field(default_factory=list)

    def node_map(self) -> dict[str, GraphNode]:
        return {n.id: n for n in self.nodes}


# ── NodeItem ──────────────────────────────────────────────────────────────────

class NodeItem(QGraphicsItem):
    def __init__(self, node: GraphNode):
        super().__init__()
        self._node   = node
        self._edges: list["EdgeItem"] = []
        self._hovered = False

        s = _NS[node.kind]
        self._r      = s["r"]
        self._fill   = QColor(s["fill"])
        self._border = QColor(s["border"])
        self._shape  = s["shape"]

        self.setFlags(
            QGraphicsItem.ItemIsMovable |
            QGraphicsItem.ItemIsSelectable |
            QGraphicsItem.ItemSendsGeometryChanges,
        )
        self.setAcceptHoverEvents(True)
        self.setPos(node.x, node.y)
        self.setZValue(1)
        self._search_match: bool | None = None   # None=no search, True=match, False=dim

    # expose for EdgeItem
    def kind(self) -> str: return self._node.kind
    def node(self) -> GraphNode: return self._node
    def add_edge(self, e: "EdgeItem"): self._edges.append(e)

    def boundingRect(self) -> QRectF:
        # +12 covers the halo (r+9); +26 extra on the bottom covers the label
        # which is drawn at y = r+14 with ~10px text height
        r = self._r + 12
        return QRectF(-r, -r, r * 2, r * 2 + 26)

    def paint(self, painter: QPainter, option, widget=None):
        painter.setRenderHint(QPainter.Antialiasing)
        r = self._r

        # glow halo on hover / selection
        if self._hovered or self.isSelected():
            halo = QColor(self._fill)
            halo.setAlpha(55)
            painter.setPen(Qt.NoPen)
            painter.setBrush(halo)
            er = r + 9
            painter.drawEllipse(QRectF(-er, -er, er * 2, er * 2))

        # selection ring
        if self.isSelected():
            painter.setPen(QPen(QColor("#CDD6F4"), 2, Qt.DotLine))
            painter.setBrush(Qt.NoBrush)
            sr = r + 5
            painter.drawEllipse(QRectF(-sr, -sr, sr * 2, sr * 2))

        fill   = self._fill.lighter(115) if self._hovered else self._fill
        bwidth = 2.5 if self._hovered else 1.5
        painter.setPen(QPen(self._border, bwidth))
        painter.setBrush(QBrush(fill))
        self._draw_shape(painter, r)

        # inner icon
        icon = _KIND_ICON.get(self._node.kind, "")
        if icon:
            f = QFont(); f.setPixelSize(max(8, r - 4))
            painter.setFont(f)
            painter.setPen(QColor("#1E1E2E"))
            fm = painter.fontMetrics()
            painter.drawText(
                QPointF(-fm.horizontalAdvance(icon) / 2, fm.ascent() / 2 - 1),
                icon,
            )

        # label below
        label = self._node.label
        if len(label) > 18:
            label = label[:16] + "…"
        f2 = QFont(); f2.setPixelSize(8 if r < 15 else 9)
        painter.setFont(f2)
        fm2 = painter.fontMetrics()
        painter.setPen(QColor("#BAC2DE"))
        painter.drawText(
            QPointF(-fm2.horizontalAdvance(label) / 2, r + 14),
            label,
        )

        # search highlight ring (drawn last so it is on top)
        if self._search_match is True:
            painter.setPen(QPen(QColor("#FAD866"), 2.5))
            painter.setBrush(Qt.NoBrush)
            rh = r + 7
            painter.drawEllipse(QRectF(-rh, -rh, rh * 2, rh * 2))

    def _draw_shape(self, p: QPainter, r: float):
        s = self._shape
        if s == "circle":
            p.drawEllipse(QRectF(-r, -r, r * 2, r * 2))
        elif s == "diamond":
            poly = QPolygonF([QPointF(0,-r), QPointF(r,0), QPointF(0,r), QPointF(-r,0)])
            p.drawPolygon(poly)
        elif s == "square":
            p.drawRoundedRect(QRectF(-r, -r, r * 2, r * 2), 4, 4)
        elif s == "hexagon":
            pts = [QPointF(r*math.cos(math.pi/6 + i*math.pi/3),
                           r*math.sin(math.pi/6 + i*math.pi/3)) for i in range(6)]
            p.drawPolygon(QPolygonF(pts))
        elif s == "triangle":
            pts = [QPointF(0,-r), QPointF(r*0.866, r*0.5), QPointF(-r*0.866, r*0.5)]
            p.drawPolygon(QPolygonF(pts))
        elif s == "shield":
            pts = [
                QPointF(-r,  -r * 0.65),
                QPointF( r,  -r * 0.65),
                QPointF( r,   r * 0.15),
                QPointF( 0,   r),
                QPointF(-r,   r * 0.15),
            ]
            p.drawPolygon(QPolygonF(pts))
        elif s == "note":
            # Rectangle with folded top-right corner (sticky-note silhouette)
            fold = r * 0.55
            body = QPolygonF([
                QPointF(-r, -r), QPointF(fold, -r),
                QPointF(r, -fold), QPointF(r, r),
                QPointF(-r, r),
            ])
            p.drawPolygon(body)
            # Folded corner triangle (slightly darker shade via border pen, no fill)
            old_brush = p.brush()
            p.setBrush(p.pen().color())
            p.drawPolygon(QPolygonF([
                QPointF(fold, -r), QPointF(r, -fold), QPointF(fold, -fold),
            ]))
            p.setBrush(old_brush)
        else:
            p.drawEllipse(QRectF(-r, -r, r * 2, r * 2))

    def itemChange(self, change, value):
        if change == QGraphicsItem.ItemPositionHasChanged:
            for e in self._edges:
                e.adjust()
            x, y = self.x(), self.y()
            self._node.x, self._node.y = x, y
            sc = self.scene()
            if sc is not None:
                sc._pos_cache[self._node.id] = (x, y)
                sc._save_timer.start()   # debounced: fires 1.5 s after last move
        return super().itemChange(change, value)

    def hoverEnterEvent(self, ev):
        self._hovered = True
        self.update()
        super().hoverEnterEvent(ev)

    def hoverLeaveEvent(self, ev):
        self._hovered = False
        self.update()
        super().hoverLeaveEvent(ev)

    def mousePressEvent(self, ev):
        if ev.button() == Qt.LeftButton:
            sc = self.scene()
            if sc and hasattr(sc, "nodeClicked"):
                sc.nodeClicked.emit(self._node)
        super().mousePressEvent(ev)

    def mouseReleaseEvent(self, ev):
        super().mouseReleaseEvent(ev)

    def contextMenuEvent(self, ev):
        kind = self._node.kind
        menu = QMenu()
        menu.setStyleSheet(_MENU_SS)

        sc = self.scene()
        nid = self._node.id

        # ── Kind-specific section ─────────────────────────────────────────────
        kind_actions: dict = {}   # QAction → callable
        copy_val: str | None = None

        if kind == "target":
            menu.addSection("Add to graph")
            kind_actions[menu.addAction("◉  Add Subdomain")] = \
                lambda: sc.addDataRequested.emit("add_subdomain", self._node)
            kind_actions[menu.addAction("△  Add OSINT Finding")] = \
                lambda: sc.addDataRequested.emit("add_osint", self._node)

        elif kind == "subdomain":
            menu.addSection(f"◉ {self._node.label}")
            kind_actions[menu.addAction("◆  Add IP Address")] = \
                lambda: sc.addDataRequested.emit("add_ip", self._node)
            kind_actions[menu.addAction("▣  Add Port / Service")] = \
                lambda: sc.addDataRequested.emit("add_port", self._node)
            kind_actions[menu.addAction("⬡  Add Technology")] = \
                lambda: sc.addDataRequested.emit("add_tech", self._node)
            kind_actions[menu.addAction("⚠  Add Vulnerability")] = \
                lambda: sc.addDataRequested.emit("add_vuln", self._node)
            kind_actions[menu.addAction("↗  Add Endpoint")] = \
                lambda: sc.addDataRequested.emit("add_endpoint", self._node)
            kind_actions[menu.addAction("⊕  Add CDN / Proxy")] = \
                lambda: sc.addDataRequested.emit("add_cdn", self._node)
            menu.addSeparator()
            kind_actions[menu.addAction("△  Add OSINT Finding")] = \
                lambda: sc.addDataRequested.emit("add_osint", self._node)

        elif kind == "ip":
            menu.addSection(f"◆ {self._node.label}")
            kind_actions[menu.addAction("▣  Add Port / Service")] = \
                lambda: sc.addDataRequested.emit("add_port", self._node)

        elif kind == "port":
            menu.addSection(f"▣ {self._node.label}")
            kind_actions[menu.addAction("⬡  Add Technology")] = \
                lambda: sc.addDataRequested.emit("add_tech", self._node)
            kind_actions[menu.addAction("⚠  Add Vulnerability")] = \
                lambda: sc.addDataRequested.emit("add_vuln", self._node)
            kind_actions[menu.addAction("↗  Add Endpoint")] = \
                lambda: sc.addDataRequested.emit("add_endpoint", self._node)

        elif kind in ("cdn", "reverse_proxy"):
            pt = self._node.data.get("proxy_type", "CDN")
            ico = "⇄" if kind == "reverse_proxy" else "⊕"
            menu.addSection(f"{ico}  {self._node.label}  [{pt}]")
            kind_actions[menu.addAction("↪  Add Origin Server")] = \
                lambda: sc.addDataRequested.emit("add_origin_server", self._node)
            copy_val = self._node.label

        elif kind == "endpoint":
            d = self._node.data
            menu.addSection(f"↗ {self._node.label}")
            is_exp = nid in getattr(sc, "_expanded_nodes", set())
            ep_lbl = "?  Hide Parameters" if is_exp else "?  Show Parameters"
            kind_actions[menu.addAction(ep_lbl)] = \
                lambda: sc.toggle_children(nid)
            copy_val = d.get("url", self._node.label)

        elif kind == "param":
            d = self._node.data
            menu.addSection(f"? {self._node.label}")
            copy_val = d.get("example", d.get("name", self._node.label))

        elif kind == "info":
            menu.addSection(f"✎  Note")
            kind_actions[menu.addAction("✎  Edit Note")] = \
                lambda: sc.addDataRequested.emit("edit_info", self._node)
            copy_val = self._node.data.get("content", "")

        elif kind == "custom":
            menu.addSection(f"＋  {self._node.label}")
            copy_val = self._node.data.get("description", self._node.label)

        else:
            # vuln / tech / osint
            copy_val = (self._node.data.get("value") or
                        self._node.data.get("tech") or
                        self._node.label)

        # ── Universal "Endpoints" toggle for subdomain ────────────────────────
        if kind == "subdomain" and sc is not None:
            is_exp = nid in getattr(sc, "_expanded_nodes", set())
            ep_lbl = "↗  Hide Endpoints" if is_exp else "↗  Show Endpoints"
            menu.addSeparator()
            kind_actions[menu.addAction(ep_lbl)] = \
                lambda: sc.toggle_children(nid)

        # ── Universal actions on every node ───────────────────────────────────
        menu.addSeparator()

        # Note: check if a note already exists for this node in the scene
        info_id = f"info:{nid}"
        has_note = info_id in getattr(sc, "_node_items", {})
        note_lbl = "✎  Edit Note" if has_note else "✎  Add Note"
        a_note = menu.addAction(note_lbl)

        # Don't offer "add custom node" on info/custom nodes themselves
        a_custom = None
        if kind not in ("info",):
            a_custom = menu.addAction("＋  Add Custom Node here")

        if copy_val is not None:
            a_copy = menu.addAction("⎘  Copy")
            kind_actions[a_copy] = lambda: QApplication.clipboard().setText(copy_val)

        menu.addSeparator()
        is_focused = getattr(sc, "_focused_id", None) == nid
        a_focus = menu.addAction(
            "⊗  Unfocus (show all)" if is_focused else "◎  Focus: show only this + neighbors"
        )

        chosen = menu.exec(ev.screenPos())
        if chosen == a_focus:
            if is_focused:
                sc.unfocus()
            else:
                sc.focus_node(nid)
        elif chosen == a_note:
            sc.addDataRequested.emit(
                "edit_info" if has_note else "add_info", self._node
            )
        elif a_custom and chosen == a_custom:
            sc.addDataRequested.emit("add_custom", self._node)
        elif chosen in kind_actions:
            kind_actions[chosen]()

        ev.accept()


# ── EdgeItem ──────────────────────────────────────────────────────────────────

class EdgeItem(QGraphicsItem):
    def __init__(self, src: NodeItem, tgt: NodeItem, kind: str):
        super().__init__()
        self._src   = src
        self._tgt   = tgt
        self._kind  = kind
        self._color = QColor(_EC.get(kind, "#585B70"))
        self._sp    = QPointF()
        self._tp    = QPointF()
        self.setFlag(QGraphicsItem.ItemIsSelectable, False)
        self.setZValue(0)
        src.add_edge(self)
        tgt.add_edge(self)
        self.adjust()

    def adjust(self):
        self.prepareGeometryChange()
        self._sp = self._src.mapToScene(QPointF(0, 0))
        self._tp = self._tgt.mapToScene(QPointF(0, 0))

    def boundingRect(self) -> QRectF:
        x1, y1 = self._sp.x(), self._sp.y()
        x2, y2 = self._tp.x(), self._tp.y()
        return QRectF(
            min(x1, x2) - 12, min(y1, y2) - 12,
            abs(x2 - x1) + 24, abs(y2 - y1) + 24,
        )

    def paint(self, painter: QPainter, option, widget=None):
        painter.setRenderHint(QPainter.Antialiasing)
        sp, tp = self._sp, self._tp
        dx, dy = tp.x() - sp.x(), tp.y() - sp.y()
        d = math.hypot(dx, dy)
        if d < 1:
            return

        sr = _NS[self._src.kind()]["r"]
        tr = _NS[self._tgt.kind()]["r"]
        # offset endpoints to node edges
        x1 = sp.x() + dx / d * sr
        y1 = sp.y() + dy / d * sr
        x2 = tp.x() - dx / d * (tr + 8)
        y2 = tp.y() - dy / d * (tr + 8)

        pen = QPen(self._color, 1.2)
        if self._kind in _DASHED:
            pen.setStyle(Qt.DashLine)
        painter.setPen(pen)
        painter.setBrush(Qt.NoBrush)
        painter.drawLine(QPointF(x1, y1), QPointF(x2, y2))

        # arrowhead
        angle = math.atan2(dy, dx)
        aw = 7
        p1 = QPointF(x2 - aw * math.cos(angle - 0.4),
                     y2 - aw * math.sin(angle - 0.4))
        p2 = QPointF(x2 - aw * math.cos(angle + 0.4),
                     y2 - aw * math.sin(angle + 0.4))
        painter.setPen(Qt.NoPen)
        painter.setBrush(self._color)
        painter.drawPolygon(QPolygonF([QPointF(x2, y2), p1, p2]))


# ── Scene ─────────────────────────────────────────────────────────────────────

class NetworkGraphScene(QGraphicsScene):
    nodeClicked      = Signal(object)          # GraphNode
    addDataRequested = Signal(str, object)     # action_key, GraphNode | None
    focusChanged     = Signal(bool)            # True = focused, False = normal

    def __init__(self, project_dir: str = "", target: str = "", parent=None):
        super().__init__(parent)
        self._node_items:    dict[str, NodeItem]            = {}
        self._edge_items:    list[EdgeItem]                 = []
        self._pos_cache:     dict[str, tuple[float, float]] = {}
        self._project_dir:   str = project_dir
        self._target:        str = target
        self._expanded_nodes: set[str] = set()   # nodes whose hidden children are shown
        self._focused_id:    str | None = None    # node being focused (None = show all)
        self._search_query:  str = ""             # active search (empty = inactive)

        # Debounce timer: write positions to DB 1.5 s after the last drag ends
        self._save_timer = QTimer(self)
        self._save_timer.setSingleShot(True)
        self._save_timer.setInterval(1500)
        self._save_timer.timeout.connect(self._flush_positions)

        # Pre-populate cache from DB so build() can apply saved positions immediately
        if project_dir and target:
            self._load_positions()

    # ── Public ────────────────────────────────────────────────────────────────

    def build(self, data: GraphData) -> None:
        """Full rebuild. Hierarchy layout for visible nodes; child layout for
        hidden-by-default nodes; cached positions override both."""
        self.clear()
        self._node_items.clear()
        self._edge_items.clear()
        self._expanded_nodes.clear()
        self._focused_id = None

        if not data.nodes:
            return

        self._hierarchy_layout(data)   # positions visible-kind nodes
        self._child_layout(data)       # positions endpoint/param relative to parents
        for node in data.nodes:        # cached positions win
            if node.id in self._pos_cache:
                node.x, node.y = self._pos_cache[node.id]

        self._bulk_add(data)
        self._refresh_visibility()

    def merge(self, data: GraphData) -> None:
        """Incremental refresh: add new nodes/edges, remove stale ones.
        All existing node positions are left exactly where they are."""
        new_ids  = {n.id for n in data.nodes}
        new_ekeys: set[tuple] = set()
        for e in data.edges:
            new_ekeys.add((e.source_id, e.target_id, e.kind))

        views = self.views()
        for v in views:
            v.setUpdatesEnabled(False)
        try:
            # ── Remove stale nodes ────────────────────────────────────────────
            stale = [nid for nid in list(self._node_items) if nid not in new_ids]
            for nid in stale:
                self.removeItem(self._node_items.pop(nid))

            # ── Remove stale edges ────────────────────────────────────────────
            live_edges = []
            for ei in self._edge_items:
                ek = (ei._src.node().id, ei._tgt.node().id, ei._kind)
                if ek in new_ekeys and ei._src.node().id not in stale and ei._tgt.node().id not in stale:
                    live_edges.append(ei)
                else:
                    self.removeItem(ei)
            self._edge_items = live_edges

            # ── Position genuinely new nodes ──────────────────────────────────
            truly_new = [n for n in data.nodes if n.id not in self._node_items]
            if truly_new:
                # Run hierarchy on the full dataset to get sensible positions
                self._hierarchy_layout(data)
                # Override existing nodes' layout coords with their live positions
                for nid, item in self._node_items.items():
                    node = next((n for n in data.nodes if n.id == nid), None)
                    if node:
                        node.x, node.y = item.x(), item.y()
                # Position new hidden-by-default nodes relative to their parents
                self._child_layout(data, {n.id for n in truly_new})
                # Apply cache to new nodes (handles re-added nodes the user moved before)
                for node in truly_new:
                    if node.id in self._pos_cache:
                        node.x, node.y = self._pos_cache[node.id]
                for node in truly_new:
                    item = NodeItem(node)
                    self.addItem(item)
                    self._node_items[node.id] = item

            # ── Add new edges ─────────────────────────────────────────────────
            live_ekeys = {(ei._src.node().id, ei._tgt.node().id, ei._kind)
                          for ei in self._edge_items}
            nmap = self._node_items
            for edge in data.edges:
                ek = (edge.source_id, edge.target_id, edge.kind)
                if ek not in live_ekeys:
                    si, ti = nmap.get(edge.source_id), nmap.get(edge.target_id)
                    if si and ti:
                        ei = EdgeItem(si, ti, edge.kind)
                        self.addItem(ei)
                        self._edge_items.append(ei)
                        live_ekeys.add(ek)
        finally:
            for v in views:
                v.setUpdatesEnabled(True)
        self._refresh_visibility()

    def reset_layout(self, data: GraphData) -> None:
        """Wipe position cache, persist the wipe to DB, then do a clean rebuild."""
        self._save_timer.stop()
        self._pos_cache.clear()
        self._expanded_nodes.clear()
        self._focused_id = None
        self._flush_positions()
        self.build(data)
        self.focusChanged.emit(False)

    # ── Visibility management ─────────────────────────────────────────────────

    def _refresh_visibility(self) -> None:
        """Recompute visibility for every node and edge from scratch.

        Two orthogonal rules (both must pass for a node to be visible):
          1. hidden-by-default rule: endpoint/param nodes are visible only if
             their parent node is in _expanded_nodes.
          2. focus rule: if _focused_id is set, only nodes in the 1-hop
             neighbourhood of the focused node are visible.
        """
        # Build parent map: child_id → parent_id  (for hidden-by-default checks)
        parent_of: dict[str, str] = {}
        for ei in self._edge_items:
            if ei._kind in _CHILD_EDGE_KINDS:
                parent_of[ei._tgt.node().id] = ei._src.node().id

        # Focus neighbourhood
        focus_ids: set[str] | None = (
            self._neighbor_ids(self._focused_id)
            if self._focused_id and self._focused_id in self._node_items
            else None
        )

        for nid, item in self._node_items.items():
            kind = item.node().kind
            if kind in _HIDDEN_BY_DEFAULT:
                base_vis = parent_of.get(nid) in self._expanded_nodes
            else:
                base_vis = True

            visible = base_vis if focus_ids is None else (nid in focus_ids)
            item.setVisible(visible)

        # Edges: both endpoints must be visible
        for ei in self._edge_items:
            s = self._node_items.get(ei._src.node().id)
            t = self._node_items.get(ei._tgt.node().id)
            ei.setVisible(
                s is not None and s.isVisible() and
                t is not None and t.isVisible()
            )
        self.update()

    def _neighbor_ids(self, node_id: str) -> set[str]:
        """Return node_id + all nodes directly connected to it by any edge."""
        ids: set[str] = {node_id}
        for ei in self._edge_items:
            if ei._src.node().id == node_id:
                ids.add(ei._tgt.node().id)
            elif ei._tgt.node().id == node_id:
                ids.add(ei._src.node().id)
        return ids

    def focus_node(self, node_id: str) -> None:
        """Show only the given node and its 1-hop neighbours. Hides everything else."""
        self._focused_id = node_id
        self._refresh_visibility()
        self.focusChanged.emit(True)

    def unfocus(self) -> None:
        """Restore normal visibility (hidden-by-default rule only)."""
        self._focused_id = None
        self._refresh_visibility()
        self.focusChanged.emit(False)

    # ── Graph search ──────────────────────────────────────────────────────────

    def set_search(self, query: str) -> None:
        """Highlight nodes matching query; dim everything else.
        Empty query restores normal visibility."""
        self._search_query = query.strip().lower()
        if not self._search_query:
            for item in self._node_items.values():
                item._search_match = None
                item.update()
            self._refresh_visibility()
            return
        # Search mode: override visibility — show ALL nodes, apply opacity
        for nid, item in self._node_items.items():
            match = self._node_matches(item.node(), self._search_query)
            item._search_match = match
            item.setVisible(True)
            item.setOpacity(1.0 if match else 0.08)
            item.update()
        for ei in self._edge_items:
            sm = self._node_items.get(ei._src.node().id)
            tm = self._node_items.get(ei._tgt.node().id)
            ei.setVisible(
                bool(sm and sm._search_match) and bool(tm and tm._search_match)
            )
        self.update()

    @staticmethod
    def _node_matches(node: "GraphNode", q: str) -> bool:
        if q in node.label.lower():
            return True
        for v in node.data.values():
            if isinstance(v, str) and q in v.lower():
                return True
            if isinstance(v, list):
                for item in v:
                    if isinstance(item, str) and q in item.lower():
                        return True
        return False

    def toggle_children(self, node_id: str) -> bool:
        """Toggle visibility of hidden-by-default children of node_id.

        The node_id is the PARENT (subdomain → endpoints, endpoint → params).
        Returns True if children are now expanded, False if collapsed.
        """
        if node_id in self._expanded_nodes:
            self._expanded_nodes.discard(node_id)
            # Collapse any endpoint children that were themselves expanded
            for ei in self._edge_items:
                if ei._src.node().id == node_id and ei._kind in _CHILD_EDGE_KINDS:
                    self._expanded_nodes.discard(ei._tgt.node().id)
            self._refresh_visibility()
            return False
        else:
            self._expanded_nodes.add(node_id)
            self._refresh_visibility()
            return True

    # ── Position persistence ──────────────────────────────────────────────────

    def _load_positions(self) -> None:
        try:
            from database.mongo import load_graph_positions
            saved = load_graph_positions(self._project_dir, self._target)
            self._pos_cache.update(saved)
        except Exception as exc:
            logger.debug("Could not load graph positions: %s", exc)

    def _flush_positions(self) -> None:
        if not (self._project_dir and self._target):
            return
        try:
            from database.mongo import save_graph_positions
            save_graph_positions(
                self._project_dir, self._target, dict(self._pos_cache)
            )
        except Exception as exc:
            logger.debug("Could not save graph positions: %s", exc)

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _bulk_add(self, data: GraphData) -> None:
        """Add all nodes and edges with a single repaint at the end."""
        views = self.views()
        for v in views:
            v.setUpdatesEnabled(False)
        try:
            for node in data.nodes:
                item = NodeItem(node)
                self.addItem(item)
                self._node_items[node.id] = item

            nmap = self._node_items
            for edge in data.edges:
                si, ti = nmap.get(edge.source_id), nmap.get(edge.target_id)
                if si and ti:
                    ei = EdgeItem(si, ti, edge.kind)
                    self.addItem(ei)
                    self._edge_items.append(ei)
        finally:
            for v in views:
                v.setUpdatesEnabled(True)
        self.update()

    # ── Layouts ───────────────────────────────────────────────────────────────

    def _child_layout(
        self,
        data: GraphData,
        only_ids: set[str] | None = None,
    ) -> None:
        """Position hidden-by-default nodes (endpoints, params) relative to
        their parents. When only_ids is given, only positions nodes in that set."""
        nmap = {n.id: n for n in data.nodes}
        from collections import defaultdict
        ep_kids:  dict[str, list[str]] = defaultdict(list)  # subdomain → [endpoint]
        pm_kids:  dict[str, list[str]] = defaultdict(list)  # endpoint  → [param]
        for e in data.edges:
            if e.kind == "has_endpoint":
                ep_kids[e.source_id].append(e.target_id)
            elif e.kind == "has_param":
                pm_kids[e.source_id].append(e.target_id)

        X_EP, Y_EP = 200, 26    # endpoint offset from parent
        X_PM, Y_PM = 170, 18    # param offset from endpoint

        for parent_id, ep_ids in ep_kids.items():
            parent = nmap.get(parent_id)
            if not parent:
                continue
            n = len(ep_ids)
            for i, ep_id in enumerate(ep_ids):
                if only_ids and ep_id not in only_ids:
                    continue
                ep = nmap.get(ep_id)
                if not ep or ep_id in self._pos_cache:
                    continue
                ep.x = parent.x + X_EP
                ep.y = parent.y + (i - n / 2.0) * Y_EP

                param_ids = pm_kids.get(ep_id, [])
                m = len(param_ids)
                for j, pm_id in enumerate(param_ids):
                    if only_ids and pm_id not in only_ids:
                        continue
                    pm = nmap.get(pm_id)
                    if not pm or pm_id in self._pos_cache:
                        continue
                    pm.x = ep.x + X_PM
                    pm.y = ep.y + (j - m / 2.0) * Y_PM

    def _hierarchy_layout(self, data: GraphData):
        # Only layout visible-kind nodes (skip hidden-by-default kinds so they
        # don't affect spacing of the main graph)
        nmap = {n.id: n for n in data.nodes
                if n.kind not in _HIDDEN_BY_DEFAULT}
        children: dict[str, list[str]] = {n.id: [] for n in data.nodes
                                          if n.id in nmap}
        for e in data.edges:
            if e.source_id in children and e.target_id in nmap:
                children[e.source_id].append(e.target_id)

        targets = [n for n in data.nodes if n.kind == "target"]
        if not targets:
            return

        visited: set[str] = set()
        levels: list[list[str]] = [[targets[0].id]]
        visited.add(targets[0].id)

        while True:
            next_lvl = []
            for nid in levels[-1]:
                for c in children.get(nid, []):
                    if c not in visited:
                        visited.add(c)
                        next_lvl.append(c)
            if not next_lvl:
                break
            levels.append(next_lvl)

        x_gap, y_gap = 170, 80
        for lvl_i, level in enumerate(levels):
            n = len(level)
            for i, nid in enumerate(level):
                node = nmap[nid]
                node.x = lvl_i * x_gap
                node.y = (i - n / 2.0) * y_gap

    # ── Background dot grid ───────────────────────────────────────────────────

    def drawBackground(self, painter: QPainter, rect: QRectF):
        import math
        painter.fillRect(rect, QColor("#181825"))

        l, t, r, b = rect.left(), rect.top(), rect.right(), rect.bottom()
        # Guard: scene rect can be NaN when empty, or astronomically large when zoomed out
        if not (math.isfinite(l) and math.isfinite(t) and
                math.isfinite(r) and math.isfinite(b)):
            return
        _MAX = 40_000
        l, t = max(l, -_MAX), max(t, -_MAX)
        r, b = min(r,  _MAX), min(b,  _MAX)

        gs = 40
        painter.setPen(QPen(QColor("#252538"), 1))
        lx = int(l) - (int(l) % gs)
        ty = int(t) - (int(t) % gs)
        x = lx
        while x < r:
            y = ty
            while y < b:
                painter.drawPoint(x, y)
                y += gs
            x += gs


# ── View ──────────────────────────────────────────────────────────────────────

class NetworkGraphView(QGraphicsView):
    def __init__(self, scene: NetworkGraphScene, parent=None):
        super().__init__(scene, parent)
        self.setRenderHints(
            QPainter.Antialiasing |
            QPainter.TextAntialiasing |
            QPainter.SmoothPixmapTransform,
        )
        self.setViewportUpdateMode(QGraphicsView.FullViewportUpdate)
        self.setDragMode(QGraphicsView.NoDrag)
        self.setTransformationAnchor(QGraphicsView.AnchorUnderMouse)
        self.setResizeAnchor(QGraphicsView.AnchorViewCenter)
        self.setFrameShape(QFrame.NoFrame)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self._panning   = False
        self._pan_start = QPointF()

    def wheelEvent(self, ev):
        factor = 1.18 if ev.angleDelta().y() > 0 else 1 / 1.18
        self.scale(factor, factor)

    def mousePressEvent(self, ev):
        if ev.button() == Qt.MiddleButton:
            self._panning   = True
            self._pan_start = ev.position()
            self.setCursor(Qt.ClosedHandCursor)
            ev.accept(); return
        super().mousePressEvent(ev)

    def contextMenuEvent(self, ev):
        item = self.itemAt(ev.pos())
        if item is not None:
            # Let the scene dispatch to the NodeItem's contextMenuEvent
            super().contextMenuEvent(ev)
            return
        # Canvas right-click
        sc = self.scene()
        if not hasattr(sc, "addDataRequested"):
            return
        menu = QMenu(self)
        menu.setStyleSheet(_MENU_SS)
        menu.addSection("Add to graph")
        a_sub   = menu.addAction("◉  Add Subdomain")
        a_osint = menu.addAction("△  Add OSINT Finding")
        menu.addSeparator()
        a_vuln  = menu.addAction("⚠  Add Vulnerability")
        a_ep    = menu.addAction("↗  Add Endpoint")
        chosen = menu.exec(ev.globalPos())
        if chosen == a_sub:
            sc.addDataRequested.emit("add_subdomain", None)
        elif chosen == a_osint:
            sc.addDataRequested.emit("add_osint", None)
        elif chosen == a_vuln:
            sc.addDataRequested.emit("add_vuln", None)
        elif chosen == a_ep:
            sc.addDataRequested.emit("add_endpoint", None)

    def mouseMoveEvent(self, ev):
        if self._panning:
            d = ev.position() - self._pan_start
            self._pan_start = ev.position()
            self.horizontalScrollBar().setValue(
                self.horizontalScrollBar().value() - int(d.x()))
            self.verticalScrollBar().setValue(
                self.verticalScrollBar().value() - int(d.y()))
            ev.accept(); return
        super().mouseMoveEvent(ev)

    def mouseReleaseEvent(self, ev):
        if self._panning:
            self._panning = False
            self.setCursor(Qt.ArrowCursor)
            ev.accept(); return
        super().mouseReleaseEvent(ev)

    def mouseDoubleClickEvent(self, ev):
        if not self.itemAt(ev.pos()):
            self.fit_all()
        super().mouseDoubleClickEvent(ev)

    def keyPressEvent(self, ev):
        if ev.key() == Qt.Key_F:
            self.fit_all()
        super().keyPressEvent(ev)

    def fit_all(self):
        br = self.scene().itemsBoundingRect()
        if not br.isEmpty():
            self.fitInView(br.adjusted(-30, -30, 30, 30), Qt.KeepAspectRatio)


# ── Detail panel ──────────────────────────────────────────────────────────────

class DetailPanel(QWidget):
    openInBrowser = Signal(str)

    _BTN = """
        QPushButton {
            background:#252540; color:#CDD6F4;
            border:1px solid #313244; border-radius:5px;
            font-size:10px; text-align:left; padding:0 10px;
            min-height:28px;
        }
        QPushButton:hover { background:#313244; border-color:%s; color:%s; }
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedWidth(260)
        self.setStyleSheet("background:#1E1E2E;")

        vb = QVBoxLayout(self)
        vb.setContentsMargins(10, 12, 10, 12)
        vb.setSpacing(8)

        self._icon_lbl = QLabel("○")
        self._icon_lbl.setStyleSheet("font-size:30px; color:#6C7086; background:transparent;")
        self._icon_lbl.setAlignment(Qt.AlignCenter)
        vb.addWidget(self._icon_lbl)

        self._title = QLabel("Select a node")
        self._title.setStyleSheet(
            "color:#CDD6F4; font-size:11px; font-weight:bold; background:transparent;")
        self._title.setAlignment(Qt.AlignCenter)
        self._title.setWordWrap(True)
        vb.addWidget(self._title)

        div = QFrame(); div.setFrameShape(QFrame.HLine)
        div.setStyleSheet("background:#313244; border:none;"); div.setFixedHeight(1)
        vb.addWidget(div)

        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setFrameShape(QFrame.NoFrame)
        self._scroll.setStyleSheet("background:#1E1E2E; border:none;")
        self._body = QWidget(); self._body.setStyleSheet("background:#1E1E2E;")
        self._body_vb = QVBoxLayout(self._body)
        self._body_vb.setContentsMargins(0, 0, 0, 0)
        self._body_vb.setSpacing(4)
        self._body_vb.addStretch()
        self._scroll.setWidget(self._body)
        vb.addWidget(self._scroll, stretch=1)

        self._act_vb = QVBoxLayout()
        self._act_vb.setSpacing(5)
        vb.addLayout(self._act_vb)

        self._empty_label = QLabel("Click any node to\nsee its details here.")
        self._empty_label.setStyleSheet(
            "color:#45475A; font-size:10px; background:transparent;")
        self._empty_label.setAlignment(Qt.AlignCenter)
        self._body_vb.insertWidget(0, self._empty_label)

    # ── Public ────────────────────────────────────────────────────────────────

    def show_node(self, node: GraphNode):
        s = _NS[node.kind]
        self._icon_lbl.setText(_KIND_ICON.get(node.kind, "○"))
        self._icon_lbl.setStyleSheet(
            f"font-size:30px; color:{s['fill']}; background:transparent;")
        self._title.setText(node.label)

        self._clear_body()
        self._clear_actions()

        self._add_row("Type", node.kind.upper(), s["fill"])
        for key, value in node.data.items():
            if isinstance(value, list):
                value = ", ".join(str(v) for v in value) or "—"
            if value:
                self._add_row(key.replace("_", " ").title(), str(value))

        url = node.data.get("url") or node.data.get("domain")
        if url:
            href = url if url.startswith("http") else f"https://{url}"
            self._add_action("◉  Open in Browser", "#89B4FA",
                             lambda u=href: self.openInBrowser.emit(u))

        copy_val = (node.data.get("ip") or node.data.get("domain") or
                    node.data.get("value") or node.label)
        if copy_val:
            lbl = copy_val[:22] + ("…" if len(copy_val) > 22 else "")
            self._add_action(f"⎘  Copy: {lbl}", "#6C7086",
                             lambda v=copy_val: QApplication.clipboard().setText(v))

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _clear_body(self):
        while self._body_vb.count() > 1:
            it = self._body_vb.takeAt(0)
            if it.widget():
                it.widget().deleteLater()

    def _clear_actions(self):
        while self._act_vb.count():
            it = self._act_vb.takeAt(0)
            if it.widget():
                it.widget().deleteLater()

    def _add_row(self, key: str, value: str, accent: str = "#45475A"):
        row = QWidget()
        row.setStyleSheet(
            "QWidget{background:#252540;border-radius:4px;}"
            "QLabel{background:transparent;border:none;}")
        hl = QHBoxLayout(row)
        hl.setContentsMargins(8, 5, 8, 5)
        hl.setSpacing(8)
        kl = QLabel(key)
        kl.setStyleSheet("color:#6C7086;font-size:9px;")
        kl.setFixedWidth(76)
        hl.addWidget(kl)
        vl = QLabel(value)
        vl.setStyleSheet("color:#CDD6F4;font-size:9px;")
        vl.setWordWrap(True)
        hl.addWidget(vl, stretch=1)
        idx = max(self._body_vb.count() - 1, 0)
        self._body_vb.insertWidget(idx, row)

    def _add_action(self, label: str, color: str, fn):
        btn = QPushButton(label)
        btn.setStyleSheet(self._BTN % (color, color))
        btn.clicked.connect(fn)
        self._act_vb.addWidget(btn)


# ── Background data loader ────────────────────────────────────────────────────

class GraphDataLoader(QThread):
    loaded = Signal(object)   # GraphData
    error  = Signal(str)

    def __init__(self, project_dir: str, target: str, parent=None):
        super().__init__(parent)
        self._project_dir = project_dir
        self._target      = target

    def run(self):
        try:
            from database.repository import AweRepository
            repo = AweRepository(self._project_dir)
            self.loaded.emit(self._build(repo))
        except Exception as exc:
            logger.exception("GraphDataLoader failed")
            self.error.emit(str(exc))

    def _build(self, repo) -> GraphData:
        from urllib.parse import urlsplit

        nodes: dict[str, GraphNode] = {}
        edges: dict[tuple, GraphEdge] = {}
        target = self._target

        def _node(nid, kind, label, data=None):
            if nid not in nodes:
                nodes[nid] = GraphNode(nid, kind, label, data or {})
            elif kind in ("cdn", "reverse_proxy") and data:
                # Multiple sessions may report the same CDN/RP — merge.
                ex = nodes[nid]
                # Accumulate origin IPs
                ex_ips = ex.data.setdefault("origin_ips", [])
                for ip in (data.get("origin_ips") or []):
                    if ip and ip not in ex_ips:
                        ex_ips.append(ip)
                # Prefer the most informative proxy_type
                new_pt = data.get("proxy_type", "")
                if "reverse proxy" in new_pt.lower():
                    ex.data["proxy_type"] = new_pt
                    ex.kind = "reverse_proxy"  # upgrade kind in-place

        def _edge(src, tgt, kind):
            k = (src, tgt, kind)
            if k not in edges:
                edges[k] = GraphEdge(src, tgt, kind)

        root_id = f"target:{target}"
        _node(root_id, "target", target, {"domain": target})

        for session in repo.list_sessions():
            sid = session["id"]

            # ── subdomains ────────────────────────────────────────────────────
            for r in repo.get_results(sid, "subdomain"):
                d = r.get("data", {})
                dom = d.get("domain", "")
                if not dom:
                    continue
                nid = f"subdomain:{dom}"
                _node(nid, "subdomain", dom, {
                    "domain": dom,
                    "ips": d.get("ip_addresses", []),
                    "sources": r.get("sources", []),
                })
                _edge(root_id, nid, "has_subdomain")
                for ip in d.get("ip_addresses", []):
                    if not ip:
                        continue
                    ip_id = f"ip:{ip}"
                    _node(ip_id, "ip", ip, {"ip": ip})
                    _edge(nid, ip_id, "resolves_to")

            # ── port scan ─────────────────────────────────────────────────────
            for r in repo.get_results(sid, "portscan"):
                d = r.get("data", {})
                host, port = d.get("host", ""), d.get("port", 0)
                if not host or not port:
                    continue
                ip_id = f"ip:{host}"
                _node(ip_id, "ip", host, {"ip": host})
                svc = d.get("service", "")
                proto = d.get("protocol", "tcp")
                label = f"{port}/{proto}" + (f" {svc}" if svc else "")
                port_id = f"port:{host}:{port}"
                _node(port_id, "port", label, {
                    "host": host, "port": port,
                    "protocol": proto, "service": svc,
                    "version": d.get("version", ""),
                })
                _edge(ip_id, port_id, "has_port")

            # ── live HTTP hosts / technologies ────────────────────────────────
            for r in repo.get_results(sid, "http"):
                d   = r.get("data", {})
                url = d.get("url", "")
                if not url:
                    continue
                try:
                    host = urlsplit(url).netloc
                except Exception:
                    host = ""
                if not host:
                    continue
                sub_id = f"subdomain:{host}"
                _node(sub_id, "subdomain", host, {
                    "domain": host,
                    "status": d.get("status_code", ""),
                    "title":  d.get("title", ""),
                })
                _edge(root_id, sub_id, "has_subdomain")

                port_num = 443 if url.startswith("https") else 80
                port_id  = f"port:{host}:{port_num}"
                _node(port_id, "port", f"{port_num}/tcp", {
                    "host": host, "port": port_num, "url": url,
                    "status": d.get("status_code", ""),
                    "title":  d.get("title", ""),
                })
                ip_id = f"ip:{host}"
                parent_id = ip_id if ip_id in nodes else sub_id
                _edge(parent_id, port_id, "has_port")

                for tech in d.get("technologies", []):
                    tech_lower = tech.lower()
                    cdn_match  = next(
                        ((prov, ptype) for key, (prov, ptype) in _CDN_TECH_MAP.items()
                         if key in tech_lower),
                        None,
                    )
                    if cdn_match:
                        provider, proxy_type = cdn_match
                        kind   = _cdn_node_kind(proxy_type)
                        cdn_id = f"cdn:{provider.lower()}:{host}"
                        _node(cdn_id, kind, provider, {
                            "provider":      provider,
                            "proxy_type":    proxy_type,
                            "proxied_host":  host,
                            "origin_masked": True,
                            "origin_ips":    [],
                            "bypass_hints":  [],
                        })
                        edge_kind = "routes_through" if kind == "reverse_proxy" else "proxied_by"
                        _edge(sub_id, cdn_id, edge_kind)
                    else:
                        tech_id = f"tech:{tech}"
                        _node(tech_id, "tech", tech, {"tech": tech})
                        _edge(port_id, tech_id, "uses_tech")

            # ── CDN / reverse proxy (explicit results) ────────────────────────
            for r in repo.get_results(sid, "cdn"):
                d         = r.get("data", {})
                provider  = d.get("provider", "")
                subdomain = d.get("subdomain", "")
                if not provider:
                    continue
                proxy_type = d.get("proxy_type", "CDN")
                kind       = _cdn_node_kind(proxy_type)
                cdn_id     = f"cdn:{provider.lower()}:{subdomain.lower()}"
                _node(cdn_id, kind, provider, {
                    "provider":      provider,
                    "proxy_type":    proxy_type,
                    "proxied_host":  subdomain,
                    "origin_masked": d.get("origin_masked", True),
                    "origin_ips":    d.get("origin_ips", []),
                    "bypass_hints":  d.get("bypass_hints", []),
                    "sources":       r.get("sources", []),
                })
                parent_id = (f"subdomain:{subdomain}"
                             if f"subdomain:{subdomain}" in nodes else root_id)
                edge_kind = "routes_through" if kind == "reverse_proxy" else "proxied_by"
                _edge(parent_id, cdn_id, edge_kind)
                for origin_ip in d.get("origin_ips", []):
                    if not origin_ip:
                        continue
                    oid = f"ip:{origin_ip}"
                    _node(oid, "ip", origin_ip, {
                        "ip": origin_ip, "note": "origin server"
                    })
                    _edge(cdn_id, oid, "origin_of")

            # ── vulnerabilities ───────────────────────────────────────────────
            for r in repo.get_results(sid, "vuln"):
                d    = r.get("data", {})
                name = d.get("name", "")
                sev  = d.get("severity", "info")
                url  = d.get("url", "")
                if not name:
                    continue
                try:
                    host = urlsplit(url).netloc
                except Exception:
                    host = ""
                vid   = f"vuln:{d.get('template_id','?')}:{host}"
                label = f"[{sev[:4].upper()}] {name[:18]}"
                _node(vid, "vuln", label, {
                    "name": name, "severity": sev,
                    "url": url, "description": d.get("description", ""),
                })
                parent = f"subdomain:{host}" if f"subdomain:{host}" in nodes else root_id
                _edge(parent, vid, "has_vuln")

            # ── OSINT ─────────────────────────────────────────────────────────
            for r in repo.get_results(sid, "osint"):
                d     = r.get("data", {})
                rtype = d.get("result_type", "")
                value = d.get("value", "")
                if not value:
                    continue
                oid = f"osint:{rtype}:{value}"
                _node(oid, "osint", value[:24], {
                    "type": rtype, "value": value,
                    "extra": d.get("extra", ""),
                    "provider": d.get("provider", ""),
                })
                _edge(root_id, oid, "is_osint")

            # ── Info notes ────────────────────────────────────────────────────
            for r in repo.get_results(sid, "info"):
                d         = r.get("data", {})
                parent_id = d.get("parent_node_id", "")
                content   = d.get("content", "")
                if not parent_id or not content or parent_id not in nodes:
                    continue
                first_line = content.split("\n")[0].strip()
                label = (first_line[:20] + "…") if len(first_line) > 20 else first_line
                info_id = f"info:{parent_id}"
                _node(info_id, "info", label, {
                    "content":        content,
                    "parent_node_id": parent_id,
                })
                _edge(parent_id, info_id, "annotates")

            # ── Custom user nodes ──────────────────────────────────────────────
            for r in repo.get_results(sid, "custom"):
                d         = r.get("data", {})
                parent_id = d.get("parent_node_id", "")
                label     = d.get("label", "")
                if not label or parent_id not in nodes:
                    continue
                custom_id = f"custom:{r.get('result_key', label)}"
                _node(custom_id, "custom", label, {
                    "label":          label,
                    "description":    d.get("description", ""),
                    "parent_node_id": parent_id,
                })
                _edge(parent_id, custom_id, "linked_to")

            # ── Endpoints (hidden by default) ─────────────────────────────────
            for r in repo.get_results(sid, "crawl"):
                d      = r.get("data", {})
                url    = d.get("url", "")
                method = d.get("method", "GET")
                if not url:
                    continue
                try:
                    parsed  = urlsplit(url)
                    host    = parsed.netloc
                    path    = parsed.path or "/"
                except Exception:
                    continue
                sub_id = f"subdomain:{host}"
                if sub_id not in nodes:
                    continue  # skip if subdomain not in main graph
                path_lbl = path if len(path) <= 28 else path[:25] + "…"
                ep_id    = f"endpoint:{method}:{url}"
                _node(ep_id, "endpoint", f"{method} {path_lbl}", {
                    "url":          url,
                    "method":       method,
                    "status_code":  d.get("status_code", 0),
                    "content_type": d.get("content_type", ""),
                })
                _edge(sub_id, ep_id, "has_endpoint")

            # ── Parameters (hidden by default, children of endpoints) ──────────
            for r in repo.get_results(sid, "params"):
                d        = r.get("data", {})
                name     = d.get("name", "")
                endpoint = d.get("endpoint", "")
                method   = d.get("method", "GET")
                if not name or not endpoint:
                    continue
                ep_id = f"endpoint:{method}:{endpoint}"
                if ep_id not in nodes:
                    continue  # endpoint not in graph
                ptype    = d.get("param_type", "query")
                param_id = f"param:{ep_id}:{name}"
                _node(param_id, "param", f"{'?' if ptype == 'query' else '⬤'} {name}", {
                    "name":       name,
                    "param_type": ptype,
                    "example":    d.get("example_value", ""),
                    "endpoint":   endpoint,
                    "method":     method,
                })
                _edge(ep_id, param_id, "has_param")

        return GraphData(nodes=list(nodes.values()), edges=list(edges.values()))


# ── Search bar widget ────────────────────────────────────────────────────────

class _SearchEdit(QLineEdit):
    """QLineEdit that clears itself on Escape."""
    def keyPressEvent(self, ev):
        if ev.key() == Qt.Key_Escape:
            self.clear()
        else:
            super().keyPressEvent(ev)


# ── Legend chip ───────────────────────────────────────────────────────────────

def _legend_chip(kind: str) -> QLabel:
    s = _NS[kind]
    icon = _KIND_ICON.get(kind, "○")
    chip = QLabel(f" {icon} {kind} ")
    chip.setStyleSheet(f"""
        QLabel {{
            background:{s['fill']}; color:#1E1E2E;
            border-radius:8px; font-size:8px;
            padding:2px 6px; font-weight:bold;
        }}
    """)
    return chip


# ── Full network page ─────────────────────────────────────────────────────────

class NetworkPage(QWidget):
    def __init__(self, project_dir: str, target: str, parent=None):
        super().__init__(parent)
        self._project_dir = project_dir
        self._target      = target
        self._data: GraphData | None = None
        self._loader: GraphDataLoader | None = None
        self._manual_repo = ManualDataRepository(project_dir, target)

        self._scene = NetworkGraphScene(project_dir, target)
        self._scene.nodeClicked.connect(self._on_node_clicked)
        self._scene.addDataRequested.connect(self._on_add_requested)

        self._view   = NetworkGraphView(self._scene)
        self._detail = DetailPanel()
        self._detail.openInBrowser.connect(self._on_open_browser)

        toolbar     = self._build_toolbar()
        self._status = QLabel("Loading…")
        self._status.setStyleSheet(
            "color:#6C7086; font-size:10px; padding:3px 10px; background:#11111B;")

        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(self._view)
        splitter.addWidget(self._detail)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)
        splitter.setStyleSheet("QSplitter::handle{background:#313244;width:2px;}")

        vb = QVBoxLayout(self)
        vb.setContentsMargins(0, 0, 0, 0)
        vb.setSpacing(0)
        vb.addWidget(toolbar)
        vb.addWidget(splitter, stretch=1)
        vb.addWidget(self._status)

        self._load_data()

    # ── Toolbar ───────────────────────────────────────────────────────────────

    def _build_toolbar(self) -> QWidget:
        bar = QWidget()
        bar.setFixedHeight(42)
        bar.setStyleSheet("background:#181825; border-bottom:1px solid #313244;")
        hl = QHBoxLayout(bar)
        hl.setContentsMargins(10, 0, 10, 0)
        hl.setSpacing(6)

        title = QLabel("⊗  Attack Surface Graph")
        title.setStyleSheet(
            "color:#94E2D5; font-size:11px; font-weight:bold; background:transparent;")
        hl.addWidget(title)
        hl.addStretch()

        for kind in _NS:
            hl.addWidget(_legend_chip(kind))

        hl.addStretch()

        # ── Search bar ────────────────────────────────────────────────────────
        search_lbl = QLabel("⌕")
        search_lbl.setStyleSheet("color:#6C7086; font-size:14px; background:transparent;")
        hl.addWidget(search_lbl)

        self._search_edit = _SearchEdit()
        self._search_edit.setPlaceholderText("Search nodes…")
        self._search_edit.setFixedSize(160, 26)
        self._search_edit.setStyleSheet(
            "QLineEdit{background:#1E1E2E;color:#CDD6F4;"
            "border:1px solid #45475A;border-radius:4px;"
            "padding:0 8px;font-size:10px;}"
            "QLineEdit:focus{border-color:#89B4FA;}"
        )
        # Debounce: fire 150 ms after the user stops typing
        self._search_debounce = QTimer(self)
        self._search_debounce.setSingleShot(True)
        self._search_debounce.setInterval(150)
        self._search_debounce.timeout.connect(
            lambda: self._scene.set_search(self._search_edit.text())
        )
        self._search_edit.textChanged.connect(self._search_debounce.start)
        hl.addWidget(self._search_edit)

        _btn_ss = ("QPushButton{background:#313244;color:#CDD6F4;"
                   "border:1px solid #45475A;border-radius:4px;"
                   "padding:2px 10px;font-size:10px;min-height:26px;}"
                   "QPushButton:hover{background:#45475A;}")
        _focus_ss_active = ("QPushButton{background:#3D2B1F;color:#FAB387;"
                            "border:1px solid #FE640B;border-radius:4px;"
                            "padding:2px 10px;font-size:10px;min-height:26px;}"
                            "QPushButton:hover{background:#4D3B2F;}")

        for lbl, fn in [("↺ Refresh",      self._load_data),
                        ("⊡ Fit",          self._view.fit_all),
                        ("⊞ Reset Layout", self._on_reset_layout)]:
            btn = QPushButton(lbl)
            btn.setFixedHeight(26)
            btn.setStyleSheet(_btn_ss)
            btn.clicked.connect(fn)
            hl.addWidget(btn)

        self._show_all_btn = QPushButton("⊗ Show All")
        self._show_all_btn.setFixedHeight(26)
        self._show_all_btn.setStyleSheet(_btn_ss)
        self._show_all_btn.setEnabled(False)
        self._show_all_btn.clicked.connect(self._scene.unfocus)
        hl.addWidget(self._show_all_btn)

        def _on_focus_changed(focused: bool):
            if focused:
                self._show_all_btn.setEnabled(True)
                self._show_all_btn.setStyleSheet(_focus_ss_active)
            else:
                self._show_all_btn.setEnabled(False)
                self._show_all_btn.setStyleSheet(_btn_ss)
        self._scene.focusChanged.connect(_on_focus_changed)

        return bar

    # ── Public API ────────────────────────────────────────────────────────────

    def refresh(self) -> None:
        self._load_data()

    # ── Slots ─────────────────────────────────────────────────────────────────

    def _load_data(self):
        if self._loader and self._loader.isRunning():
            return
        self._status.setText("⟳  Loading graph data…")
        self._loader = GraphDataLoader(self._project_dir, self._target, self)
        self._loader.loaded.connect(self._on_loaded)
        self._loader.error.connect(lambda m: self._status.setText(f"Error: {m}"))
        self._loader.start()

    def _on_loaded(self, data: GraphData):
        first_load = self._data is None
        self._data = data
        if first_load:
            self._scene.build(data)
            QTimer.singleShot(150, self._view.fit_all)
        else:
            self._scene.merge(data)   # preserves all node positions

        n = data.nodes
        counts = {k: sum(1 for nd in n if nd.kind == k) for k in _NS}
        proxy_count = counts["cdn"] + counts["reverse_proxy"]
        cdn_s = f"  ·  {proxy_count} CDN/proxies" if proxy_count else ""
        self._status.setText(
            f"{counts['subdomain']} subdomains  ·  {counts['ip']} IPs  ·  "
            f"{counts['port']} ports  ·  {counts['tech']} technologies  ·  "
            f"{counts['vuln']} vulns  ·  {counts['osint']} OSINT{cdn_s}"
        )

    def _on_reset_layout(self):
        if self._data:
            self._scene.reset_layout(self._data)
            QTimer.singleShot(150, self._view.fit_all)

    def _on_node_clicked(self, node: GraphNode):
        self._detail.show_node(node)

    def _on_open_browser(self, url: str):
        win = self.window()
        if hasattr(win, "openNewBrowserTab"):
            win.openNewBrowserTab(url)

    # ── Manual data entry ─────────────────────────────────────────────────────

    def _on_add_requested(self, action: str, parent_node):
        """Open the appropriate dialog, save to DB, and refresh the graph."""
        nd = parent_node  # GraphNode or None

        def _prefill_host() -> str:
            if nd is None:
                return ""
            return nd.data.get("ip") or nd.data.get("domain") or ""

        def _prefill_url(port: int | None = None) -> str:
            if nd is None:
                return ""
            h = nd.data.get("domain") or nd.data.get("ip") or ""
            p = port or nd.data.get("port")
            if not h:
                return ""
            scheme = "https" if p in (443, 8443) else "http"
            if p and p not in (80, 443):
                return f"{scheme}://{h}:{p}/"
            return f"{scheme}://{h}/"

        try:
            if action == "add_subdomain":
                prefill = nd.data.get("domain", "") if nd and nd.kind == "target" else ""
                dlg = _AddSubdomainDlg(self, prefill_domain="")
                if dlg.exec() != QDialog.Accepted:
                    return
                domain, ips = dlg.values()
                self._manual_repo.add_subdomain(domain, ips)

            elif action == "add_ip":
                host = _prefill_host()
                dlg = _AddSubdomainDlg(self, prefill_domain=host)
                dlg.setWindowTitle("Add IP Address to Subdomain")
                if dlg.exec() != QDialog.Accepted:
                    return
                domain, ips = dlg.values()
                self._manual_repo.add_subdomain(domain, ips)

            elif action == "add_port":
                host = _prefill_host()
                dlg = _AddPortDlg(self, prefill_host=host)
                if dlg.exec() != QDialog.Accepted:
                    return
                host, port, proto, svc, ver = dlg.values()
                self._manual_repo.add_port(host, port, proto, svc, ver)

            elif action == "add_tech":
                url = _prefill_url(nd.data.get("port") if nd else None)
                dlg = _AddTechDlg(self, prefill_url=url)
                if dlg.exec() != QDialog.Accepted:
                    return
                url, tech, status, title = dlg.values()
                self._manual_repo.add_tech(url, tech, status, title)

            elif action == "add_vuln":
                url = _prefill_url()
                dlg = _AddVulnDlg(self, prefill_url=url)
                if dlg.exec() != QDialog.Accepted:
                    return
                name, sev, url, desc, tid = dlg.values()
                self._manual_repo.add_vuln(name, sev, url, desc, tid)

            elif action == "add_endpoint":
                url = _prefill_url(nd.data.get("port") if nd else None)
                dlg = _AddEndpointDlg(self, prefill_url=url)
                if dlg.exec() != QDialog.Accepted:
                    return
                url, method, status = dlg.values()
                self._manual_repo.add_endpoint(url, method, status)

            elif action == "add_osint":
                dlg = _AddOSINTDlg(self)
                if dlg.exec() != QDialog.Accepted:
                    return
                rtype, value, extra, provider = dlg.values()
                self._manual_repo.add_osint(rtype, value, extra, provider)

            elif action == "add_cdn":
                host = _prefill_host()
                dlg  = _AddCdnDlg(self, prefill_subdomain=host)
                if dlg.exec() != QDialog.Accepted:
                    return
                subdomain, provider, proxy_type, origin_ips, bypass_hints = dlg.values()
                self._manual_repo.add_cdn(subdomain, provider, proxy_type,
                                          origin_ips, bypass_hints)

            elif action in ("add_info", "edit_info"):
                prefill = (self._manual_repo.get_info_note(nd.id)
                           if action == "edit_info" else "")
                dlg = _InfoNoteDlg(self,
                                   node_label=nd.label if nd else "",
                                   prefill=prefill)
                if dlg.exec() != QDialog.Accepted:
                    return
                self._manual_repo.save_info_note(nd.id, dlg.content())

            elif action == "add_custom":
                dlg = _AddCustomNodeDlg(self,
                                        parent_node_label=nd.label if nd else "")
                if dlg.exec() != QDialog.Accepted:
                    return
                label, desc = dlg.values()
                self._manual_repo.add_custom_node(nd.id, label, desc)

            elif action == "add_origin_server":
                dlg = _AddOriginServerDlg(
                    self,
                    provider=nd.label if nd else "",
                    subdomain=nd.data.get("proxied_host", "") if nd else "",
                )
                if dlg.exec() != QDialog.Accepted:
                    return
                origin_ip, subdomain, provider = dlg.values()
                self._manual_repo.add_origin_to_cdn(subdomain, provider, origin_ip)

            else:
                return

            # Refresh the graph so the new node appears immediately
            self._load_data()

        except Exception as exc:
            logger.exception("Manual data entry failed")
            QMessageBox.critical(
                self, "Save Failed",
                f"Could not save to database:\n{exc}",
            )
