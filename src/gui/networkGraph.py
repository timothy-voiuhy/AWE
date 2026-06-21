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
}

_EC: dict[str, str] = {
    "has_subdomain": "#45475A",
    "resolves_to":   "#89B4FA",
    "has_port":      "#A6E3A1",
    "uses_tech":     "#F9E2AF",
    "has_vuln":      "#F38BA8",
    "is_osint":      "#94E2D5",
}

_KIND_ICON = {
    "target": "◎", "subdomain": "◉", "ip": "◆",
    "port": "▣",   "tech": "⬡",      "vuln": "⚠", "osint": "△",
}

_DASHED = {"uses_tech", "has_vuln", "is_osint"}

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

    # expose for EdgeItem
    def kind(self) -> str: return self._node.kind
    def node(self) -> GraphNode: return self._node
    def add_edge(self, e: "EdgeItem"): self._edges.append(e)

    def boundingRect(self) -> QRectF:
        r = self._r + 12
        return QRectF(-r, -r, r * 2, r * 2)

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
        else:
            p.drawEllipse(QRectF(-r, -r, r * 2, r * 2))

    def itemChange(self, change, value):
        if change == QGraphicsItem.ItemPositionHasChanged:
            for e in self._edges:
                e.adjust()
            self._node.x = self.x()
            self._node.y = self.y()
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
        sc = self.scene()
        if sc and hasattr(sc, "_locked"):
            sc._locked.add(self._node.id)
        super().mouseReleaseEvent(ev)

    def contextMenuEvent(self, ev):
        kind = self._node.kind
        menu = QMenu()
        menu.setStyleSheet(_MENU_SS)

        _add_hdr = lambda text: (
            a := menu.addAction(text),
            a.setEnabled(False),
            a.setIcon(QApplication.style().standardIcon(
                QApplication.style().StandardPixmap.SP_DialogApplyButton)),
        )

        if kind == "target":
            menu.addSection("Add to graph")
            a_sub  = menu.addAction("◉  Add Subdomain")
            a_osint = menu.addAction("△  Add OSINT Finding")
            chosen = menu.exec(ev.screenPos().toPoint())
            if chosen == a_sub:
                self.scene().addDataRequested.emit("add_subdomain", self._node)
            elif chosen == a_osint:
                self.scene().addDataRequested.emit("add_osint", self._node)

        elif kind == "subdomain":
            menu.addSection(f"◉ {self._node.label}")
            a_ip       = menu.addAction("◆  Add IP Address")
            a_port     = menu.addAction("▣  Add Port / Service")
            a_tech     = menu.addAction("⬡  Add Technology")
            a_vuln     = menu.addAction("⚠  Add Vulnerability")
            a_endpoint = menu.addAction("↗  Add Endpoint")
            menu.addSeparator()
            a_osint    = menu.addAction("△  Add OSINT Finding")
            chosen = menu.exec(ev.screenPos().toPoint())
            if chosen == a_ip:
                self.scene().addDataRequested.emit("add_ip", self._node)
            elif chosen == a_port:
                self.scene().addDataRequested.emit("add_port", self._node)
            elif chosen == a_tech:
                self.scene().addDataRequested.emit("add_tech", self._node)
            elif chosen == a_vuln:
                self.scene().addDataRequested.emit("add_vuln", self._node)
            elif chosen == a_endpoint:
                self.scene().addDataRequested.emit("add_endpoint", self._node)
            elif chosen == a_osint:
                self.scene().addDataRequested.emit("add_osint", self._node)

        elif kind == "ip":
            menu.addSection(f"◆ {self._node.label}")
            a_port = menu.addAction("▣  Add Port / Service")
            chosen = menu.exec(ev.screenPos().toPoint())
            if chosen == a_port:
                self.scene().addDataRequested.emit("add_port", self._node)

        elif kind == "port":
            menu.addSection(f"▣ {self._node.label}")
            a_tech = menu.addAction("⬡  Add Technology")
            a_vuln = menu.addAction("⚠  Add Vulnerability")
            a_ep   = menu.addAction("↗  Add Endpoint")
            chosen = menu.exec(ev.screenPos().toPoint())
            if chosen == a_tech:
                self.scene().addDataRequested.emit("add_tech", self._node)
            elif chosen == a_vuln:
                self.scene().addDataRequested.emit("add_vuln", self._node)
            elif chosen == a_ep:
                self.scene().addDataRequested.emit("add_endpoint", self._node)

        else:
            # vuln / tech / osint — just show copy
            a_copy = menu.addAction("⎘  Copy value")
            chosen = menu.exec(ev.screenPos().toPoint())
            if chosen == a_copy:
                val = (self._node.data.get("value") or
                       self._node.data.get("tech") or
                       self._node.label)
                QApplication.clipboard().setText(val)

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

    def __init__(self, parent=None):
        super().__init__(parent)
        self._node_items: dict[str, NodeItem] = {}
        self._edge_items: list[EdgeItem]      = []
        self._locked:     set[str]            = set()
        self._vx:         dict[str, float]    = {}
        self._vy:         dict[str, float]    = {}
        self._alpha       = 1.0
        self._timer       = QTimer(self)
        self._timer.timeout.connect(self._force_step)

    # ── Public ────────────────────────────────────────────────────────────────

    def build(self, data: GraphData, layout: str = "radial"):
        self._timer.stop()
        self.clear()
        self._node_items.clear()
        self._edge_items.clear()
        self._locked.clear()
        self._vx.clear()
        self._vy.clear()

        if not data.nodes:
            return

        if layout == "radial":
            self._radial_layout(data)
        elif layout == "hierarchy":
            self._hierarchy_layout(data)
        else:
            self._random_positions(data)

        for node in data.nodes:
            item = NodeItem(node)
            self.addItem(item)
            self._node_items[node.id] = item
            self._vx[node.id] = 0.0
            self._vy[node.id] = 0.0

        nmap = self._node_items
        for edge in data.edges:
            si, ti = nmap.get(edge.source_id), nmap.get(edge.target_id)
            if si and ti:
                ei = EdgeItem(si, ti, edge.kind)
                self.addItem(ei)
                self._edge_items.append(ei)

        if layout == "force":
            self._alpha = 1.0
            self._timer.start(16)

    def stop_force(self):
        self._timer.stop()

    # ── Layouts ───────────────────────────────────────────────────────────────

    def _radial_layout(self, data: GraphData):
        nmap = {n.id: n for n in data.nodes}
        children: dict[str, list[str]] = {n.id: [] for n in data.nodes}
        for e in data.edges:
            if e.source_id in children:
                children[e.source_id].append(e.target_id)

        targets = [n for n in data.nodes if n.kind == "target"]
        if not targets:
            return
        root = targets[0]
        root.x = root.y = 0.0

        subs = [n for n in data.nodes if n.kind == "subdomain"]
        n_sub = max(len(subs), 1)
        r1 = max(200, n_sub * 35)

        for i, sub in enumerate(subs):
            ang = 2 * math.pi * i / n_sub
            sub.x = r1 * math.cos(ang)
            sub.y = r1 * math.sin(ang)

            ip_nodes   = [nmap[c] for c in children.get(sub.id, [])
                          if c in nmap and nmap[c].kind == "ip"]
            vuln_nodes = [nmap[c] for c in children.get(sub.id, [])
                          if c in nmap and nmap[c].kind in ("vuln", "osint")]

            n_ip = max(len(ip_nodes), 1)
            for j, ip in enumerate(ip_nodes):
                a2 = ang - 0.5 + j / n_ip
                ip.x = sub.x + 95 * math.cos(a2)
                ip.y = sub.y + 95 * math.sin(a2)

                port_nodes = [nmap[c] for c in children.get(ip.id, []) if c in nmap]
                n_port = max(len(port_nodes), 1)
                for k, port in enumerate(port_nodes):
                    a3 = a2 - 0.3 + 0.6 * k / n_port
                    port.x = ip.x + 60 * math.cos(a3)
                    port.y = ip.y + 60 * math.sin(a3)

                    tech_nodes = [nmap[c] for c in children.get(port.id, []) if c in nmap]
                    n_tech = max(len(tech_nodes), 1)
                    for m, tech in enumerate(tech_nodes):
                        a4 = a3 - 0.25 + 0.5 * m / n_tech
                        tech.x = port.x + 50 * math.cos(a4)
                        tech.y = port.y + 50 * math.sin(a4)

            for j, node in enumerate(vuln_nodes):
                a2 = ang + 0.9 + 0.5 * j / max(len(vuln_nodes), 1)
                node.x = sub.x + 80 * math.cos(a2)
                node.y = sub.y + 80 * math.sin(a2)

        osint = [n for n in data.nodes if n.kind == "osint"]
        n_os = max(len(osint), 1)
        for i, n in enumerate(osint):
            ang = 2 * math.pi * i / n_os + math.pi / n_os
            n.x = (r1 + 140) * math.cos(ang)
            n.y = (r1 + 140) * math.sin(ang)

    def _hierarchy_layout(self, data: GraphData):
        nmap = {n.id: n for n in data.nodes}
        children: dict[str, list[str]] = {n.id: [] for n in data.nodes}
        for e in data.edges:
            if e.source_id in children:
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

    def _random_positions(self, data: GraphData):
        spread = max(250, len(data.nodes) * 18)
        import random
        for n in data.nodes:
            n.x = random.uniform(-spread, spread)
            n.y = random.uniform(-spread, spread)

    # ── Force simulation ──────────────────────────────────────────────────────

    def _force_step(self):
        if self._alpha < 0.004:
            self._timer.stop()
            return

        items = list(self._node_items.values())
        n = len(items)
        if n == 0:
            return

        k = math.sqrt(800 * 600 / max(n, 1)) * 0.75

        # repulsion O(n²) — acceptable for typical graph sizes (<200 nodes)
        for i in range(n):
            a = items[i]
            aid = a.node().id
            ax, ay = a.x(), a.y()
            for j in range(i + 1, n):
                b = items[j]
                bid = b.node().id
                dx = ax - b.x()
                dy = ay - b.y()
                d2 = max(dx * dx + dy * dy, 1.0)
                d = math.sqrt(d2)
                f = k * k / d2
                fx, fy = dx / d * f, dy / d * f
                self._vx[aid] += fx;  self._vy[aid] += fy
                self._vx[bid] -= fx;  self._vy[bid] -= fy

        # attraction along edges
        for ei in self._edge_items:
            si, ti = ei._src, ei._tgt
            sid, tid = si.node().id, ti.node().id
            dx = ti.x() - si.x()
            dy = ti.y() - si.y()
            d = max(math.hypot(dx, dy), 1.0)
            f = d * d / k * 0.28
            fx, fy = dx / d * f, dy / d * f
            self._vx[sid] += fx;  self._vy[sid] += fy
            self._vx[tid] -= fx;  self._vy[tid] -= fy

        # update
        for item in items:
            nid = item.node().id
            if nid in self._locked:
                continue
            vx = self._vx[nid] * 0.82
            vy = self._vy[nid] * 0.82
            item.setPos(item.x() + vx * self._alpha,
                        item.y() + vy * self._alpha)
            self._vx[nid] = vx
            self._vy[nid] = vy

        self._alpha *= 0.97

    # ── Background dot grid ───────────────────────────────────────────────────

    def drawBackground(self, painter: QPainter, rect: QRectF):
        painter.fillRect(rect, QColor("#181825"))
        gs = 40
        pen = QPen(QColor("#252538"), 1)
        painter.setPen(pen)
        lx = int(rect.left())  - (int(rect.left())  % gs)
        ty = int(rect.top())   - (int(rect.top())   % gs)
        x = lx
        while x < rect.right():
            y = ty
            while y < rect.bottom():
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
        self.setViewportUpdateMode(QGraphicsView.BoundingRectViewportUpdate)
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
                    tech_id = f"tech:{tech}"
                    _node(tech_id, "tech", tech, {"tech": tech})
                    _edge(port_id, tech_id, "uses_tech")

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

        return GraphData(nodes=list(nodes.values()), edges=list(edges.values()))


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
        self._project_dir    = project_dir
        self._target         = target
        self._data: GraphData | None = None
        self._current_layout = "radial"
        self._loader: GraphDataLoader | None = None
        self._manual_repo    = ManualDataRepository(project_dir, target)

        self._scene = NetworkGraphScene()
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
        hl.addSpacing(12)

        # layout toggle buttons
        self._layout_btns: dict[str, QPushButton] = {}
        _active_style   = ("QPushButton{background:#313244;color:#CDD6F4;"
                           "border:1px solid #89B4FA;border-radius:4px;"
                           "padding:2px 10px;font-size:10px;min-height:22px;}")
        _inactive_style = ("QPushButton{background:transparent;color:#6C7086;"
                           "border:1px solid #313244;border-radius:4px;"
                           "padding:2px 10px;font-size:10px;min-height:22px;}"
                           "QPushButton:hover{background:#252538;color:#CDD6F4;}")
        for key, lbl in [("radial","Radial"), ("force","Force"), ("hierarchy","Hierarchy")]:
            btn = QPushButton(lbl)
            btn.setStyleSheet(_active_style if key == self._current_layout else _inactive_style)
            btn.clicked.connect(lambda _, k=key,
                                a=_active_style, i=_inactive_style: self._set_layout(k, a, i))
            hl.addWidget(btn)
            self._layout_btns[key] = btn
        self._active_style   = _active_style
        self._inactive_style = _inactive_style

        hl.addStretch()

        for kind in _NS:
            hl.addWidget(_legend_chip(kind))

        hl.addStretch()

        for lbl, fn in [("↺ Refresh", self._load_data),
                         ("⊡ Fit",     self._view.fit_all)]:
            btn = QPushButton(lbl)
            btn.setFixedHeight(26)
            btn.setStyleSheet(
                "QPushButton{background:#313244;color:#CDD6F4;"
                "border:1px solid #45475A;border-radius:4px;"
                "padding:2px 10px;font-size:10px;}"
                "QPushButton:hover{background:#45475A;}")
            btn.clicked.connect(fn)
            hl.addWidget(btn)

        return bar

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
        self._data = data
        self._scene.build(data, self._current_layout)
        QTimer.singleShot(150, self._view.fit_all)
        n = data.nodes
        counts = {k: sum(1 for nd in n if nd.kind == k) for k in _NS}
        self._status.setText(
            f"{counts['subdomain']} subdomains  ·  {counts['ip']} IPs  ·  "
            f"{counts['port']} ports  ·  {counts['tech']} technologies  ·  "
            f"{counts['vuln']} vulns  ·  {counts['osint']} OSINT"
        )

    def _on_node_clicked(self, node: GraphNode):
        self._detail.show_node(node)

    def _on_open_browser(self, url: str):
        win = self.window()
        if hasattr(win, "openNewBrowserTab"):
            win.openNewBrowserTab(url)

    def _set_layout(self, key: str, active_s: str, inactive_s: str):
        self._current_layout = key
        self._scene.stop_force()
        for k, btn in self._layout_btns.items():
            btn.setStyleSheet(active_s if k == key else inactive_s)
        if self._data:
            self._scene.build(self._data, key)
            QTimer.singleShot(150, self._view.fit_all)

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
