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
    "cname":         {"fill": "#B4BEFE", "border": "#CDD6F4", "r": 11, "shape": "hexagon"},
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
    "has_cname":     "#B4BEFE",
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
    "cname":         "↪",
    "endpoint":      "↗",
    "param":         "?",
    "custom":        "＋",
    "info":          "✎",
}

_DASHED = {"uses_tech", "has_vuln", "is_osint"}

# ── Lane layout constants ─────────────────────────────────────────────────────

# (internal_key, display_label, width_px)
_LANE_COLUMNS: list[tuple[str, str, int]] = [
    ("target",    "Domain",        140),
    ("subdomain", "Subdomains",    205),
    ("cname",     "CNAME Chain",   175),
    ("ip",        "IPs",           140),
    ("port",      "Ports",         115),
    ("tech_cdn",  "Tech / CDN",    175),
    ("origin",    "Origin Server", 150),
    ("endpoint",  "Endpoints",     185),
    ("param",     "Parameters",    150),
    ("findings",  "Findings",      165),
]
_LANE_NODE_GAP  = 60    # px between stacked nodes within one cell
_LANE_ROW_MIN_H = 150   # minimum row-band height
_LANE_ROW_GAP   = 22    # gap between adjacent row bands
_LANE_HEADER_H  = 40    # column-header bar height
_LANE_PAD_TOP   = 64    # space above the first row band

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
    """Map a CdnResult.proxy_type string to a graph node kind."""
    return "reverse_proxy" if "reverse proxy" in proxy_type.lower() else "cdn"


# ── Shared UI style strings ───────────────────────────────────────────────────

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
