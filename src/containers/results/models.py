"""
Typed result models for every tool category.

Each model has a `key` property used for deduplication, a `sources` list tracking
which tools produced it, and a `merge()` method for combining duplicates.
"""
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class BaseResult:
    sources: list[str] = field(default_factory=list)

    def add_source(self, tool: str):
        if tool not in self.sources:
            self.sources.append(tool)

    def merge(self, other: "BaseResult") -> "BaseResult":
        for s in other.sources:
            self.add_source(s)
        return self

    @property
    def key(self) -> str:
        raise NotImplementedError

    @property
    def source_str(self) -> str:
        return ", ".join(self.sources)


# ── Subdomain enumeration ─────────────────────────────────────────────────────

@dataclass
class SubdomainResult(BaseResult):
    domain: str = ""
    ip_addresses: list[str] = field(default_factory=list)
    is_wildcard: bool = False

    @property
    def key(self) -> str:
        return self.domain.lower().strip().rstrip(".")

    def merge(self, other: "SubdomainResult") -> "SubdomainResult":
        super().merge(other)
        for ip in other.ip_addresses:
            if ip and ip not in self.ip_addresses:
                self.ip_addresses.append(ip)
        return self

    @property
    def ip_str(self) -> str:
        return ", ".join(self.ip_addresses) if self.ip_addresses else ""


# ── DNS records ───────────────────────────────────────────────────────────────

@dataclass
class DNSRecord(BaseResult):
    name: str = ""
    record_type: str = ""
    value: str = ""
    ttl: str = ""

    @property
    def key(self) -> str:
        return f"{self.name.lower()}|{self.record_type.upper()}|{self.value.lower()}"


# ── Port scanning ─────────────────────────────────────────────────────────────

@dataclass
class PortResult(BaseResult):
    host: str = ""
    port: int = 0
    protocol: str = "tcp"
    service: str = ""
    version: str = ""
    state: str = "open"

    @property
    def key(self) -> str:
        return f"{self.host.lower()}:{self.port}/{self.protocol}"

    def merge(self, other: "PortResult") -> "PortResult":
        super().merge(other)
        if other.service and not self.service:
            self.service = other.service
        if other.version and not self.version:
            self.version = other.version
        return self


# ── Live HTTP hosts ───────────────────────────────────────────────────────────

@dataclass
class LiveHost(BaseResult):
    url: str = ""
    status_code: int = 0
    title: str = ""
    technologies: list[str] = field(default_factory=list)
    content_length: int = 0
    redirect_url: str = ""
    # extended fields from httpx JSON output
    host: str = ""                           # resolved hostname (input subdomain)
    host_ip: str = ""                        # primary resolved IP
    ip_addresses: list[str] = field(default_factory=list)   # all A records
    ipv6_addresses: list[str] = field(default_factory=list) # all AAAA records
    cname: list[str] = field(default_factory=list)
    webserver: str = ""
    scheme: str = ""
    port: str = ""
    words: int = 0
    lines: int = 0
    cdn: bool = False
    cdn_name: str = ""
    cdn_type: str = ""                       # waf | cdn | cloud | …
    cpe: list[str] = field(default_factory=list)  # CPE identifiers

    @property
    def key(self) -> str:
        return self.url.lower().rstrip("/")

    def merge(self, other: "LiveHost") -> "LiveHost":
        super().merge(other)
        for t in other.technologies:
            if t not in self.technologies:
                self.technologies.append(t)
        if not self.title and other.title:
            self.title = other.title
        if not self.status_code and other.status_code:
            self.status_code = other.status_code
        if not self.host_ip and other.host_ip:
            self.host_ip = other.host_ip
        for ip in other.ip_addresses:
            if ip not in self.ip_addresses:
                self.ip_addresses.append(ip)
        for ip in other.ipv6_addresses:
            if ip not in self.ipv6_addresses:
                self.ipv6_addresses.append(ip)
        for c in other.cname:
            if c not in self.cname:
                self.cname.append(c)
        if not self.webserver and other.webserver:
            self.webserver = other.webserver
        if not self.cdn_name and other.cdn_name:
            self.cdn_name = other.cdn_name
            self.cdn_type = other.cdn_type
            self.cdn = other.cdn
        for cpe in other.cpe:
            if cpe not in self.cpe:
                self.cpe.append(cpe)
        return self

    @property
    def tech_str(self) -> str:
        return ", ".join(self.technologies)

    @property
    def ip_str(self) -> str:
        return ", ".join(self.ip_addresses)


# ── Endpoints / crawl results ─────────────────────────────────────────────────

@dataclass
class EndpointResult(BaseResult):
    url: str = ""
    method: str = "GET"
    status_code: int = 0
    content_type: str = ""
    params: list[str] = field(default_factory=list)

    @property
    def key(self) -> str:
        # strip trailing slash and query string for dedup; keep scheme+host+path
        from urllib.parse import urlsplit
        try:
            p = urlsplit(self.url)
            return f"{p.scheme}://{p.netloc}{p.path}".lower().rstrip("/")
        except Exception:
            return self.url.lower().rstrip("/")

    def merge(self, other: "EndpointResult") -> "EndpointResult":
        super().merge(other)
        for p in other.params:
            if p not in self.params:
                self.params.append(p)
        if not self.status_code and other.status_code:
            self.status_code = other.status_code
        if not self.content_type and other.content_type:
            self.content_type = other.content_type
        return self

    @property
    def param_str(self) -> str:
        return ", ".join(self.params[:5]) + ("…" if len(self.params) > 5 else "")


# ── Parameters ────────────────────────────────────────────────────────────────

@dataclass
class ParamResult(BaseResult):
    name: str = ""
    endpoint: str = ""
    method: str = "GET"
    param_type: str = "query"   # query | body | header | path
    example_value: str = ""

    @property
    def key(self) -> str:
        return f"{self.endpoint.lower().rstrip('/')}|{self.name}|{self.method}"

    def merge(self, other: "ParamResult") -> "ParamResult":
        super().merge(other)
        if not self.example_value and other.example_value:
            self.example_value = other.example_value
        return self


# ── Directory / path fuzzing ──────────────────────────────────────────────────

@dataclass
class FuzzResult(BaseResult):
    url: str = ""
    path: str = ""
    status_code: int = 0
    content_length: int = 0
    words: int = 0
    lines: int = 0
    redirect_url: str = ""

    @property
    def key(self) -> str:
        base = self.url.rstrip("/")
        path = self.path.lstrip("/")
        return f"{base}/{path}".lower()

    def merge(self, other: "FuzzResult") -> "FuzzResult":
        super().merge(other)
        if not self.content_length and other.content_length:
            self.content_length = other.content_length
        return self


# ── Vulnerability findings ────────────────────────────────────────────────────

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "": 5}

@dataclass
class VulnFinding(BaseResult):
    template_id: str = ""
    name: str = ""
    severity: str = ""
    url: str = ""
    matched: str = ""
    description: str = ""
    tags: list[str] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.template_id}|{self.url.lower().rstrip('/')}"

    @property
    def severity_order(self) -> int:
        return SEVERITY_ORDER.get(self.severity.lower(), 5)

    @property
    def tag_str(self) -> str:
        return ", ".join(self.tags[:4])


# ── OSINT / cloud / recon ─────────────────────────────────────────────────────

@dataclass
class OSINTResult(BaseResult):
    result_type: str = ""   # cloud_bucket | github_endpoint | asn | netblock | ip
    value: str = ""
    extra: str = ""         # URL, CIDR, org name, etc.
    provider: str = ""      # aws | azure | gcp | github

    @property
    def key(self) -> str:
        return f"{self.result_type}|{self.value.lower()}"


# ── CDN / cloud proxy detection ──────────────────────────────────────────────

@dataclass
class CdnResult(BaseResult):
    subdomain:     str       = ""    # hostname being proxied
    provider:      str       = ""    # Cloudflare | Akamai | Fastly | …
    proxy_type:    str       = "CDN" # CDN | WAF | CDN/WAF | DDoS Protection | Reverse Proxy
    origin_masked: bool      = True
    origin_ips:    list[str] = field(default_factory=list)
    bypass_hints:  list[str] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.provider.lower()}|{self.subdomain.lower()}"

    def merge(self, other: "CdnResult") -> "CdnResult":
        super().merge(other)
        for ip in other.origin_ips:
            if ip and ip not in self.origin_ips:
                self.origin_ips.append(ip)
        for hint in other.bypass_hints:
            if hint and hint not in self.bypass_hints:
                self.bypass_hints.append(hint)
        return self


# ── Wordlist (CeWL output) ────────────────────────────────────────────────────

@dataclass
class WordlistEntry(BaseResult):
    word: str = ""

    @property
    def key(self) -> str:
        return self.word.lower()


# ── User-created graph nodes ──────────────────────────────────────────────────

@dataclass
class InfoNote(BaseResult):
    """Sticky-note attached to a graph node. One note per node (key by node_id)."""
    parent_node_id: str = ""   # graph node ID, e.g. "subdomain:api.example.com"
    content: str = ""

    @property
    def key(self) -> str:
        return f"info:{self.parent_node_id}"


@dataclass
class CustomNode(BaseResult):
    """Free-form user-defined node connected to any graph node."""
    parent_node_id: str = ""
    label:          str = ""
    description:    str = ""

    @property
    def key(self) -> str:
        slug = self.label.lower().strip()[:40]
        return f"custom:{self.parent_node_id}:{slug}"


# ── Category → model class mapping ───────────────────────────────────────────

CATEGORY_MODEL = {
    "subdomain": SubdomainResult,
    "dns":       DNSRecord,
    "portscan":  PortResult,
    "http":      LiveHost,
    "crawl":     EndpointResult,
    "params":    ParamResult,
    "fuzz":      FuzzResult,
    "vuln":      VulnFinding,
    "osint":     OSINTResult,
    "cdn":    CdnResult,
    "info":   InfoNote,
    "custom": CustomNode,
}


def result_from_dict(category: str, data: dict, sources: list[str]) -> "BaseResult | None":
    """
    Reconstruct a typed result object from a MongoDB document's data dict.
    `sources` is the authoritative merged list from the top-level document field.
    Returns None if the category is unknown or the data is malformed.
    """
    import dataclasses
    cls = CATEGORY_MODEL.get(category)
    if cls is None:
        return None
    known = {f.name for f in dataclasses.fields(cls)}
    filtered = {k: v for k, v in data.items() if k in known and k != "sources"}
    try:
        obj = cls(**filtered)
        obj.sources = list(sources)
        return obj
    except Exception:
        return None
