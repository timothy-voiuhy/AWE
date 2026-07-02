"""
Per-tool output file parsers.

Each parser function:
  parse_<toolname>(output_dir: str) -> list[BaseResult]

Returns an empty list (never raises) if the file is missing or malformed.
All files are expected under output_dir/ with the filenames the Docker tool
configs write to (e.g. amass → /.config/amass/amass_.txt).
"""
import json
import logging
import os
import re
from pathlib import Path
from urllib.parse import urlsplit

from containers.results.models import (
    DNSRecord, EndpointResult, FuzzResult, LiveHost, OSINTResult,
    ParamResult, PortResult, ScreenshotResult, SubdomainResult,
    VulnFinding, WordlistEntry,
)

logger = logging.getLogger(__name__)

_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
_URL_RE = re.compile(r"^https?://")


def _read_lines(path: str) -> list[str]:
    try:
        with open(path, "r", errors="replace") as f:
            return [l.strip() for l in f if l.strip()]
    except FileNotFoundError:
        return []
    except Exception as exc:
        logger.debug("read_lines %s: %s", path, exc)
        return []


def _read_json(path: str):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def _read_jsonl(path: str) -> list[dict]:
    results = []
    try:
        with open(path, errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    except FileNotFoundError:
        pass
    except Exception as exc:
        logger.debug("read_jsonl %s: %s", path, exc)
    return results


def _is_domain(s: str) -> bool:
    return bool(_DOMAIN_RE.match(s))


def _norm_domain(s: str) -> str:
    return s.lower().strip().rstrip(".")


def _norm_url(s: str) -> str:
    s = s.strip()
    if not s.startswith(("http://", "https://")):
        return ""
    try:
        p = urlsplit(s)
        return f"{p.scheme}://{p.netloc}{p.path}".rstrip("/")
    except Exception:
        return s.rstrip("/")


# ── Subdomain parsers ─────────────────────────────────────────────────────────

def _parse_subdomain_lines(path: str, tool: str) -> list[SubdomainResult]:
    results = []
    for line in _read_lines(path):
        domain = _norm_domain(line.split()[0] if line.split() else line)
        if _is_domain(domain):
            r = SubdomainResult(domain=domain)
            r.add_source(tool)
            results.append(r)
    return results


def parse_amass(output_dir: str) -> list[SubdomainResult]:
    results = []
    # Docker output → /.config/amass/amass_.txt (mounted to output_dir)
    for candidate in ["amass_.txt", "amass_results.txt"]:
        for line in _read_lines(os.path.join(output_dir, candidate)):
            # amass output: "sub.example.com (FQDN) --> a_record --> 1.2.3.4"
            parts = line.split()
            if not parts:
                continue
            domain = _norm_domain(parts[0])
            if not _is_domain(domain):
                continue
            ip = ""
            if "-->" in line and len(parts) >= 5:
                ip = parts[-1] if re.match(r"\d+\.\d+\.\d+\.\d+", parts[-1]) else ""
            r = SubdomainResult(domain=domain, ip_addresses=[ip] if ip else [])
            r.add_source("amass")
            results.append(r)
    return results


def parse_assetfinder(output_dir: str) -> list[SubdomainResult]:
    return _parse_subdomain_lines(
        os.path.join(output_dir, "assetfinder_results.txt"), "assetfinder"
    )


def parse_subfinder(output_dir: str) -> list[SubdomainResult]:
    return _parse_subdomain_lines(
        os.path.join(output_dir, "subfinder_results.txt"), "subfinder"
    )


def parse_sublist3r(output_dir: str) -> list[SubdomainResult]:
    results = []
    for candidate in ["sublist3r_results.txt", "sublisterSubdomains.txt"]:
        results.extend(_parse_subdomain_lines(
            os.path.join(output_dir, candidate), "sublist3r"
        ))
    return results


def parse_subdomainizer(output_dir: str) -> list[SubdomainResult]:
    results = []
    for candidate in ["subdomainizer_results.txt", "subdomainizerSubdomains.txt"]:
        for line in _read_lines(os.path.join(output_dir, candidate)):
            # SubDomainizer outputs one domain per line; skip URLs and secrets
            domain = _norm_domain(line)
            if _is_domain(domain):
                r = SubdomainResult(domain=domain)
                r.add_source("subdomainizer")
                results.append(r)
    return results


def parse_shuffledns(output_dir: str) -> list[SubdomainResult]:
    return _parse_subdomain_lines(
        os.path.join(output_dir, "shuffledns_results.txt"), "shuffledns"
    )


def parse_ctl(output_dir: str) -> list[SubdomainResult]:
    return _parse_subdomain_lines(
        os.path.join(output_dir, "ctl_results.txt"), "ctl"
    )


# ── DNS parsers ───────────────────────────────────────────────────────────────

def parse_dnsx(output_dir: str) -> list[DNSRecord]:
    results = []
    for line in _read_lines(os.path.join(output_dir, "dnsx_results.txt")):
        # dnsx format: "example.com [A] [1.2.3.4]"  or  "example.com A 1.2.3.4"
        m = re.match(
            r"^(\S+)\s+\[?([A-Z]+)\]?\s+\[?([^\]\s]+)\]?", line, re.IGNORECASE
        )
        if m:
            r = DNSRecord(name=m.group(1).lower(),
                          record_type=m.group(2).upper(),
                          value=m.group(3))
            r.add_source("dnsx")
            results.append(r)
    return results


def parse_metabigor(output_dir: str) -> list[DNSRecord]:
    results = []
    for line in _read_lines(os.path.join(output_dir, "metabigor_results.txt")):
        # metabigor: CIDR lines like "192.168.0.0/24" or ASN lines
        m_cidr = re.match(r"^(\d+\.\d+\.\d+\.\d+/\d+)", line)
        m_asn  = re.match(r"^(AS\d+)\s+(.*)", line, re.IGNORECASE)
        if m_cidr:
            r = DNSRecord(name="netblock", record_type="CIDR", value=m_cidr.group(1))
        elif m_asn:
            r = DNSRecord(name=m_asn.group(2).strip(), record_type="ASN",
                          value=m_asn.group(1).upper())
        else:
            r = DNSRecord(name=line, record_type="INFO", value="")
        r.add_source("metabigor")
        results.append(r)
    return results


# ── Port scan parsers ─────────────────────────────────────────────────────────

def parse_nmap(output_dir: str) -> list[PortResult]:
    results = []
    lines = _read_lines(os.path.join(output_dir, "nmap_results.txt"))
    current_host = ""
    for line in lines:
        host_m = re.match(r"Nmap scan report for (\S+)", line)
        if host_m:
            current_host = host_m.group(1).strip("()")
            continue
        port_m = re.match(
            r"^(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+(\S+)\s*(.*)", line
        )
        if port_m and current_host:
            r = PortResult(
                host=current_host,
                port=int(port_m.group(1)),
                protocol=port_m.group(2),
                state=port_m.group(3),
                service=port_m.group(4),
                version=port_m.group(5).strip(),
            )
            r.add_source("nmap")
            results.append(r)
    return results


def parse_naabu(output_dir: str) -> list[PortResult]:
    results = []
    for line in _read_lines(os.path.join(output_dir, "naabu_results.txt")):
        m = re.match(r"^([^:]+):(\d+)", line)
        if m:
            r = PortResult(host=m.group(1), port=int(m.group(2)), state="open")
            r.add_source("naabu")
            results.append(r)
    return results


# ── HTTP probing parsers ──────────────────────────────────────────────────────

def parse_httpx(output_dir: str) -> list[LiveHost]:
    results = []
    # httpx can output plain text or JSON; try JSON first
    for line in _read_lines(os.path.join(output_dir, "httpx_results.txt")):
        try:
            obj = json.loads(line)
            raw_cpe = obj.get("cpe", []) or []
            cpe_list = [
                c["cpe"] if isinstance(c, dict) else c
                for c in raw_cpe if c
            ]
            r = LiveHost(
                url=obj.get("url", ""),
                status_code=obj.get("status_code", 0),
                title=obj.get("title", ""),
                technologies=obj.get("tech", []) or [],
                content_length=obj.get("content_length", 0),
                redirect_url=obj.get("location", ""),
                host=obj.get("host", ""),
                host_ip=obj.get("host_ip", ""),
                ip_addresses=obj.get("a", []) or [],
                ipv6_addresses=obj.get("aaaa", []) or [],
                cname=obj.get("cname", []) or [],
                webserver=obj.get("webserver", ""),
                scheme=obj.get("scheme", ""),
                port=str(obj.get("port", "")),
                words=obj.get("words", 0),
                lines=obj.get("lines", 0),
                cdn=bool(obj.get("cdn", False)),
                cdn_name=obj.get("cdn_name", ""),
                cdn_type=obj.get("cdn_type", ""),
                cpe=cpe_list,
            )
        except json.JSONDecodeError:
            # plain text: "https://example.com [200] [Title]"
            m = re.match(r"^(https?://\S+)\s+\[(\d+)\]\s*(?:\[([^\]]*)\])?", line)
            if not m:
                continue
            r = LiveHost(url=m.group(1), status_code=int(m.group(2)),
                         title=m.group(3) or "")
        if r.url:
            r.add_source("httpx")
            results.append(r)
    return results


# ── Crawl / endpoint parsers ──────────────────────────────────────────────────

def _parse_url_lines(path: str, tool: str) -> list[EndpointResult]:
    results = []
    for line in _read_lines(path):
        url = line.split()[0] if " " in line else line
        if not _URL_RE.match(url):
            continue
        r = EndpointResult(url=url.rstrip("/"))
        r.add_source(tool)
        results.append(r)
    return results


def parse_gospider(output_dir: str) -> list[EndpointResult]:
    results = []
    for line in _read_lines(os.path.join(output_dir, "gospider_results.txt")):
        try:
            obj = json.loads(line)
            url = obj.get("output", "")
            if _URL_RE.match(url):
                r = EndpointResult(url=url.rstrip("/"),
                                   status_code=obj.get("status", 0))
                r.add_source("gospider")
                results.append(r)
            # sub-urls
            for sub in obj.get("data", []):
                sub_url = sub if isinstance(sub, str) else sub.get("url", "")
                if _URL_RE.match(sub_url):
                    sr = EndpointResult(url=sub_url.rstrip("/"))
                    sr.add_source("gospider")
                    results.append(sr)
        except json.JSONDecodeError:
            if _URL_RE.match(line):
                r = EndpointResult(url=line.rstrip("/"))
                r.add_source("gospider")
                results.append(r)
    return results


def parse_katana(output_dir: str) -> list[EndpointResult]:
    results = []
    for obj in _read_jsonl(os.path.join(output_dir, "katana_results.txt")):
        url = obj.get("request", {}).get("endpoint", "") or obj.get("endpoint", "")
        method = obj.get("request", {}).get("method", "GET")
        ct = obj.get("response", {}).get("headers", {}).get("content-type", "")
        status = obj.get("response", {}).get("status_code", 0)
        if url and _URL_RE.match(url):
            r = EndpointResult(url=url.rstrip("/"), method=method,
                               status_code=status, content_type=ct.split(";")[0])
            r.add_source("katana")
            results.append(r)
    # also handle plain URL per line
    if not results:
        results = _parse_url_lines(
            os.path.join(output_dir, "katana_results.txt"), "katana"
        )
    return results


def parse_waybackurls(output_dir: str) -> list[EndpointResult]:
    return _parse_url_lines(
        os.path.join(output_dir, "waybackurls_results.txt"), "waybackurls"
    )


def parse_gau(output_dir: str) -> list[EndpointResult]:
    return _parse_url_lines(
        os.path.join(output_dir, "gau_results.txt"), "gau"
    )


def parse_linkfinder(output_dir: str) -> list[EndpointResult]:
    results = []
    for candidate in ["linkfinder_results.txt", "linkFinder_Subdomains.txt"]:
        for line in _read_lines(os.path.join(output_dir, candidate)):
            if _URL_RE.match(line):
                r = EndpointResult(url=line.rstrip("/"))
            elif line.startswith("/"):
                r = EndpointResult(url=line)   # relative path
            else:
                continue
            r.add_source("linkfinder")
            results.append(r)
    return results



def parse_xnlinkfinder(output_dir: str) -> list[EndpointResult]:
    results = []
    for line in _read_lines(os.path.join(output_dir, "xnlinkfinder_results.txt")):
        if _URL_RE.match(line):
            r = EndpointResult(url=line.rstrip("/"))
        elif line.startswith("/"):
            r = EndpointResult(url=line)
        else:
            continue
        r.add_source("xnlinkfinder")
        results.append(r)
    return results


# ── Parameter parsers ─────────────────────────────────────────────────────────

def parse_arjun(output_dir: str) -> list[ParamResult]:
    results = []
    data = _read_json(os.path.join(output_dir, "arjun_results.json"))
    if isinstance(data, dict):
        data = [data]
    if isinstance(data, list):
        for entry in data:
            if not isinstance(entry, dict):
                continue
            url = entry.get("url", "")
            method = entry.get("method", "GET")
            for param in entry.get("params", []):
                r = ParamResult(name=param, endpoint=url,
                                method=method, param_type="query")
                r.add_source("arjun")
                results.append(r)
    return results


def parse_parameth(output_dir: str) -> list[ParamResult]:
    results = []
    for line in _read_lines(os.path.join(output_dir, "parameth_results.txt")):
        # parameth: "Found parameter: name=value at URL"
        m = re.search(r"Found\s+parameter[:\s]+(\w+)(?:=\S+)?\s+at\s+(\S+)", line, re.I)
        if m:
            r = ParamResult(name=m.group(1), endpoint=m.group(2), method="GET")
            r.add_source("parameth")
            results.append(r)
        else:
            # plain "name=value" lines
            m2 = re.match(r"^([A-Za-z_]\w*)[=\s]", line)
            if m2:
                r = ParamResult(name=m2.group(1), endpoint="")
                r.add_source("parameth")
                results.append(r)
    return results


def parse_x8(output_dir: str) -> list[ParamResult]:
    results = []
    for line in _read_lines(os.path.join(output_dir, "x8_results.txt")):
        # x8 output: "param | endpoint | method | type"
        parts = [p.strip() for p in line.split("|")]
        if len(parts) >= 2:
            r = ParamResult(
                name=parts[0],
                endpoint=parts[1] if len(parts) > 1 else "",
                method=parts[2] if len(parts) > 2 else "GET",
                param_type=parts[3] if len(parts) > 3 else "query",
            )
            r.add_source("x8")
            results.append(r)
        elif re.match(r"^[A-Za-z_]\w*$", line):
            r = ParamResult(name=line, endpoint="")
            r.add_source("x8")
            results.append(r)
    return results


# ── Fuzzing parsers ───────────────────────────────────────────────────────────

def parse_ffuf(output_dir: str) -> list[FuzzResult]:
    results = []
    data = _read_json(os.path.join(output_dir, "ffuf_results.json"))
    if not data:
        return results
    base_url = data.get("commandline", "").replace("/FUZZ", "")
    for entry in data.get("results", []):
        url = entry.get("url", "")
        path = url.replace(base_url, "") if base_url else url
        r = FuzzResult(
            url=base_url.rstrip("/"),
            path=path.lstrip("/"),
            status_code=entry.get("status", 0),
            content_length=entry.get("length", 0),
            words=entry.get("words", 0),
            lines=entry.get("lines", 0),
            redirect_url=entry.get("redirectlocation", ""),
        )
        r.add_source("ffuf")
        results.append(r)
    return results


def parse_cewl(output_dir: str) -> list[WordlistEntry]:
    results = []
    for word in _read_lines(os.path.join(output_dir, "cewl_wordlist.txt")):
        if word and not word.startswith("#") and len(word) >= 3:
            r = WordlistEntry(word=word)
            r.add_source("cewl")
            results.append(r)
    return results


# ── Vulnerability parsers ─────────────────────────────────────────────────────

def parse_nuclei(output_dir: str) -> list[VulnFinding]:
    results = []
    for obj in _read_jsonl(os.path.join(output_dir, "nuclei_results.jsonl")):
        info = obj.get("info", {})
        r = VulnFinding(
            template_id=obj.get("template-id", ""),
            name=info.get("name", obj.get("template-id", "")),
            severity=info.get("severity", "").lower(),
            url=obj.get("matched-at", obj.get("host", "")),
            matched=obj.get("matched-at", ""),
            description=info.get("description", ""),
            tags=info.get("tags", []) if isinstance(info.get("tags"), list)
                 else info.get("tags", "").split(","),
        )
        r.add_source("nuclei")
        results.append(r)
    return results


# ── OSINT parsers ─────────────────────────────────────────────────────────────

def parse_github_recon(output_dir: str) -> list[OSINTResult]:
    results = []
    for line in _read_lines(os.path.join(output_dir, "github_recon_results.txt")):
        if _URL_RE.match(line):
            r = OSINTResult(result_type="github_endpoint", value=line, provider="github")
        elif _is_domain(line):
            r = OSINTResult(result_type="github_domain", value=line, provider="github")
        else:
            r = OSINTResult(result_type="github_match", value=line, provider="github")
        r.add_source("github_recon")
        results.append(r)
    return results


def parse_cloud_enum(output_dir: str) -> list[OSINTResult]:
    results = []
    provider_map = {"s3": "aws", "blob": "azure", "storage.googleapis": "gcp"}
    for line in _read_lines(os.path.join(output_dir, "cloud_enum_results.txt")):
        if not line or line.startswith("["):
            continue
        provider = "unknown"
        for keyword, prov in provider_map.items():
            if keyword in line.lower():
                provider = prov
                break
        r = OSINTResult(
            result_type="cloud_bucket",
            value=line,
            provider=provider,
        )
        r.add_source("cloud_enum")
        results.append(r)
    return results


# ── JWT parsers ───────────────────────────────────────────────────────────────

def parse_jwt_tool(output_dir: str) -> list[VulnFinding]:
    results = []
    keywords = [
        "vulnerable", "accepted", "success", "alg:none", "claim",
        "invalid", "expired", "forged", "bypass", "confusion",
    ]
    for line in _read_lines(os.path.join(output_dir, "jwt_tool_output.txt")):
        if any(kw in line.lower() for kw in keywords):
            r = VulnFinding(
                template_id="jwt_tool",
                name="JWT Finding",
                severity="high",
                url="",
                matched=line.strip(),
                description=line.strip(),
                tags=["jwt"],
            )
            r.add_source("jwt_tool")
            results.append(r)
    return results


def parse_graphql_tools(output_dir: str) -> list:
    results = []
    keywords = [
        "graphql", "apollo", "hasura", "graphene", "strawberry", "dgraph",
        "ariadne", "juniper", "absinthe", "sangria", "lighthouse",
        "vulnerable", "found", "detected", "introspection", "error",
        "engine", "identified", "version",
    ]
    for line in _read_lines(os.path.join(output_dir, "fingerprint.txt")):
        if any(k in line.lower() for k in keywords):
            r = VulnFinding(
                template_id="graphql_tools",
                name="GraphQL Finding",
                severity="info",
                url="",
                matched=line.strip(),
                description=line.strip(),
                tags=["graphql"],
            )
            r.add_source("graphql_tools")
            results.append(r)

    schema_path = os.path.join(output_dir, "schema.json")
    if os.path.exists(schema_path):
        try:
            data = json.loads(Path(schema_path).read_text(errors="replace"))
            types = (data.get("data", {}).get("__schema", {}).get("types") or [])
            user_types = [t for t in types if t.get("name", "").startswith("__") is False]
            r = VulnFinding(
                template_id="graphql_schema",
                name="GraphQL Schema Discovered",
                severity="medium",
                url="",
                matched=f"{len(user_types)} types recovered via clairvoyance",
                description=f"Schema inferred via field-suggestion fuzzing: {len(user_types)} types found.",
                tags=["graphql", "schema", "discovery"],
            )
            r.add_source("graphql_tools")
            results.append(r)
        except Exception:
            pass

    return results


# ── XSS / reflection parsers ─────────────────────────────────────────────────

def parse_kxss(output_dir: str) -> list[VulnFinding]:
    results = []
    for line in _read_lines(os.path.join(output_dir, "kxss_results.txt")):
        url_m = re.search(r"(https?://\S+)", line)
        chars_m = re.search(r"chars?:\s*(.+)", line, re.I)
        if not url_m:
            continue
        chars = chars_m.group(1).strip() if chars_m else "unknown"
        r = VulnFinding(
            template_id="kxss",
            name="Reflected Parameter Detected",
            severity="medium",
            url=url_m.group(1),
            matched=line.strip(),
            description=f"Parameter reflected unescaped. Surviving chars: {chars}",
            tags=["xss", "reflection"],
        )
        r.add_source("kxss")
        results.append(r)
    return results


def parse_gxss(output_dir: str) -> list[VulnFinding]:
    results = []
    for line in _read_lines(os.path.join(output_dir, "gxss_results.txt")):
        if not _URL_RE.match(line):
            continue
        r = VulnFinding(
            template_id="gxss",
            name="Reflected Parameter Detected",
            severity="medium",
            url=line,
            matched=line,
            description="Parameter value reflected in response body.",
            tags=["xss", "reflection"],
        )
        r.add_source("gxss")
        results.append(r)
    return results


def parse_dalfox(output_dir: str) -> list[VulnFinding]:
    results = []
    for obj in _read_jsonl(os.path.join(output_dir, "dalfox_results.txt")):
        raw_sev = obj.get("severity", obj.get("type", "medium"))
        sev_map = {"G": "high", "E": "medium", "HIGH": "high",
                   "MEDIUM": "medium", "LOW": "low"}
        severity = sev_map.get(str(raw_sev).upper(), "medium")
        url = obj.get("data", obj.get("url", ""))
        r = VulnFinding(
            template_id="dalfox",
            name="Cross-Site Scripting (XSS)",
            severity=severity,
            url=url,
            matched=obj.get("poc", obj.get("payload", url)),
            description=f"Param: {obj.get('param', '?')} — Payload: {obj.get('payload', '')}",
            tags=["xss", "cwe-79"],
        )
        r.add_source("dalfox")
        results.append(r)
    return results


# ── SQL injection parsers ─────────────────────────────────────────────────────

def parse_sqlmap(output_dir: str) -> list[VulnFinding]:
    results = []
    _INJECT_RE = re.compile(
        r"(parameter\s+'?([^']+)'?\s+is\s+'([^']+)'\s+injectable"
        r"|identified the following injection point"
        r"|Type:\s+(.+))",
        re.I,
    )
    for log_file in Path(output_dir).rglob("log"):
        current_target = ""
        for line in _read_lines(str(log_file)):
            target_m = re.search(r"testing URL\s+'?(https?://\S+?)'?$", line, re.I)
            if target_m:
                current_target = target_m.group(1)
            if _INJECT_RE.search(line):
                r = VulnFinding(
                    template_id="sqlmap",
                    name="SQL Injection",
                    severity="critical",
                    url=current_target,
                    matched=line.strip(),
                    description=line.strip(),
                    tags=["sqli", "cwe-89"],
                )
                r.add_source("sqlmap")
                results.append(r)
    return results


# ── Screenshot parsers ────────────────────────────────────────────────────────

def parse_gowitness(output_dir: str) -> list[ScreenshotResult]:
    results = []
    for obj in _read_jsonl(os.path.join(output_dir, "gowitness.jsonl")):
        url = obj.get("url", "")
        if not url:
            continue
        techs = []
        for t in obj.get("technologies", []) or []:
            name = t.get("name", "") if isinstance(t, dict) else str(t)
            if name:
                techs.append(name)
        r = ScreenshotResult(
            url=url,
            final_url=obj.get("final_url", url),
            status_code=obj.get("response_code", obj.get("status_code", 0)),
            title=obj.get("title", ""),
            screenshot_path=obj.get("screenshot_path", ""),
            technologies=techs,
        )
        r.add_source("gowitness")
        results.append(r)
    return results


# ── Subdomain takeover parsers ────────────────────────────────────────────────

def parse_subzy(output_dir: str) -> list[VulnFinding]:
    results = []
    data = _read_json(os.path.join(output_dir, "subzy_results.json"))
    if isinstance(data, list):
        for entry in data:
            if not isinstance(entry, dict):
                continue
            if not entry.get("vulnerable", False):
                continue
            subdomain = entry.get("subdomain", entry.get("target", ""))
            service   = entry.get("service", entry.get("fingerprint", ""))
            r = VulnFinding(
                template_id="subzy",
                name="Subdomain Takeover",
                severity="high",
                url=subdomain,
                matched=f"{subdomain} → {service}",
                description=f"Unclaimed {service} resource; subdomain may be hijacked.",
                tags=["takeover", "subdomain"],
            )
            r.add_source("subzy")
            results.append(r)
    else:
        for line in _read_lines(os.path.join(output_dir, "subzy_results.txt")):
            if "[VULNERABLE]" not in line.upper():
                continue
            r = VulnFinding(
                template_id="subzy",
                name="Subdomain Takeover",
                severity="high",
                url=line,
                matched=line.strip(),
                description=line.strip(),
                tags=["takeover", "subdomain"],
            )
            r.add_source("subzy")
            results.append(r)
    return results


# ── WAF detection parsers ─────────────────────────────────────────────────────

def parse_wafw00f(output_dir: str) -> list[VulnFinding]:
    results = []
    data = _read_json(os.path.join(output_dir, "wafw00f_results.json"))
    entries = data if isinstance(data, list) else ([data] if isinstance(data, dict) else [])
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        url      = entry.get("url", "")
        detected = entry.get("detected", False)
        firewall = entry.get("firewall", "Unknown WAF")
        severity = "info" if detected else "info"
        r = VulnFinding(
            template_id="wafw00f",
            name=f"WAF Detected: {firewall}" if detected else "No WAF Detected",
            severity=severity,
            url=url,
            matched=firewall if detected else "none",
            description=(
                f"{firewall} is protecting {url}." if detected
                else f"No WAF detected in front of {url}."
            ),
            tags=["waf", "recon"],
        )
        r.add_source("wafw00f")
        results.append(r)
    return results


# ── CORS parsers ──────────────────────────────────────────────────────────────

def parse_corsy(output_dir: str) -> list[VulnFinding]:
    results = []
    data = _read_json(os.path.join(output_dir, "corsy_results.json"))
    if not isinstance(data, dict):
        return results
    for url, detail in data.items():
        if not isinstance(detail, dict):
            continue
        cls = detail.get("class", "")
        if not cls or cls.lower() in ("not vulnerable", "secure"):
            continue
        origin = detail.get("origin", "")
        creds  = detail.get("credentials", False)
        sev    = "high" if creds else "medium"
        r = VulnFinding(
            template_id="corsy",
            name=f"CORS Misconfiguration: {cls}",
            severity=sev,
            url=url,
            matched=f"Reflected origin: {origin}, credentials: {creds}",
            description=(
                f"{cls} CORS policy on {url}. "
                f"Origin '{origin}' is reflected"
                + (" with credentials." if creds else ".")
            ),
            tags=["cors", "cwe-942"],
        )
        r.add_source("corsy")
        results.append(r)
    return results


# ── Secret / credential parsers ───────────────────────────────────────────────

_SECRET_RE = re.compile(
    r"\[(?:CRITICAL|HIGH|MEDIUM|LOW|INFO)\]\s*(.+?):\s*(.+)", re.I
)

def parse_secretfinder(output_dir: str) -> list[VulnFinding]:
    results = []
    for line in _read_lines(os.path.join(output_dir, "secretfinder_results.txt")):
        m = _SECRET_RE.match(line)
        if not m:
            continue
        secret_type = m.group(1).strip()
        value       = m.group(2).strip()
        sev_m = re.match(r"\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]", line, re.I)
        sev_map = {"critical": "critical", "high": "high",
                   "medium": "medium", "low": "low", "info": "info"}
        sev = sev_map.get((sev_m.group(1).lower() if sev_m else ""), "medium")
        r = VulnFinding(
            template_id="secretfinder",
            name=f"Exposed Secret: {secret_type}",
            severity=sev,
            url="",
            matched=value[:120],
            description=f"{secret_type} found in JavaScript: {value[:200]}",
            tags=["secrets", "exposure", "js"],
        )
        r.add_source("secretfinder")
        results.append(r)
    return results


# ── API discovery parsers (kiterunner) ────────────────────────────────────────

_KR_RE = re.compile(
    r"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+\d+\s+\[.*?\]\s+(https?://\S+)", re.I
)

def parse_kiterunner(output_dir: str) -> list[EndpointResult]:
    results = []
    for line in _read_lines(os.path.join(output_dir, "kiterunner_results.txt")):
        m = _KR_RE.search(line)
        if not m:
            continue
        r = EndpointResult(url=m.group(2).rstrip("/"), method=m.group(1).upper())
        r.add_source("kiterunner")
        results.append(r)
    return results


# ── Master parser registry ────────────────────────────────────────────────────

PARSERS: dict[str, callable] = {
    # subdomain
    "amass":         parse_amass,
    "assetfinder":   parse_assetfinder,
    "subfinder":     parse_subfinder,
    "sublist3r":     parse_sublist3r,
    "subdomainizer": parse_subdomainizer,
    "shuffledns":    parse_shuffledns,
    "ctl":           parse_ctl,
    # dns
    "dnsx":          parse_dnsx,
    "metabigor":     parse_metabigor,
    # portscan
    "nmap":          parse_nmap,
    "naabu":         parse_naabu,
    # http
    "httpx":         parse_httpx,
    # crawl
    "gospider":      parse_gospider,
    "katana":        parse_katana,
    "waybackurls":   parse_waybackurls,
    "gau":           parse_gau,
    "linkfinder":    parse_linkfinder,
    "xnlinkfinder":  parse_xnlinkfinder,
    # fuzz
    "ffuf":          parse_ffuf,
    "cewl":          parse_cewl,
    # params
    "arjun":         parse_arjun,
    "parameth":      parse_parameth,
    "x8":            parse_x8,
    # vuln
    "nuclei":        parse_nuclei,
    "jwt_tool":      parse_jwt_tool,
    "graphql_tools": parse_graphql_tools,
    # xss / reflection
    "kxss":          parse_kxss,
    "gxss":          parse_gxss,
    "dalfox":        parse_dalfox,
    # sqli
    "sqlmap":        parse_sqlmap,
    # screenshot
    "gowitness":     parse_gowitness,
    # takeover
    "subzy":         parse_subzy,
    # waf
    "wafw00f":       parse_wafw00f,
    # cors
    "corsy":         parse_corsy,
    # secrets
    "secretfinder":  parse_secretfinder,
    # api
    "kiterunner":    parse_kiterunner,
    # osint
    "github_recon":  parse_github_recon,
    "cloud_enum":    parse_cloud_enum,
}
