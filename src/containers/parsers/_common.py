"""
Shared helpers used by per-tool parser modules in this package.
"""
import json
import logging
import re

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
    from urllib.parse import urlsplit
    s = s.strip()
    if not s.startswith(("http://", "https://")):
        return ""
    try:
        p = urlsplit(s)
        return f"{p.scheme}://{p.netloc}{p.path}".rstrip("/")
    except Exception:
        return s.rstrip("/")


def _parse_subdomain_lines(path: str, tool: str) -> list:
    from containers.results.models import SubdomainResult
    results = []
    for line in _read_lines(path):
        domain = _norm_domain(line.split()[0] if line.split() else line)
        if _is_domain(domain):
            r = SubdomainResult(domain=domain)
            r.add_source(tool)
            results.append(r)
    return results


def _parse_url_lines(path: str, tool: str) -> list:
    from containers.results.models import EndpointResult
    results = []
    for line in _read_lines(path):
        url = line.split()[0] if " " in line else line
        if not _URL_RE.match(url):
            continue
        r = EndpointResult(url=url.rstrip("/"))
        r.add_source(tool)
        results.append(r)
    return results
