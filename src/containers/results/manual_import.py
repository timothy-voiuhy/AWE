"""Manual import — parse user-supplied plaintext into result models.

Backs the Results page's "Import" button, letting subdomains or URL
endpoints discovered outside AWE's own tools (another scanner's output, a
scope document, etc.) be seeded directly into the Results page — and, since
they land in the normal results collection, into scope-aware pipeline inputs
too — without having to run a container for them.
"""
from __future__ import annotations

from urllib.parse import urlsplit

from containers.results.models import EndpointResult, SubdomainResult

SOURCE = "manual_import"

_HTTP_METHODS = {
    "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "CONNECT", "TRACE",
}


def parse_subdomains(text: str) -> list[SubdomainResult]:
    """One hostname per line. A scheme/path/port, if present, is stripped —
    only the bare host is kept. Blank lines and '#' comments are skipped."""
    out: list[SubdomainResult] = []
    seen: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        host = _extract_host(line)
        if not host or host in seen:
            continue
        seen.add(host)
        out.append(SubdomainResult(domain=host, sources=[SOURCE]))
    return out


def parse_endpoints(text: str) -> list[EndpointResult]:
    """One URL per line, optionally prefixed with an HTTP method
    (e.g. "POST https://host/api/login"). A bare host/path with no scheme is
    treated as https://. Blank lines and '#' comments are skipped."""
    out: list[EndpointResult] = []
    seen: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        method = "GET"
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[0].upper() in _HTTP_METHODS:
            method, line = parts[0].upper(), parts[1].strip()
        url = _normalize_url(line)
        if not url:
            continue
        key = f"{method} {url}".lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(EndpointResult(url=url, method=method, sources=[SOURCE]))
    return out


def _extract_host(line: str) -> str:
    candidate = line
    if "://" in candidate:
        candidate = urlsplit(candidate).netloc or candidate
    # Strip any leftover userinfo/port/path/query.
    candidate = candidate.split("@")[-1].split("/")[0].split("?")[0].split(":")[0]
    return candidate.strip().lower().rstrip(".")


def _normalize_url(line: str) -> str:
    if "://" not in line:
        line = f"https://{line}"
    if not urlsplit(line).netloc:
        return ""
    return line
