"""
TrafficExtractor — mines proxy traffic from MongoDB for security-relevant data.

Reads from awe_proxy_traffic.traffic and extracts:
  - SubdomainResult:  unique hostnames observed
  - LiveHost:         URLs with 2xx/3xx responses + technology hints
  - EndpointResult:   unique (method, path) pairs (skips static assets)
  - ParamResult:      query string and request body parameters
  - CdnResult:        CDN/proxy layer detection with role classification
                       (CDN | Reverse Proxy | CDN/Reverse Proxy)

CDN role classification:
  The role is determined per (host, provider) pair by analysing the *kinds*
  of requests being proxied:

  - Static evidence  (score += 1):
      • Path has a static-asset extension (.js, .png, .css, …)
      • CF-Cache-Status == HIT or REVALIDATED
      • X-Cache header starts with "HIT"

  - Dynamic evidence  (score += 1):
      • Path has no static extension (HTML page, API endpoint, etc.)
      • CF-Cache-Status == DYNAMIC or BYPASS  (Cloudflare explicitly marks
        these as not served from cache — i.e., origin is always hit)
      • HTTP method is POST, PUT, PATCH, or DELETE

  Final classification per (host, provider):
      dynamic > 0 and static > 0  → "CDN/Reverse Proxy"
      dynamic > 0 and static == 0 → "Reverse Proxy"
      static  > 0 and dynamic == 0 → "CDN"
      no evidence                  → default from _CDN_HEADER_MAP capability
"""
from __future__ import annotations

import json
import logging
from pathlib import PurePosixPath
from urllib.parse import urlsplit, parse_qs

from PySide6.QtCore import QThread, Signal

from containers.results.models import (
    SubdomainResult, LiveHost, EndpointResult, ParamResult, CdnResult,
    BaseResult,
)
from database.scope import ScopeConfig

log = logging.getLogger(__name__)

_STATIC_EXTS: frozenset[str] = frozenset({
    ".css", ".scss", ".less", ".sass",
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".webp", ".bmp", ".avif", ".tiff",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp4", ".mp3", ".avi", ".wav", ".ogg", ".flac", ".mkv", ".webm", ".mov",
    ".map",
})

_WRITE_METHODS: frozenset[str] = frozenset({"POST", "PUT", "PATCH", "DELETE"})

_SOURCE = "proxy_traffic"

_TECH_HEADERS = (
    "server", "x-powered-by", "x-generator",
    "x-aspnet-version", "x-runtime",
)

# Response headers that identify a CDN/proxy layer.
# Value tuple: (provider_name, default_capability)
# The default_capability is used only when traffic analysis yields no evidence.
_CDN_HEADER_MAP: dict[str, tuple[str, str]] = {
    "cf-ray":              ("Cloudflare",  "CDN/WAF"),
    "cf-cache-status":     ("Cloudflare",  "CDN/WAF"),
    "x-fastly-request-id": ("Fastly",      "CDN"),
    "fastly-restarts":     ("Fastly",      "CDN"),
    "x-amz-cf-id":         ("CloudFront",  "CDN"),
    "x-amz-cf-pop":        ("CloudFront",  "CDN"),
    "x-sucuri-id":         ("Sucuri",      "WAF/CDN"),
    "x-iinfo":             ("Imperva",     "WAF/CDN"),
    "x-cdn":               ("Generic CDN", "CDN"),
    "cdn-requestid":       ("BunnyCDN",    "CDN"),
    "x-akamai-request-id": ("Akamai",      "CDN"),
    "akamai-cache-status": ("Akamai",      "CDN"),
    "x-ddos-protection":   ("DDoS-Guard",  "DDoS Protection"),
}

# Cache-status header values that definitively indicate the response was
# served from origin (i.e., the provider acted as a *reverse proxy* here).
_DYNAMIC_CACHE_VALUES: frozenset[str] = frozenset({"DYNAMIC", "BYPASS", "MISS"})

# Cache-status values that confirm a cached (CDN) response.
_STATIC_CACHE_VALUES: frozenset[str] = frozenset({"HIT", "REVALIDATED", "STALE"})


# ── CDN stats accumulator type ────────────────────────────────────────────────

class _CdnStats:
    """Accumulates static vs dynamic evidence for one (host, provider) pair."""
    __slots__ = ("static", "dynamic", "default_type")

    def __init__(self, default_type: str):
        self.static:       int = 0
        self.dynamic:      int = 0
        self.default_type: str = default_type

    def classify(self) -> str:
        if self.dynamic > 0 and self.static > 0:
            return "CDN/Reverse Proxy"
        if self.dynamic > 0:
            return "Reverse Proxy"
        if self.static > 0:
            return "CDN"
        return self.default_type


class TrafficExtractor:
    """Read proxy traffic from MongoDB and return categorised BaseResult objects."""

    def extract(
        self,
        col,                          # pymongo Collection
        scope: ScopeConfig | None = None,
    ) -> dict[str, list[BaseResult]]:
        results: dict[str, list[BaseResult]] = {
            "subdomain": [], "http": [], "crawl": [], "params": [], "cdn": []
        }
        if col is None:
            return results

        try:
            all_hosts = col.distinct("host")
        except Exception as exc:
            log.warning("TrafficExtractor: cannot query hosts: %s", exc)
            return results

        in_scope = [h for h in all_hosts if not scope or scope.matches(h)]

        for host in in_scope:
            if "." in host:
                results["subdomain"].append(
                    SubdomainResult(domain=host, sources=[_SOURCE])
                )

        if not in_scope:
            return results

        try:
            cursor = col.find({"host": {"$in": in_scope}})
        except Exception as exc:
            log.warning("TrafficExtractor: cursor failed: %s", exc)
            return results

        # Accumulate CDN evidence across ALL documents before classifying.
        # Key: (host, provider)  →  _CdnStats
        cdn_stats: dict[tuple[str, str], _CdnStats] = {}

        for doc in cursor:
            try:
                self._process_doc(doc, results, cdn_stats)
            except Exception as exc:
                log.debug("skip doc %s: %s", doc.get("_id"), exc)

        # Convert accumulated evidence into classified CdnResult objects.
        # One result per (host, provider) pair.
        for (host, provider), stats in cdn_stats.items():
            results["cdn"].append(CdnResult(
                subdomain=host,
                provider=provider,
                proxy_type=stats.classify(),
                origin_masked=True,
                sources=[_SOURCE],
            ))

        return results

    # ── Per-document processing ───────────────────────────────────────────────

    def _process_doc(
        self,
        doc: dict,
        results: dict[str, list[BaseResult]],
        cdn_stats: dict[tuple[str, str], _CdnStats],
    ) -> None:
        req    = doc.get("request", {}) or {}
        resp   = doc.get("response", {}) or {}
        method = doc.get("method", req.get("method", "GET")).upper()
        path   = doc.get("path", "/") or "/"
        status = int(doc.get("status_code", resp.get("status_code", 0)) or 0)
        url    = req.get("url", "")

        if not url:
            return

        parsed = urlsplit(url)
        query  = parsed.query or ""

        ext       = PurePosixPath(path).suffix.lower()
        is_static = ext in _STATIC_EXTS

        base_url = f"{parsed.scheme}://{parsed.netloc}{path}".rstrip("/") or url

        # ── Tech detection from response headers ──────────────────────────────
        resp_headers: dict = resp.get("headers", {}) or {}
        techs: list[str] = []
        for hdr in _TECH_HEADERS:
            val = resp_headers.get(hdr) or resp_headers.get(hdr.title()) or ""
            if isinstance(val, list):
                val = val[0] if val else ""
            val = str(val).strip()
            if val:
                tech = val.split("/")[0].strip()
                if tech and tech not in techs:
                    techs.append(tech)

        # ── CDN / reverse proxy role detection ────────────────────────────────
        host = doc.get("host", "")
        for hdr_key, (provider, default_type) in _CDN_HEADER_MAP.items():
            present = resp_headers.get(hdr_key) or resp_headers.get(hdr_key.title())
            if not present:
                continue

            key = (host, provider)
            if key not in cdn_stats:
                cdn_stats[key] = _CdnStats(default_type)
            s = cdn_stats[key]

            # Check cache-status headers for Cloudflare / generic X-Cache
            cf_cache = _hdr_str(resp_headers, "cf-cache-status").upper()
            x_cache  = _hdr_str(resp_headers, "x-cache").upper()

            if cf_cache in _DYNAMIC_CACHE_VALUES:
                # Cloudflare explicitly did NOT serve this from cache →
                # the request hit the origin server → reverse proxy behaviour.
                s.dynamic += 1
            elif cf_cache in _STATIC_CACHE_VALUES or x_cache.startswith("HIT"):
                # Served directly from CDN cache → pure CDN behaviour.
                s.static += 1
            elif is_static:
                # No cache signal, but static extension → count as CDN.
                s.static += 1
            else:
                # No cache signal, dynamic path → treat as reverse proxy.
                s.dynamic += 1

            # Write methods (POST/PUT/PATCH/DELETE) always reach origin.
            if method in _WRITE_METHODS:
                s.dynamic += 1

            break  # attribute this doc to at most one provider

        # ── LiveHost for 2xx/3xx ──────────────────────────────────────────────
        if 200 <= status < 400:
            results["http"].append(LiveHost(
                url=base_url,
                status_code=status,
                technologies=techs,
                sources=[_SOURCE],
            ))

        if is_static:
            return

        # ── Request content-type ──────────────────────────────────────────────
        req_headers: dict = req.get("headers", {}) or {}
        req_ct  = _hdr_str(req_headers,  "content-type").split(";")[0].strip()
        resp_ct = _hdr_str(resp_headers, "content-type").split(";")[0].strip()

        q_params = list(parse_qs(query).keys())

        # ── Endpoint ──────────────────────────────────────────────────────────
        results["crawl"].append(EndpointResult(
            url=base_url,
            method=method,
            status_code=status,
            content_type=resp_ct,
            params=q_params,
            sources=[_SOURCE],
        ))

        # ── Query string parameters ───────────────────────────────────────────
        for name, values in parse_qs(query).items():
            results["params"].append(ParamResult(
                name=name,
                endpoint=base_url,
                method=method,
                param_type="query",
                example_value=(values[0] if values else "")[:128],
                sources=[_SOURCE],
            ))

        # ── Body parameters ───────────────────────────────────────────────────
        body = req.get("body", "") or ""
        if body:
            if req_ct == "application/json":
                try:
                    body_json = json.loads(body)
                    if isinstance(body_json, dict):
                        for bk, bv in body_json.items():
                            results["params"].append(ParamResult(
                                name=bk,
                                endpoint=base_url,
                                method=method,
                                param_type="body",
                                example_value=str(bv)[:128],
                                sources=[_SOURCE],
                            ))
                except (json.JSONDecodeError, ValueError):
                    pass
            else:
                for name, values in parse_qs(body).items():
                    results["params"].append(ParamResult(
                        name=name,
                        endpoint=base_url,
                        method=method,
                        param_type="body",
                        example_value=(values[0] if values else "")[:128],
                        sources=[_SOURCE],
                    ))


# ── Helpers ───────────────────────────────────────────────────────────────────

def _hdr_str(headers: dict, key: str) -> str:
    """Return the first value of a case-insensitive header as a stripped string."""
    v = headers.get(key) or headers.get(key.title()) or headers.get(key.upper()) or ""
    if isinstance(v, list):
        v = v[0] if v else ""
    return str(v).strip()


class _ExtractWorker(QThread):
    done  = Signal(dict)
    error = Signal(str)

    def __init__(self, col, scope: ScopeConfig | None = None, parent=None) -> None:
        super().__init__(parent)
        self._col   = col
        self._scope = scope

    def run(self) -> None:
        try:
            results = TrafficExtractor().extract(self._col, self._scope)
            self.done.emit(results)
        except Exception as exc:
            log.exception("TrafficExtractor failed")
            self.error.emit(str(exc))
