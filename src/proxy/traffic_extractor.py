"""
TrafficExtractor — mines proxy traffic from MongoDB for security-relevant data.

Reads from awe_proxy_traffic.traffic and extracts:
  - SubdomainResult:  unique hostnames observed
  - LiveHost:         URLs with 2xx/3xx responses + technology hints
  - EndpointResult:   unique (method, path) pairs (skips static assets)
  - ParamResult:      query string and request body parameters
  - CdnResult:        CDN/proxy layer detection with role classification
                       (CDN | Reverse Proxy | CDN/Reverse Proxy)
  - VulnFinding:      passive misconfiguration findings — insecure cookie flags,
                       missing security response headers, CORS misconfiguration,
                       secrets spotted in response bodies (see proxy.passive_detect)

`extract()` also returns a second dict of *review candidates* — JWTs and
GraphQL-shaped requests spotted in traffic. These aren't results (there's
nothing to "discover" about them, they just need a human to look at them), so
they're queued for review on the JWT/GraphQL pages instead of landing in the
Results table — see AweRepository.create_review_item.

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
import time
from pathlib import PurePosixPath
from urllib.parse import urlsplit, parse_qs

from PySide6.QtCore import QThread, Signal

from containers.results.models import (
    SubdomainResult, LiveHost, EndpointResult, ParamResult, CdnResult,
    VulnFinding, BaseResult,
)
from database.scope import ScopeConfig
from proxy.passive_detect import (
    check_cors_misconfig,
    check_security_headers,
    detect_graphql_request,
    extract_cookie_flags,
    find_jwts_in_headers,
    find_secrets_in_text,
)

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

_DEFAULT_BATCH_SIZE = 100
_DEFAULT_BATCH_PAUSE_MS = 15
_MAX_REQUEST_BODY_SCAN_CHARS = 250_000
_MAX_SECRET_SCAN_CHARS = 250_000

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
        *,
        should_stop=None,
        batch_size: int = _DEFAULT_BATCH_SIZE,
        batch_pause_ms: int = _DEFAULT_BATCH_PAUSE_MS,
        max_request_body_scan_chars: int = _MAX_REQUEST_BODY_SCAN_CHARS,
        max_secret_scan_chars: int = _MAX_SECRET_SCAN_CHARS,
    ) -> tuple[dict[str, list[BaseResult]], dict[str, list[dict]]]:
        """Returns (results, review_candidates):
          results           — {category: [BaseResult, ...]} for the Results page
          review_candidates — {"jwt": [...], "graphql": [...]} for the review queue
        """
        results: dict[str, list[BaseResult]] = {
            "subdomain": [], "http": [], "crawl": [], "params": [], "cdn": [], "vuln": []
        }
        review_candidates: dict[str, list[dict]] = {"jwt": [], "graphql": []}
        if col is None:
            return results, review_candidates

        try:
            all_hosts = col.distinct("host")
        except Exception as exc:
            log.warning("TrafficExtractor: cannot query hosts: %s", exc)
            return results, review_candidates

        in_scope = [h for h in all_hosts if not scope or scope.matches(h)]

        for host in in_scope:
            if "." in host:
                results["subdomain"].append(
                    SubdomainResult(domain=host, sources=[_SOURCE])
                )

        if not in_scope:
            return results, review_candidates

        try:
            # tool_source: None matches both docs missing the field and docs
            # explicitly tagged None — excludes traffic AWE's own testing
            # panels (GraphQL/WebSocket/etc.) generated about themselves so
            # it never re-enters Results or the review queues. See proxy._markers.
            cursor = col.aggregate(
                [
                    {"$match": {"host": {"$in": in_scope}, "tool_source": None}},
                    {"$project": {
                        "host": 1,
                        "method": 1,
                        "path": 1,
                        "status_code": 1,
                        "request.method": 1,
                        "request.url": 1,
                        "request.headers": 1,
                        "request.body": {
                            "$substrCP": [
                                {"$ifNull": ["$request.body", ""]},
                                0,
                                max(0, max_request_body_scan_chars),
                            ]
                        },
                        "response.status_code": 1,
                        "response.headers": 1,
                        "response.body": {
                            "$substrCP": [
                                {"$ifNull": ["$response.body", ""]},
                                0,
                                max(0, max_secret_scan_chars),
                            ]
                        },
                    }},
                ],
                batchSize=max(1, batch_size),
            )
        except Exception as exc:
            log.warning("TrafficExtractor: cursor failed: %s", exc)
            return results, review_candidates

        # Accumulate CDN evidence across ALL documents before classifying.
        # Key: (host, provider)  →  _CdnStats
        cdn_stats: dict[tuple[str, str], _CdnStats] = {}

        for index, doc in enumerate(cursor, start=1):
            if should_stop and should_stop():
                break
            try:
                self._process_doc(
                    doc,
                    results,
                    cdn_stats,
                    review_candidates,
                    max_secret_scan_chars=max_secret_scan_chars,
                )
            except Exception as exc:
                log.debug("skip doc %s: %s", doc.get("_id"), exc)
            if batch_pause_ms > 0 and index % max(1, batch_size) == 0:
                time.sleep(batch_pause_ms / 1000)

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

        return results, review_candidates

    # ── Per-document processing ───────────────────────────────────────────────

    def _process_doc(
        self,
        doc: dict,
        results: dict[str, list[BaseResult]],
        cdn_stats: dict[tuple[str, str], _CdnStats],
        review_candidates: dict[str, list[dict]],
        *,
        max_secret_scan_chars: int = _MAX_SECRET_SCAN_CHARS,
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
        is_https = parsed.scheme == "https"

        ext       = PurePosixPath(path).suffix.lower()
        is_static = ext in _STATIC_EXTS

        base_url = f"{parsed.scheme}://{parsed.netloc}{path}".rstrip("/") or url
        # Host-root URL (no path) — LiveHost represents one row per live host,
        # like httpx's output, not one row per endpoint. Using base_url here
        # would create a separate "Live Host" row for every distinct path hit
        # on the same host.
        host_url = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else url

        # ── Tech detection from response headers ──────────────────────────────
        resp_headers: dict = resp.get("headers", {}) or {}
        req_headers:  dict = req.get("headers", {}) or {}

        # ── JWT candidates (review queue, not a result) ────────────────────────
        for jwt_hit in find_jwts_in_headers(req_headers):
            review_candidates["jwt"].append({
                "token": jwt_hit["token"],
                "header_name": jwt_hit["header_name"],
                "source_url": base_url,
            })

        # ── Passive misconfiguration findings (cookies / security headers / CORS) ──
        for flag in extract_cookie_flags(resp_headers):
            issues = []
            if not flag["secure"] and is_https:
                issues.append(("insecure_cookie_no_secure", "low", "Cookie missing Secure flag"))
            if not flag["httponly"]:
                issues.append(("insecure_cookie_no_httponly", "low", "Cookie missing HttpOnly flag"))
            if not flag["samesite"]:
                issues.append(("insecure_cookie_no_samesite", "info", "Cookie missing SameSite attribute"))
            for template_id, severity, desc in issues:
                results["vuln"].append(VulnFinding(
                    template_id=f"{template_id}:{flag['name']}",
                    name=f"{desc} ({flag['name']})",
                    severity=severity,
                    url=base_url,
                    description=f"Cookie '{flag['name']}' observed on {base_url} — {desc.lower()}.",
                    tags=["passive", "cookie"],
                    sources=[_SOURCE],
                ))

        for issue_code in check_security_headers(resp_headers, is_https):
            results["vuln"].append(VulnFinding(
                template_id=issue_code,
                name=f"Missing security header ({issue_code.replace('missing_', '').upper()})",
                severity="info",
                url=base_url,
                description=f"Response from {base_url} is missing the {issue_code.replace('missing_', '')} header.",
                tags=["passive", "security_misconfig"],
                sources=[_SOURCE],
            ))

        cors_issue = check_cors_misconfig(resp_headers)
        if cors_issue:
            results["vuln"].append(VulnFinding(
                template_id=cors_issue,
                name="CORS misconfiguration",
                severity="medium",
                url=base_url,
                description=f"{base_url} reflects credentialed CORS access ({cors_issue}).",
                tags=["passive", "cors"],
                sources=[_SOURCE],
            ))

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
                url=host_url,
                host=host,
                status_code=status,
                technologies=techs,
                sources=[_SOURCE],
            ))

        if is_static:
            return

        # ── Request content-type ──────────────────────────────────────────────
        req_ct  = _hdr_str(req_headers,  "content-type").split(";")[0].strip()
        resp_ct = _hdr_str(resp_headers, "content-type").split(";")[0].strip()

        body = req.get("body", "") or ""

        # ── GraphQL candidates (review queue, not a result) ────────────────────
        graphql_hit = detect_graphql_request(method, req_ct, body, path)
        if graphql_hit:
            review_candidates["graphql"].append({
                "endpoint": base_url,
                "query": graphql_hit["query"],
                "variables": graphql_hit["variables"],
            })

        # ── Secrets spotted in the response body ───────────────────────────────
        resp_body = resp.get("body", "") or ""
        if max_secret_scan_chars > 0 and len(resp_body) > max_secret_scan_chars:
            resp_body = resp_body[:max_secret_scan_chars]
        for secret_hit in find_secrets_in_text(resp_body):
            results["vuln"].append(VulnFinding(
                template_id=f"secret:{secret_hit['kind']}",
                name=f"Possible {secret_hit['kind'].replace('_', ' ')} in response",
                severity="high",
                url=base_url,
                matched=secret_hit["match"],
                description=f"Response body from {base_url} contains a pattern matching {secret_hit['kind']}.",
                tags=["passive", "secret"],
                sources=[_SOURCE],
            ))

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
    done  = Signal(dict, dict)   # (results, review_candidates)
    error = Signal(str)

    def __init__(self, col, scope: ScopeConfig | None = None, parent=None) -> None:
        super().__init__(parent)
        self._col   = col
        self._scope = scope
        self._stop_requested = False

    def stop(self) -> None:
        self._stop_requested = True
        self.requestInterruption()

    def _should_stop(self) -> bool:
        return self._stop_requested or self.isInterruptionRequested()

    def run(self) -> None:
        try:
            results, review_candidates = TrafficExtractor().extract(
                self._col,
                self._scope,
                should_stop=self._should_stop,
            )
            if self._should_stop():
                return
            self.done.emit(results, review_candidates)
        except Exception as exc:
            log.exception("TrafficExtractor failed")
            self.error.emit(str(exc))
