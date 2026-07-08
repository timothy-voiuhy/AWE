"""Passive detection heuristics run over captured proxy traffic.

Pure functions only — no Qt, no Mongo — so they're cheap to unit test and safe
to call from anywhere traffic documents are processed (the traffic writer
thread, TrafficExtractor, etc.).
"""
from __future__ import annotations

import base64
import json
import re
from http.cookies import SimpleCookie


def _header_str(headers: dict, name: str) -> str:
    """Case-insensitive header lookup. Values may be a bare string or a list of
    strings (repeated headers), matching TrafficStore's _headers_to_dict shape."""
    for key in (name, name.title(), name.lower(), name.upper()):
        v = headers.get(key)
        if v is not None:
            if isinstance(v, list):
                return v[0] if v else ""
            return str(v)
    return ""


def _header_all(headers: dict, name: str) -> list[str]:
    """Like _header_str but returns every value — for repeatable headers (Set-Cookie)."""
    for key in (name, name.title(), name.lower(), name.upper()):
        v = headers.get(key)
        if v is not None:
            return v if isinstance(v, list) else [str(v)]
    return []


# ── JWT detection ─────────────────────────────────────────────────────────────

_JWT_RE = re.compile(r"[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}")


def _looks_like_jwt(token: str) -> bool:
    """Structural check beyond "3 dot-separated segments": the header segment
    must base64url-decode to a JSON object containing an "alg" key. This avoids
    flagging arbitrary dotted strings (version numbers, hashes) as JWTs."""
    parts = token.split(".")
    if len(parts) != 3:
        return False
    try:
        pad = "=" * (-len(parts[0]) % 4)
        header = json.loads(base64.urlsafe_b64decode(parts[0] + pad))
        return isinstance(header, dict) and "alg" in header
    except Exception:
        return False


def find_jwts_in_headers(headers: dict) -> list[dict]:
    """Scan Authorization and Cookie header values for JWT-shaped, structurally
    valid tokens. Returns one {"token", "header_name"} dict per distinct token."""
    found: list[dict] = []
    seen: set[str] = set()

    auth = _header_str(headers, "authorization")
    for match in _JWT_RE.findall(auth):
        if match not in seen and _looks_like_jwt(match):
            seen.add(match)
            found.append({"token": match, "header_name": "Authorization"})

    cookie_header = _header_str(headers, "cookie")
    for part in cookie_header.split(";"):
        part = part.strip()
        if "=" not in part:
            continue
        name, _, value = part.partition("=")
        for match in _JWT_RE.findall(value):
            if match not in seen and _looks_like_jwt(match):
                seen.add(match)
                found.append({"token": match, "header_name": f"Cookie:{name.strip()}"})

    return found


# ── GraphQL detection ─────────────────────────────────────────────────────────

_GRAPHQL_PATH_HINT = re.compile(r"/(graphql|gql)(/|$)", re.IGNORECASE)


def detect_graphql_request(method: str, content_type: str, body: str, path: str) -> dict | None:
    """Return {"query", "variables"} if this request looks like GraphQL, else None."""
    if method.upper() != "POST" or not body:
        return None

    if "json" in content_type.lower():
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            data = None
        if isinstance(data, dict) and isinstance(data.get("query"), str) and data["query"].strip():
            return {"query": data["query"], "variables": data.get("variables") or {}}

    if _GRAPHQL_PATH_HINT.search(path or ""):
        stripped = body.strip()
        if stripped.startswith(("query", "mutation", "subscription", "{")):
            return {"query": stripped, "variables": {}}

    return None


# ── Cookie flags ──────────────────────────────────────────────────────────────

def extract_cookie_flags(headers: dict) -> list[dict]:
    """Parse every Set-Cookie response header into flag-level detail."""
    results: list[dict] = []
    for raw in _header_all(headers, "set-cookie"):
        try:
            jar: SimpleCookie = SimpleCookie()
            jar.load(raw)
        except Exception:
            continue
        for name, morsel in jar.items():
            results.append({
                "name": name,
                "secure": bool(morsel["secure"]),
                "httponly": bool(morsel["httponly"]),
                "samesite": morsel["samesite"] or None,
            })
    return results


# ── Security response headers ─────────────────────────────────────────────────

_SECURITY_HEADER_CHECKS: tuple[tuple[str, str], ...] = (
    ("strict-transport-security", "missing_hsts"),
    ("content-security-policy",   "missing_csp"),
    ("x-frame-options",           "missing_xfo"),
    ("x-content-type-options",    "missing_xcto"),
)


def check_security_headers(headers: dict, is_https: bool) -> list[str]:
    """Return issue codes for security response headers that are absent."""
    issues = []
    for header_name, issue_code in _SECURITY_HEADER_CHECKS:
        if header_name == "strict-transport-security" and not is_https:
            continue  # HSTS is meaningless to check over plain HTTP
        if not _header_str(headers, header_name):
            issues.append(issue_code)
    return issues


# ── CORS misconfiguration ─────────────────────────────────────────────────────

def check_cors_misconfig(headers: dict) -> str | None:
    """Flag a wildcard/reflected Access-Control-Allow-Origin combined with credentials."""
    origin = _header_str(headers, "access-control-allow-origin")
    creds = _header_str(headers, "access-control-allow-credentials").lower() == "true"
    if not origin or not creds:
        return None
    if origin == "*":
        return "cors_wildcard_with_credentials"
    return "cors_reflected_origin_with_credentials"


# ── Secrets in response bodies (lightweight — not a replacement for secretfinder) ──

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern], ...] = (
    ("aws_access_key",  re.compile(r"AKIA[0-9A-Z]{16}")),
    ("private_key",     re.compile(r"-----BEGIN (?:RSA |EC |)PRIVATE KEY-----")),
    ("slack_token",     re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}")),
    ("google_api_key",  re.compile(r"AIzaSy[0-9A-Za-z_\-]{33}")),
    ("generic_api_key", re.compile(r"(?i)(?:api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]")),
)


def find_secrets_in_text(text: str) -> list[dict]:
    """Lightweight regex scan for common secret patterns in a response body."""
    if not text:
        return []
    found = []
    for kind, pattern in _SECRET_PATTERNS:
        m = pattern.search(text)
        if m:
            found.append({"kind": kind, "match": m.group(0)[:80]})
    return found
