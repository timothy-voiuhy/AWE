"""Bounded HTTP transport. No redirects, ambient proxies, or cookie jar."""
import hashlib
import json
import re
import ssl
import time
from dataclasses import dataclass
from urllib.error import HTTPError
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener


class ValidationError(ValueError):
    """An actionable, static message that cannot contain request secrets."""


def origin(url):
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValidationError("Provide an HTTP(S) URL without embedded credentials")
    if any(ord(char) < 32 for char in url):
        raise ValidationError("URLs cannot contain control characters")
    return parsed.scheme, parsed.hostname.lower(), parsed.port or (443 if parsed.scheme == "https" else 80)


def safe_url(url):
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode([(key, "[redacted]") for key, _ in parse_qsl(parsed.query, keep_blank_values=True)]), ""))


def parse_context(value, base):
    if isinstance(value, str):
        if len(value.encode()) > 65536:
            raise ValidationError("Request contexts must not exceed 64 KiB")
        value = json.loads(value or "{}")
    if not isinstance(value, dict):
        raise ValidationError("Request context must be a JSON object")
    result = dict(value)
    if "raw_request" in result:
        raw = result.pop("raw_request")
        if not isinstance(raw, str):
            raise ValidationError("raw_request must be text")
        head, _, body = raw.replace("\r\n", "\n").partition("\n\n")
        lines = head.splitlines()
        method, path, protocol = lines[0].split(" ", 2)
        if not protocol.startswith("HTTP/"):
            raise ValidationError("raw_request must contain an HTTP request line")
        url = urljoin(base, path)
        if origin(url) != origin(base):
            raise ValidationError("Captured request must stay on the selected origin")
        headers = {}
        for line in lines[1:]:
            key, separator, val = line.partition(":")
            if not separator:
                raise ValidationError("Invalid captured request header")
            headers[key.strip()] = val.strip()
        result.update(method=method, url=url, headers=headers, body=body)
    if not isinstance(result.get("headers", {}), dict):
        raise ValidationError("headers must be a JSON object")
    if result.get("url"):
        result["url"] = urljoin(base, result["url"])
        if origin(result["url"]) != origin(base):
            raise ValidationError("Request context must stay on the selected origin")
    return result


def anonymous(headers):
    return {key: value for key, value in headers.items() if key.lower() not in {"authorization", "cookie", "proxy-authorization", "x-api-key", "api-key"}}


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@dataclass
class Response:
    status: int
    headers: list
    text: str
    evidence_id: str
    truncated: bool = False

    def values(self, key):
        return [str(value) for name, value in self.headers if name.lower() == key.lower()]

    def header(self, key):
        return ", ".join(self.values(key))


class Transport:
    def __init__(self, config):
        self.config = config
        self.base = config["url"]
        self.target_origin = origin(self.base)
        self.max_requests = int(config.get("max_requests", 12))
        self.timeout = float(config.get("timeout", 10))
        self.max_bytes = int(config.get("max_bytes", 1048576))
        self.delay = float(config.get("delay", .1))
        if not (1 <= self.max_requests <= 32 and .1 <= self.timeout <= 20 and 1024 <= self.max_bytes <= 2097152 and 0 <= self.delay <= 2):
            raise ValidationError("Invalid request, timeout, delay, or response-size limit")
        context = ssl.create_default_context()
        if config.get("insecure_tls") is True:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        self.opener = build_opener(ProxyHandler({}), NoRedirect(), HTTPSHandler(context=context))
        self.records = []
        self.started = time.monotonic()

    def request(self, url=None, context=None, *, headers=None, method=None, body=None, external=False, safe_post=False, host_override=None):
        if len(self.records) >= self.max_requests or time.monotonic() - self.started > 160:
            raise ValidationError("Execution request/time budget exhausted")
        context = dict(context or {})
        url = urljoin(self.base, url or context.get("url") or self.base)
        if not external and origin(url) != self.target_origin:
            raise ValidationError("Requests must stay on the selected origin")
        origin(url)
        method = str(method or context.get("method", "GET")).upper()
        if method not in {"GET", "HEAD", "OPTIONS", "TRACE", "POST", "PUT", "PATCH", "DELETE"}:
            raise ValidationError("Unsupported HTTP method")
        if method not in {"GET", "HEAD", "OPTIONS", "TRACE"} and not self.config.get("allow_state_change") and not safe_post:
            raise ValidationError("Enable state-changing requests explicitly for this context")
        selected_headers = {str(key): str(value) for key, value in (headers if headers is not None else context.get("headers", {})).items()}
        for key, value in selected_headers.items():
            if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key) or "\r" in value or "\n" in value:
                raise ValidationError("Invalid request header")
        selected_headers = {key: value for key, value in selected_headers.items() if key.lower() not in {"content-length", "transfer-encoding", "connection", "host"}}
        # Host mutations are created by the dedicated profile, not copied from a capture.
        if host_override:
            if not re.fullmatch(r"[A-Za-z0-9.-]+(?::[0-9]+)?", host_override):
                raise ValidationError("Invalid dedicated Host override")
            selected_headers["Host"] = host_override
        body = context.get("body") if body is None else body
        if isinstance(body, (dict, list)):
            body = json.dumps(body)
            if not any(key.lower() == 'content-type' for key in selected_headers):
                selected_headers["Content-Type"] = "application/json"
        data = body.encode() if isinstance(body, str) else body
        if data is not None and (not isinstance(data, bytes) or len(data) > 65536):
            raise ValidationError("Request body must be text/JSON at most 64 KiB")
        if self.records and self.delay:
            time.sleep(self.delay)
        record = {"id": f"request-{len(self.records) + 1}", "method": method, "url": safe_url(url), "request_header_names": sorted(selected_headers), "request_body_sha256": hashlib.sha256(data or b"").hexdigest()}
        self.records.append(record)
        begin = time.monotonic()
        try:
            try:
                response = self.opener.open(Request(url, data=data, headers=selected_headers, method=method), timeout=self.timeout)
            except HTTPError as error:
                response = error
            with response:
                raw = response.read(self.max_bytes + 1)
                truncated = len(raw) > self.max_bytes
                raw = raw[:self.max_bytes]
                record.update(status=response.code, elapsed_ms=round((time.monotonic() - begin) * 1000), response_bytes=len(raw), response_sha256=hashlib.sha256(raw).hexdigest(), response_header_names=sorted(set(response.headers.keys())), truncated=truncated)
                return Response(response.code, list(response.headers.items()), raw.decode("utf-8", errors="replace"), record["id"], truncated)
        except Exception:
            record["error"] = "HTTP transport failed"
            raise RuntimeError("HTTP transport failed; check target connectivity, TLS, and context") from None
