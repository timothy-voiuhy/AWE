"""
Scoped traffic capture — MongoDB backend.

Thread-safe.  When enabled and the hostname matches at least one scope
pattern, queues each request/response pair for insertion into:

    MongoDB: awe_proxy_traffic.traffic

Documents have the shape:
    {host, path, method, status_code, timestamp,
     request:  {method, url, headers, body},
     response: {status_code, reason, http_version, headers, body}}

A daemon writer thread drains the queue so capture() never blocks the
asyncio event loop.
"""
from __future__ import annotations

import base64
import logging
import queue
import re
import threading
from datetime import datetime, timezone
from urllib.parse import urlsplit

from proxy._models import ProxyResponse

log = logging.getLogger(__name__)

_SENTINEL = None   # queued to stop the writer thread


class TrafficStore:
    def __init__(self) -> None:
        self._enabled: bool = True
        self._scope: list[re.Pattern[str]] = [re.compile(".")]
        self._lock = threading.Lock()
        self._queue: queue.Queue = queue.Queue(maxsize=20_000)
        self._writer = threading.Thread(target=self._writer_loop, daemon=True,
                                        name="traffic-writer")
        self._writer.start()

    # ── control ───────────────────────────────────────────────────────────────

    def set_enabled(self, enabled: bool) -> None:
        with self._lock:
            self._enabled = enabled

    def set_scope(self, patterns: list[str]) -> None:
        compiled = [re.compile(p) for p in patterns]
        with self._lock:
            self._scope = compiled

    @property
    def enabled(self) -> bool:
        with self._lock:
            return self._enabled

    def shutdown(self) -> None:
        """Flush remaining items and stop the writer thread."""
        self._queue.put(_SENTINEL)
        self._writer.join(timeout=5)

    # ── capture ───────────────────────────────────────────────────────────────

    def capture(
        self,
        host: str,
        method: str,
        url: str,
        req_headers: list[tuple[str, str]],
        req_body: bytes,
        response: ProxyResponse,
    ) -> None:
        with self._lock:
            if not self._enabled:
                return
            if not any(p.search(host) for p in self._scope):
                return

        parsed = urlsplit(url)
        entry = {
            "host":        host,
            "path":        parsed.path or "/",
            "method":      method.upper(),
            "status_code": response.status_code,
            "timestamp":   datetime.now(timezone.utc).isoformat(),
            "request": {
                "method":        method,
                "url":           url,
                "headers":       _headers_to_dict(req_headers),
                "body":          _body_str(req_body),
                "body_encoding": _body_enc(req_body),
            },
            "response": {
                "status_code":   response.status_code,
                "reason":        response.reason,
                "http_version":  response.http_version,
                "headers":       _headers_to_dict(response.headers),
                "body":          _body_str(response.body),
                "body_encoding": _body_enc(response.body),
            },
        }

        try:
            self._queue.put_nowait(entry)
        except queue.Full:
            log.warning("traffic queue full — dropping %s %s", method, url)

    # ── writer thread ─────────────────────────────────────────────────────────

    def _writer_loop(self) -> None:
        col = None
        while True:
            entry = self._queue.get()
            if entry is _SENTINEL:
                break
            if col is None:
                try:
                    from database.mongo import get_proxy_traffic_db
                    col = get_proxy_traffic_db().traffic
                except Exception:
                    log.exception("Cannot connect to MongoDB for traffic capture")
                    continue
            try:
                col.insert_one(entry)
            except Exception:
                log.exception("MongoDB traffic insert failed")


# ── helpers ───────────────────────────────────────────────────────────────────

def _body_enc(raw: bytes) -> str:
    try:
        raw.decode("utf-8")
        return "utf-8"
    except UnicodeDecodeError:
        return "base64"


def _body_str(raw: bytes) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return base64.b64encode(raw).decode()


def _headers_to_dict(headers: list[tuple[str, str]]) -> dict[str, str | list[str]]:
    out: dict[str, list[str]] = {}
    for k, v in headers:
        out.setdefault(k, []).append(v)
    return {k: v[0] if len(v) == 1 else v for k, v in out.items()}
