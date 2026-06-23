"""
Intercept gate — pauses HTTP requests mid-flight so the GUI can inspect
and optionally modify them before forwarding upstream.

Architecture
────────────
Everything runs inside the asyncio event loop (same thread as the proxy).
Each intercepted request creates an asyncio.Future.  The handler awaits
the future; the ControlServer resolves it when the GUI sends a decision.

Thread-safety note: `set_enabled` / `set_scope` can be called from any
thread (ControlServer dispatches on the event loop, but set_enabled is
also called at startup from the main thread before the loop starts).
We guard the flag and scope list with a plain threading.Lock.

The _pending / _pending_requests dicts are ONLY touched from within the
asyncio event loop, so they need no locking.
"""
from __future__ import annotations

import asyncio
import base64
import logging
import re
import threading
import uuid

log = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 300.0   # 5 minutes — auto-forward if GUI takes too long


class InterceptGate:
    def __init__(self) -> None:
        self._enabled: bool = False
        self._patterns: list[re.Pattern] = []   # empty = intercept ALL hosts
        self._lock = threading.Lock()

        # Only accessed from asyncio loop — no lock needed
        self._pending:          dict[str, asyncio.Future] = {}
        self._pending_requests: dict[str, dict]           = {}

    # ── control (may be called from any thread) ───────────────────────────────

    def set_enabled(self, enabled: bool, patterns: list[str] = ()) -> None:
        compiled = []
        for p in patterns:
            try:
                compiled.append(re.compile(p, re.IGNORECASE))
            except re.error as exc:
                log.warning("InterceptGate: bad pattern %r — %s", p, exc)
        with self._lock:
            self._enabled  = enabled
            self._patterns = compiled

    def is_enabled(self) -> bool:
        with self._lock:
            return self._enabled

    # ── asyncio API (called from handler coroutines) ──────────────────────────

    async def maybe_intercept(
        self,
        host:    str,
        method:  str,
        url:     str,
        headers: list[tuple[str, str]],
        body:    bytes,
    ) -> dict:
        """
        Returns a decision dict:
          {"action": "forward", "headers": [...], "body": b"..."}
          {"action": "drop"}

        If intercept is disabled or host is out of scope the function
        returns immediately without blocking.
        """
        with self._lock:
            enabled  = self._enabled
            patterns = list(self._patterns)

        if not enabled:
            return _passthrough(headers, body)

        if patterns and not any(p.search(host) for p in patterns):
            return _passthrough(headers, body)

        req_id = uuid.uuid4().hex[:8]
        loop   = asyncio.get_running_loop()
        fut    = loop.create_future()

        self._pending[req_id] = fut
        self._pending_requests[req_id] = {
            "id":      req_id,
            "host":    host,
            "method":  method,
            "url":     url,
            "headers": [[k, v] for k, v in headers],
            "body_b64": base64.b64encode(body).decode(),
        }
        log.debug("Intercept: pausing %s %s [%s]", method, url, req_id)

        try:
            decision = await asyncio.wait_for(fut, timeout=_DEFAULT_TIMEOUT)
            return decision
        except asyncio.TimeoutError:
            log.debug("Intercept: timeout on %s — auto-forwarding", req_id)
            return _passthrough(headers, body)
        finally:
            self._pending.pop(req_id, None)
            self._pending_requests.pop(req_id, None)

    def resolve(self, req_id: str, decision: dict) -> None:
        """
        Called from ControlServer (asyncio context) to release a paused handler.
        decision must have {"action": "forward"|"drop", ...}.
        """
        fut = self._pending.get(req_id)
        if fut is None:
            log.warning("InterceptGate.resolve: unknown req_id %r", req_id)
            return
        if not fut.done():
            fut.set_result(decision)

    def list_pending(self) -> list[dict]:
        """Snapshot of requests currently waiting for a decision."""
        return list(self._pending_requests.values())


# ── helpers ───────────────────────────────────────────────────────────────────

def _passthrough(headers, body: bytes) -> dict:
    return {
        "action":  "forward",
        "headers": headers,
        "body_b64": base64.b64encode(body).decode(),
    }


def decision_headers(decision: dict) -> list[tuple[str, str]]:
    """Extract headers from a resolved decision (list of [k,v] pairs)."""
    raw = decision.get("headers", [])
    if not raw:
        return []
    if isinstance(raw[0], (list, tuple)):
        return [(k, v) for k, v in raw]
    return raw


def decision_body(decision: dict, fallback: bytes = b"") -> bytes:
    """Extract body bytes from a resolved decision."""
    b64 = decision.get("body_b64")
    if b64 is not None:
        try:
            return base64.b64decode(b64)
        except Exception:
            pass
    return fallback
