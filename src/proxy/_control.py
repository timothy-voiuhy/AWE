"""
Control IPC — async JSON over TCP loopback.

ControlServer runs inside the proxy's asyncio event loop.
ControlClient is synchronous — used by the GUI process.

Protocol
--------
Request  : single JSON object followed by newline, sent by client.
Response : {"ok": true,  "result": ...}
         | {"ok": false, "error": "..."}

Commands
--------
{"action": "set_scope",   "patterns": ["regex", ...]}
{"action": "set_logging", "enabled": true|false}
{"action": "get_stats"}   → {"ok": true, "result": {"active_connections": N}}
{"action": "stop"}        → schedules proxy shutdown, returns {"ok": true}
"""
from __future__ import annotations

import asyncio
import json
import logging
import socket
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from proxy._traffic import TrafficStore

log = logging.getLogger(__name__)


class ControlServer:
    def __init__(
        self,
        traffic: "TrafficStore",
        get_stats_fn,       # () -> dict
        stop_fn,            # async () -> None
    ) -> None:
        self._traffic   = traffic
        self._get_stats = get_stats_fn
        self._stop      = stop_fn
        self._server: asyncio.Server | None = None

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_client, "127.0.0.1", 0,
        )

    @property
    def port(self) -> int:
        if self._server is None:
            raise RuntimeError("ControlServer not started")
        return self._server.sockets[0].getsockname()[1]

    async def shutdown(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    # ── private ───────────────────────────────────────────────────────────────

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            data = await asyncio.wait_for(reader.readuntil(b"\n"), timeout=5.0)
            cmd  = json.loads(data)
            result = await self._dispatch(cmd)
            writer.write(json.dumps({"ok": True, "result": result}).encode())
            await writer.drain()
        except json.JSONDecodeError as exc:
            try:
                writer.write(json.dumps({"ok": False, "error": f"JSON: {exc}"}).encode())
                await writer.drain()
            except OSError:
                pass
        except Exception as exc:
            log.exception("Control handler error")
            try:
                writer.write(json.dumps({"ok": False, "error": str(exc)}).encode())
                await writer.drain()
            except OSError:
                pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _dispatch(self, cmd: dict) -> object:
        action = cmd.get("action")
        if action == "set_scope":
            self._traffic.set_scope(cmd.get("patterns", ["."]))
            return None
        if action == "set_logging":
            self._traffic.set_enabled(bool(cmd.get("enabled", False)))
            return None
        if action == "get_stats":
            return self._get_stats()
        if action == "stop":
            asyncio.get_running_loop().create_task(self._stop())
            return None
        raise ValueError(f"Unknown action: {action!r}")


class ControlClient:
    """Synchronous client — used by the GUI (different process)."""

    def __init__(self, port: int) -> None:
        self._port = port

    def set_scope(self, patterns: list[str]) -> bool:
        return self._send({"action": "set_scope", "patterns": patterns})

    def set_logging(self, enabled: bool) -> bool:
        return self._send({"action": "set_logging", "enabled": enabled})

    def get_stats(self) -> dict:
        reply = self._rpc({"action": "get_stats"})
        return reply.get("result") or {}

    def stop(self) -> bool:
        return self._send({"action": "stop"})

    # ── private ───────────────────────────────────────────────────────────────

    def _send(self, cmd: dict) -> bool:
        return bool(self._rpc(cmd).get("ok"))

    def _rpc(self, cmd: dict) -> dict:
        try:
            with socket.create_connection(("127.0.0.1", self._port), timeout=5.0) as s:
                s.sendall((json.dumps(cmd) + "\n").encode())
                buf = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
            return json.loads(buf) if buf else {}
        except Exception:
            return {}
