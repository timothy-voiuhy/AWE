"""
ProxyServer — async accept loop and lifecycle management.

Entry point
-----------
    python -m proxy.server -p 8080

On startup writes the control port to:

    <RUNDIR>/tmp/proxy_control.txt

The GUI reads that file to instantiate a ControlClient.

Design
------
asyncio.start_server() hands each accepted connection to
_handle_connection() as a coroutine.  No threads.  The event loop
multiplexes all connections, upstream requests (via httpx.AsyncClient),
and the control server concurrently on a single OS thread.

Each keep-alive HTTPS connection is a single coroutine that loops
read→forward→respond without blocking any other connection.  The old
ThreadPoolExecutor had a hard ceiling of 128 concurrent connections;
the async approach handles thousands with a tiny memory footprint.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from config.config import RUNDIR
from proxy._ca import CertificateAuthority
from proxy._control import ControlServer
from proxy._handler import ConnectionHandler
from proxy._intercept import InterceptGate
from proxy._rules import RulesEngine
from proxy._traffic import TrafficStore
from proxy._upstream import UpstreamClient
from proxy._ws_store import WSStore

log = logging.getLogger(__name__)

_CONTROL_PORT_FILE = Path(RUNDIR) / "tmp" / "proxy_control.txt"
_STREAM_LIMIT      = 256 * 1024   # per-connection read buffer — generous for HTTP headers


class ProxyServer:
    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
        upstream_proxy: str | None = None,
    ) -> None:
        self._host     = host
        self._port     = port
        self._ca        = CertificateAuthority()
        self._upstream  = UpstreamClient(upstream_proxy=upstream_proxy)
        self._traffic   = TrafficStore()
        self._ws_store  = WSStore()
        self._rules     = RulesEngine()
        self._intercept = InterceptGate()
        self._server: asyncio.Server | None     = None
        self._control: ControlServer | None     = None
        self._active   = 0
        self._tasks:   set[asyncio.Task]        = set()   # all live connection tasks

    # ── public API ─────────────────────────────────────────────────────────────

    async def start(self) -> None:
        """Start the proxy and block until stop() is called."""

        self._control = ControlServer(
            self._traffic,
            get_stats_fn=self._stats,
            stop_fn=self.stop,
            rules=self._rules,
            intercept=self._intercept,
        )
        await self._control.start()

        _CONTROL_PORT_FILE.parent.mkdir(parents=True, exist_ok=True)
        _CONTROL_PORT_FILE.write_text(str(self._control.port))

        self._server = await asyncio.start_server(
            self._handle_connection,
            self._host, self._port,
            limit=_STREAM_LIMIT,
        )

        log.info("Proxy listening on %s:%d", self._host, self._port)
        log.info("Control socket on port %d", self._control.port)

        async with self._server:
            await self._server.serve_forever()

        # Reached after stop() cancels serve_forever()
        await self._cleanup()

    async def stop(self) -> None:
        log.info("Proxy shutting down")
        if self._server is not None:
            self._server.close()      # wakes serve_forever()

    async def _cleanup(self) -> None:
        # Cancel every in-flight connection task and wait for it to finish
        if self._tasks:
            for task in list(self._tasks):
                task.cancel()
            await asyncio.gather(*self._tasks, return_exceptions=True)
            self._tasks.clear()

        if self._control:
            await self._control.shutdown()
        await self._upstream.aclose()
        self._traffic.shutdown()
        self._ws_store.shutdown()
        try:
            _CONTROL_PORT_FILE.unlink(missing_ok=True)
        except OSError:
            pass

    # ── connection handler ────────────────────────────────────────────────────

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)
        self._active += 1
        try:
            handler = ConnectionHandler(
                reader, writer, self._ca, self._upstream,
                self._traffic, self._ws_store,
                self._rules, self._intercept,
            )
            await handler.handle()
        except asyncio.CancelledError:
            pass   # clean shutdown — swallow so the task ends without noise
        finally:
            self._active -= 1
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    def _stats(self) -> dict:
        return {"active_connections": self._active}


# ── __main__ entry point ───────────────────────────────────────────────────────

def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    if not verbose:
        for name in ("httpx", "httpcore", "urllib3", "hpack"):
            logging.getLogger(name).setLevel(logging.ERROR)


async def _run(args: argparse.Namespace) -> None:
    proxy = ProxyServer(host=args.host, port=args.port,
                        upstream_proxy=args.upstream_proxy)
    try:
        await proxy.start()
    except (KeyboardInterrupt, asyncio.CancelledError):
        await proxy.stop()
        await proxy._cleanup()


def main() -> None:
    parser = argparse.ArgumentParser(description="AWE MITM Proxy")
    parser.add_argument("-p", "--port",         type=int, default=8080)
    parser.add_argument("--host",               default="127.0.0.1")
    parser.add_argument("--upstream-proxy",     default=None,
                        help="Upstream proxy URL, e.g. http://127.0.0.1:9050")
    parser.add_argument("-v", "--verbose",      action="store_true")
    args = parser.parse_args()

    _setup_logging(args.verbose)

    try:
        asyncio.run(_run(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
