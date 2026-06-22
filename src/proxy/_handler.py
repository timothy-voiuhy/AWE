"""
Per-connection handler — async.

Routing
-------
1. Read the opening header block from the browser.
2. CONNECT → TLS MITM:
   a. Send 200 Connection Established.
   b. Upgrade the transport to server-side TLS in-place via loop.start_tls().
   c. Loop: read decrypted requests, forward upstream, write responses.
   d. WebSocket Upgrade header → switch to async bidirectional tunnel.
3. Plain HTTP → forward, respond, loop on keep-alive.

The TLS upgrade uses asyncio.get_running_loop().start_tls() with
server_side=True.  This replaces the transport underneath the existing
StreamReader/StreamReaderProtocol without creating a new reader object,
so buffered data is never lost.  A new StreamWriter is built on top of the
upgraded TLS transport.
"""
from __future__ import annotations

import asyncio
import logging
import ssl

from proxy._ca import CertificateAuthority
from proxy._http import (
    build_request_bytes,
    build_response,
    header_map,
    is_keep_alive,
    parse_header_block,
    read_request,
)
from proxy._traffic import TrafficStore
from proxy._upstream import UpstreamClient

log = logging.getLogger(__name__)

_CONNECT_OK   = b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: AWEProxy/1.0\r\n\r\n"
_CONNECT_FAIL = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"


class ConnectionHandler:
    __slots__ = ("_reader", "_writer", "_ca", "_upstream", "_traffic")

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        ca: CertificateAuthority,
        upstream: UpstreamClient,
        traffic: TrafficStore,
    ) -> None:
        self._reader   = reader
        self._writer   = writer
        self._ca       = ca
        self._upstream = upstream
        self._traffic  = traffic

    # ── entry point ───────────────────────────────────────────────────────────

    async def handle(self) -> None:
        try:
            await self._dispatch()
        except (ConnectionResetError, asyncio.IncompleteReadError,
                TimeoutError, ConnectionAbortedError, BrokenPipeError):
            pass
        except ssl.SSLError as exc:
            log.debug("SSL error from %s: %s", self._peer(), exc)
        except Exception:
            log.exception("Unhandled error from %s", self._peer())
        finally:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass

    def _peer(self) -> str:
        try:
            return str(self._writer.get_extra_info("peername"))
        except Exception:
            return "?"

    # ── dispatch ──────────────────────────────────────────────────────────────

    async def _dispatch(self) -> None:
        try:
            raw = await self._reader.readuntil(b"\r\n\r\n")
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            return
        first_line, headers = parse_header_block(raw)
        parts = first_line.split(" ", 2)
        if len(parts) != 3:
            log.debug("Malformed first line from %s: %r", self._peer(), first_line[:120])
            return
        method, target, version = parts[0].upper(), parts[1], parts[2].strip()

        if method == "CONNECT":
            await self._handle_connect(target)
        else:
            from proxy._http import _read_body
            body = await _read_body(self._reader, header_map(headers))
            await self._handle_plain_http(method, target, version, headers, body)

    # ── CONNECT / TLS MITM ────────────────────────────────────────────────────

    async def _handle_connect(self, target: str) -> None:
        host, _, port_str = target.rpartition(":")
        if not host or not port_str.isdigit():
            self._writer.write(_CONNECT_FAIL)
            await self._writer.drain()
            return
        port = int(port_str)

        self._writer.write(_CONNECT_OK)
        await self._writer.drain()

        ssl_ctx  = self._ca.ssl_context_for(host)
        loop     = asyncio.get_running_loop()
        transport = self._writer.transport
        protocol  = transport.get_protocol()

        try:
            tls_transport = await loop.start_tls(
                transport, protocol, ssl_ctx, server_side=True,
            )
        except (ssl.SSLError, OSError) as exc:
            log.debug("TLS handshake failed for %s: %s", host, exc)
            return

        # loop.start_tls() doesn't set _over_ssl on the StreamReaderProtocol,
        # so eof_received() would return True and trigger a spurious asyncio
        # warning "returning true from eof_received() has no effect when using ssl".
        if hasattr(protocol, "_over_ssl"):
            protocol._over_ssl = True

        # Build a new writer on the TLS transport; reader is unchanged
        # (it's backed by StreamReaderProtocol which loop.start_tls() updated in-place)
        tls_writer = asyncio.StreamWriter(tls_transport, protocol, self._reader, loop)
        await self._serve_tunnel(self._reader, tls_writer, host, port)

    async def _serve_tunnel(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        host: str,
        port: int,
    ) -> None:
        while True:
            try:
                method, target, version, headers, body = await read_request(reader)
            except (ConnectionResetError, asyncio.IncompleteReadError,
                    TimeoutError, asyncio.LimitOverrunError):
                break
            except ValueError as exc:
                log.debug("Parse error in tunnel for %s: %s", host, exc)
                break

            hmap = header_map(headers)
            if hmap.get("upgrade", "").lower() == "websocket":
                await self._handle_websocket(
                    reader, writer, host, port, target, headers, body,
                )
                break

            url      = _build_url("https", host, port, target)
            response = await self._upstream.request(method, url, headers, body)
            self._traffic.capture(host, method, url, headers, body, response)

            try:
                writer.write(build_response(
                    response.status_code, response.reason,
                    response.headers, response.body,
                ))
                await writer.drain()
            except OSError:
                break

            if not is_keep_alive(headers, version):
                break

    # ── plain HTTP ────────────────────────────────────────────────────────────

    async def _handle_plain_http(
        self,
        method: str,
        target: str,
        version: str,
        headers: list[tuple[str, str]],
        body: bytes,
    ) -> None:
        while True:
            hmap = header_map(headers)
            host = hmap.get("host", "")
            url  = target if "://" in target else f"http://{host}{target}"

            response = await self._upstream.request(method, url, headers, body)
            self._traffic.capture(host, method, url, headers, body, response)

            try:
                self._writer.write(build_response(
                    response.status_code, response.reason,
                    response.headers, response.body,
                ))
                await self._writer.drain()
            except OSError:
                break

            if not is_keep_alive(headers, version):
                break

            try:
                method, target, version, headers, body = await read_request(self._reader)
            except (ConnectionResetError, asyncio.IncompleteReadError,
                    TimeoutError, asyncio.LimitOverrunError):
                break

    # ── WebSocket passthrough ─────────────────────────────────────────────────

    async def _handle_websocket(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        host: str,
        port: int,
        path: str,
        headers: list[tuple[str, str]],
        body: bytes,
    ) -> None:
        log.debug("WebSocket passthrough: %s:%d%s", host, port, path)
        up_ctx = ssl.create_default_context()
        up_ctx.check_hostname = False
        up_ctx.verify_mode    = ssl.CERT_NONE
        try:
            up_reader, up_writer = await asyncio.open_connection(
                host, port, ssl=up_ctx,
            )
        except OSError as exc:
            log.warning("WebSocket upstream connect failed %s:%d: %s", host, port, exc)
            return

        upgrade_bytes = build_request_bytes("GET", path, headers, body)
        try:
            up_writer.write(upgrade_bytes)
            await up_writer.drain()
            resp_raw = await up_reader.readuntil(b"\r\n\r\n")
            client_writer.write(resp_raw)
            await client_writer.drain()
        except OSError as exc:
            log.warning("WebSocket handshake relay error: %s", exc)
            up_writer.close()
            return

        await _bidirectional_tunnel(client_reader, client_writer, up_reader, up_writer)


# ── helpers ───────────────────────────────────────────────────────────────────

def _build_url(scheme: str, host: str, port: int, path: str) -> str:
    default = {"http": 80, "https": 443}
    if port == default.get(scheme):
        return f"{scheme}://{host}{path}"
    return f"{scheme}://{host}:{port}{path}"


async def _pipe(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except OSError:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def _bidirectional_tunnel(
    r1: asyncio.StreamReader, w1: asyncio.StreamWriter,
    r2: asyncio.StreamReader, w2: asyncio.StreamWriter,
) -> None:
    await asyncio.gather(_pipe(r1, w2), _pipe(r2, w1), return_exceptions=True)
