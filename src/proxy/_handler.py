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
    build_ws_upgrade_bytes,
    header_map,
    is_keep_alive,
    parse_header_block,
    read_request,
)
from proxy._intercept import InterceptGate, decision_body, decision_headers
from proxy._models import ProxyResponse
from proxy._rules import RulesEngine
from proxy._traffic import TrafficStore
from proxy._upstream import UpstreamClient
from proxy._ws_frame import WSFrame, encode_frame, read_frame
from proxy._ws_store import WSStore

log = logging.getLogger(__name__)

_CONNECT_OK   = b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: AWEProxy/1.0\r\n\r\n"
_CONNECT_FAIL = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"


class ConnectionHandler:
    __slots__ = (
        "_reader", "_writer", "_ca", "_upstream",
        "_traffic", "_ws_store", "_rules", "_intercept",
    )

    def __init__(
        self,
        reader:    asyncio.StreamReader,
        writer:    asyncio.StreamWriter,
        ca:        CertificateAuthority,
        upstream:  UpstreamClient,
        traffic:   TrafficStore,
        ws_store:  WSStore | None       = None,
        rules:     RulesEngine | None   = None,
        intercept: InterceptGate | None = None,
    ) -> None:
        self._reader    = reader
        self._writer    = writer
        self._ca        = ca
        self._upstream  = upstream
        self._traffic   = traffic
        self._ws_store  = ws_store
        self._rules     = rules
        self._intercept = intercept

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

            url = _build_url("https", host, port, target)

            # Apply match-and-replace to the request
            if self._rules:
                method, url, headers, body = self._rules.apply_to_request(
                    method, url, headers, body,
                )

            # Intercept — may pause until user decides
            if self._intercept and self._intercept.is_enabled():
                decision = await self._intercept.maybe_intercept(
                    host, method, url, headers, body,
                )
                if decision.get("action") == "drop":
                    writer.write(build_response(
                        403, "Forbidden", [], b"[AWE] Dropped by intercept",
                    ))
                    await writer.drain()
                    break
                new_hdrs = decision_headers(decision)
                headers  = new_hdrs if new_hdrs else headers
                body     = decision_body(decision, body)

            response = await self._upstream.request(method, url, headers, body)

            # Apply match-and-replace to the response
            if self._rules:
                resp_headers, resp_body = self._rules.apply_to_response(
                    list(response.headers), response.body,
                )
                response = ProxyResponse(
                    response.status_code, response.reason,
                    response.http_version, resp_headers, resp_body,
                )

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

            # Apply match-and-replace to the request
            if self._rules:
                method, url, headers, body = self._rules.apply_to_request(
                    method, url, headers, body,
                )

            # Intercept — may pause until user decides
            if self._intercept and self._intercept.is_enabled():
                decision = await self._intercept.maybe_intercept(
                    host, method, url, headers, body,
                )
                if decision.get("action") == "drop":
                    self._writer.write(build_response(
                        403, "Forbidden", [], b"[AWE] Dropped by intercept",
                    ))
                    await self._writer.drain()
                    break
                new_hdrs = decision_headers(decision)
                headers  = new_hdrs if new_hdrs else headers
                body     = decision_body(decision, body)

            response = await self._upstream.request(method, url, headers, body)

            # Apply match-and-replace to the response
            if self._rules:
                resp_headers, resp_body = self._rules.apply_to_response(
                    list(response.headers), response.body,
                )
                response = ProxyResponse(
                    response.status_code, response.reason,
                    response.http_version, resp_headers, resp_body,
                )

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

    # ── WebSocket frame-aware relay ───────────────────────────────────────────

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
        log.debug("WebSocket intercept: %s:%d%s", host, port, path)
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

        upgrade_bytes = build_ws_upgrade_bytes(path, headers)
        try:
            up_writer.write(upgrade_bytes)
            await up_writer.drain()
            resp_raw = await up_reader.readuntil(b"\r\n\r\n")
            # Strip permessage-deflate from the 101 response so the client
            # also believes compression is disabled (matching what we sent upstream).
            resp_clean = _strip_ws_compression_from_response(resp_raw)
            client_writer.write(resp_clean)
            await client_writer.drain()
        except OSError as exc:
            log.warning("WebSocket handshake relay error: %s", exc)
            up_writer.close()
            return

        conn_id = ""
        if self._ws_store is not None:
            conn_id = self._ws_store.create_connection(host, path)

        try:
            await _ws_frame_relay(
                client_reader, client_writer,
                up_reader, up_writer,
                conn_id, self._ws_store,
            )
        finally:
            if self._ws_store is not None and conn_id:
                self._ws_store.close_connection(conn_id)
            try:
                up_writer.close()
            except Exception:
                pass


# ── helpers ───────────────────────────────────────────────────────────────────

def _strip_ws_compression_from_response(raw: bytes) -> bytes:
    """
    Remove any Sec-WebSocket-Extensions header from the server's 101 response
    before forwarding to the client.  This ensures both sides believe compression
    is disabled (matching the stripped upgrade we sent upstream).
    """
    try:
        text = raw.decode("iso-8859-1")
        lines = text.split("\r\n")
        filtered = [
            ln for ln in lines
            if not ln.lower().startswith("sec-websocket-extensions")
        ]
        return "\r\n".join(filtered).encode("iso-8859-1")
    except Exception:
        return raw


def _build_url(scheme: str, host: str, port: int, path: str) -> str:
    default = {"http": 80, "https": 443}
    if port == default.get(scheme):
        return f"{scheme}://{host}{path}"
    return f"{scheme}://{host}:{port}{path}"


async def _ws_frame_relay(
    c_reader: asyncio.StreamReader,
    c_writer: asyncio.StreamWriter,
    s_reader: asyncio.StreamReader,
    s_writer: asyncio.StreamWriter,
    conn_id: str,
    ws_store,
) -> None:
    """
    Bidirectional WS relay that decodes every frame for logging while
    forwarding it faithfully to the other side.

    Client→server frames arrive MASKED (RFC 6455 §5.3).  We unmask them
    for logging, then re-mask before forwarding — RFC 6455 §5.1 requires
    all client-to-server frames to be masked; servers MUST close on an
    unmasked client frame (close code 1002).

    Server→client frames arrive UNMASKED and are forwarded unmasked.
    """

    async def relay(
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        direction: str,
        masked_in: bool,
        mask_out: bool,
    ) -> None:
        try:
            while True:
                frame = await read_frame(reader, masked_in=masked_in)
                frame.direction = direction
                if ws_store is not None and conn_id:
                    ws_store.append_frame(conn_id, frame)
                writer.write(encode_frame(frame.opcode, frame.payload, mask=mask_out))
                await writer.drain()
                if frame.opcode == 0x8:   # close frame — both sides shut down
                    break
        except (asyncio.IncompleteReadError, asyncio.CancelledError,
                OSError, ConnectionResetError):
            pass

    await asyncio.gather(
        relay(c_reader, s_writer, "↑", masked_in=True,  mask_out=True),   # client→server: must re-mask
        relay(s_reader, c_writer, "↓", masked_in=False, mask_out=False),  # server→client: unmasked
        return_exceptions=True,
    )
