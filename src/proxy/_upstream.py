"""
Upstream HTTP(S) client — async, shared httpx.AsyncClient connection pool.

Key decisions
-------------
* follow_redirects=False — the browser handles redirects.
* verify=False           — we MITM TLS; upstream certs look wrong to us.
* content-encoding strip — httpx auto-decompresses r.content but leaves the
  Content-Encoding header intact; forwarding it would cause "Content Encoding
  Error" in the browser, so we drop it here.
"""
from __future__ import annotations

import html
import logging
import socket
from urllib.parse import urlsplit

import httpx

from proxy._http import strip_hop_by_hop
from proxy._models import ProxyResponse


def _build_accept_encoding() -> str:
    """Encodings httpx can decode with currently-installed packages."""
    parts = ["gzip", "deflate", "identity"]
    try:
        import brotli  # noqa: F401
        parts.insert(0, "br")
    except ImportError:
        pass
    try:
        import zstandard  # noqa: F401
        parts.insert(0, "zstd")
    except ImportError:
        pass
    return ", ".join(parts)


_ACCEPT_ENCODING = _build_accept_encoding()

log = logging.getLogger(__name__)


class UpstreamClient:
    def __init__(
        self,
        *,
        verify: bool = False,
        connect_timeout: float = 10.0,
        read_timeout: float = 30.0,
        upstream_proxy: str | None = None,
    ) -> None:
        self._client = httpx.AsyncClient(
            verify=verify,
            proxy=upstream_proxy or None,
            follow_redirects=False,
            timeout=httpx.Timeout(
                connect=connect_timeout,
                read=read_timeout,
                write=10.0,
                pool=5.0,
            ),
            limits=httpx.Limits(
                max_connections=256,
                max_keepalive_connections=64,
                keepalive_expiry=30.0,
            ),
        )

    def _clean_headers(self, headers: list[tuple[str, str]]) -> list[tuple[str, str]]:
        clean = strip_hop_by_hop(headers)
        clean = [(k, v) for k, v in clean if k.lower() != "accept-encoding"]
        clean.append(("Accept-Encoding", _ACCEPT_ENCODING))
        return clean

    async def request(
        self,
        method: str,
        url: str,
        headers: list[tuple[str, str]],
        body: bytes,
    ) -> ProxyResponse:
        clean = self._clean_headers(headers)
        try:
            r = await self._client.request(method, url, headers=clean, content=body)
        except httpx.TimeoutException as exc:
            log.warning("Upstream timeout: %s %s — %s", method, url, exc)
            return _timeout_error_response(_host_from_url(url), str(exc))
        except httpx.ConnectError as exc:
            log.warning("Upstream connect error: %s %s — %s", method, url, exc)
            host = _host_from_url(url)
            if _is_dns_error(exc):
                return _dns_error_response(host, str(exc))
            return _connect_error_response(host, str(exc))
        except Exception as exc:
            log.exception("Upstream unexpected error: %s %s", method, url)
            return _error_response(502, "Bad Gateway", _host_from_url(url), str(exc))

        resp_headers = [
            (k, v) for k, v in r.headers.multi_items()
            if k.lower() != "content-encoding"
        ]
        return ProxyResponse(
            status_code=r.status_code,
            reason=r.reason_phrase or "",
            http_version=r.http_version,
            headers=resp_headers,
            body=r.content,
        )

    async def stream_sse(
        self,
        method: str,
        url: str,
        headers: list[tuple[str, str]],
        body: bytes,
        writer: "asyncio.StreamWriter",
    ) -> tuple[bool, ProxyResponse]:
        """
        Stream an SSE (text/event-stream) response directly to *writer*.

        Returns (wrote_to_client, ProxyResponse).
        - wrote_to_client=True  → headers + body already sent; caller must NOT
                                   call build_response / writer.write again.
        - wrote_to_client=False → upstream failed before anything was sent;
                                   caller should write the returned error response.
        """
        import asyncio
        # Force identity encoding — compressed SSE would be garbled on the wire
        clean = strip_hop_by_hop(headers)
        clean = [(k, v) for k, v in clean if k.lower() != "accept-encoding"]
        clean.append(("Accept-Encoding", "identity"))

        try:
            async with self._client.stream(method, url, headers=clean, content=body) as r:
                resp_headers = [
                    (k, v) for k, v in r.headers.multi_items()
                    if k.lower() not in (
                        "content-encoding", "content-length", "transfer-encoding"
                    )
                ]
                # Write status line + headers — no Content-Length (stream is open-ended)
                hblock = "".join(f"{k}: {v}\r\n" for k, v in resp_headers)
                writer.write(
                    f"HTTP/1.1 {r.status_code} {r.reason_phrase or ''}\r\n"
                    f"{hblock}\r\n".encode("iso-8859-1")
                )
                await writer.drain()

                async for chunk in r.aiter_bytes():
                    if not chunk:
                        continue
                    try:
                        writer.write(chunk)
                        await writer.drain()
                    except OSError:
                        break   # client disconnected mid-stream

                capture_resp = ProxyResponse(
                    status_code=r.status_code,
                    reason=r.reason_phrase or "",
                    http_version=r.http_version,
                    headers=resp_headers,
                    body=b"[SSE stream]",
                )
                return True, capture_resp

        except httpx.TimeoutException as exc:
            log.warning("SSE upstream timeout: %s %s — %s", method, url, exc)
            return False, _timeout_error_response(_host_from_url(url), str(exc))
        except httpx.ConnectError as exc:
            log.warning("SSE upstream connect error: %s %s — %s", method, url, exc)
            host = _host_from_url(url)
            if _is_dns_error(exc):
                return False, _dns_error_response(host, str(exc))
            return False, _connect_error_response(host, str(exc))
        except (OSError, asyncio.CancelledError):
            return True, ProxyResponse(0, "", "HTTP/1.1", [], b"")  # client closed first
        except Exception as exc:
            log.exception("SSE upstream unexpected error: %s %s", method, url)
            return False, _error_response(502, "Bad Gateway", _host_from_url(url), str(exc))

    async def aclose(self) -> None:
        try:
            await self._client.aclose()
        except Exception:
            pass


def _host_from_url(url: str) -> str:
    try:
        return urlsplit(url).hostname or url
    except Exception:
        return url


def _is_dns_error(exc: BaseException) -> bool:
    """Walk the exception chain looking for the underlying DNS lookup failure."""
    seen: set[int] = set()
    cur: BaseException | None = exc
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        if isinstance(cur, socket.gaierror):
            return True
        cur = cur.__cause__ or cur.__context__
    return False


# ── branded error pages ───────────────────────────────────────────────────────
# Catppuccin Mocha palette (kept literal here so `proxy` doesn't import `gui`).

_ERROR_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{status} {reason} — AWE Proxy</title>
<style>
  :root {{ color-scheme: dark; }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; min-height: 100vh; display: flex; align-items: center;
    justify-content: center; background: #11111B; color: #CDD6F4;
    font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    padding: 24px;
  }}
  .card {{
    width: 100%; max-width: 560px; background: #1E1E2E;
    border: 1px solid #313244; border-radius: 12px; padding: 32px 36px;
    box-shadow: 0 20px 60px rgba(0,0,0,0.45);
  }}
  .brand {{
    display: flex; align-items: center; gap: 8px; font-size: 12px;
    letter-spacing: 0.08em; text-transform: uppercase; color: #7F849C;
    margin-bottom: 20px;
  }}
  .brand .dot {{ width: 8px; height: 8px; border-radius: 50%; background: {accent}; }}
  .icon {{ font-size: 40px; margin-bottom: 12px; }}
  h1 {{ font-size: 20px; margin: 0 0 6px; color: #CDD6F4; }}
  .sub {{ font-size: 14px; color: #9399B2; margin: 0 0 20px; line-height: 1.5; }}
  .field {{
    background: #181825; border: 1px solid #313244; border-radius: 8px;
    padding: 12px 14px; margin-bottom: 12px;
  }}
  .field .label {{
    font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em;
    color: #6C7086; margin-bottom: 4px;
  }}
  .field .value {{
    font-size: 13px; font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
    color: #CDD6F4; word-break: break-all;
  }}
  .hint {{
    font-size: 13px; color: #9399B2; line-height: 1.6; margin-top: 20px;
    padding-top: 16px; border-top: 1px solid #313244;
  }}
  .hint ul {{ margin: 6px 0 0; padding-left: 18px; }}
  .status {{
    display: inline-block; font-size: 12px; font-weight: 600; color: {accent};
    background: {accent}22; border: 1px solid {accent}55; border-radius: 999px;
    padding: 3px 10px; margin-bottom: 16px;
  }}
</style>
</head>
<body>
  <div class="card">
    <div class="brand"><span class="dot"></span>AWE Proxy</div>
    <div class="status">{status} {reason}</div>
    <div class="icon">{icon}</div>
    <h1>{title}</h1>
    <p class="sub">{message}</p>
    <div class="field">
      <div class="label">Requested host</div>
      <div class="value">{host}</div>
    </div>
    <div class="field">
      <div class="label">Details</div>
      <div class="value">{detail}</div>
    </div>
    {hint_block}
  </div>
</body>
</html>
"""


def _render_error_page(
    *, status: int, reason: str, icon: str, accent: str,
    title: str, message: str, host: str, detail: str, hints: list[str],
) -> bytes:
    hint_block = ""
    if hints:
        items = "".join(f"<li>{html.escape(h)}</li>" for h in hints)
        hint_block = f'<div class="hint">Suggestions<ul>{items}</ul></div>'
    return _ERROR_PAGE.format(
        status=status, reason=html.escape(reason), icon=icon,
        title=html.escape(title), message=html.escape(message),
        host=html.escape(host or "—"), detail=html.escape(detail or "—"),
        accent=accent, hint_block=hint_block,
    ).encode()


def _dns_error_response(host: str, detail: str) -> ProxyResponse:
    body = _render_error_page(
        status=502, reason="Bad Gateway", icon="🌐", accent="#F38BA8",
        title="DNS Resolution Failed",
        message="AWE Proxy could not resolve the hostname for this request.",
        host=host, detail=detail,
        hints=[
            "Check that the hostname is spelled correctly.",
            "Confirm the host is publicly resolvable, or add it to /etc/hosts if it's internal-only.",
            "Verify your machine's DNS settings and network connectivity.",
            "If a match/replace rule rewrote the Host header, check that rule.",
        ],
    )
    return ProxyResponse(
        status_code=502, reason="Bad Gateway", http_version="HTTP/1.1",
        headers=[("Content-Type", "text/html; charset=utf-8")], body=body,
    )


def _timeout_error_response(host: str, detail: str) -> ProxyResponse:
    body = _render_error_page(
        status=504, reason="Gateway Timeout", icon="⏱", accent="#FAB387",
        title="Upstream Timeout",
        message="AWE Proxy did not receive a response from the upstream host in time.",
        host=host, detail=detail,
        hints=[
            "The server may be slow, overloaded, or unreachable.",
            "Check your network connection and any firewall rules.",
            "Increase the proxy's read timeout in Settings if this host is expected to be slow.",
        ],
    )
    return ProxyResponse(
        status_code=504, reason="Gateway Timeout", http_version="HTTP/1.1",
        headers=[("Content-Type", "text/html; charset=utf-8")], body=body,
    )


def _connect_error_response(host: str, detail: str) -> ProxyResponse:
    body = _render_error_page(
        status=502, reason="Bad Gateway", icon="🔌", accent="#F38BA8",
        title="Connection Failed",
        message="AWE Proxy could not establish a connection to the upstream host.",
        host=host, detail=detail,
        hints=[
            "The host may be down or refusing connections.",
            "Check for firewall rules blocking outbound traffic.",
            "If this is an HTTPS target, confirm the port is correct.",
        ],
    )
    return ProxyResponse(
        status_code=502, reason="Bad Gateway", http_version="HTTP/1.1",
        headers=[("Content-Type", "text/html; charset=utf-8")], body=body,
    )


def _error_response(status: int, reason: str, host: str, detail: str) -> ProxyResponse:
    body = _render_error_page(
        status=status, reason=reason, icon="⚠", accent="#F9E2AF",
        title="Unexpected Proxy Error",
        message="AWE Proxy hit an unexpected error while handling this request.",
        host=host, detail=detail, hints=[],
    )
    return ProxyResponse(
        status_code=status, reason=reason, http_version="HTTP/1.1",
        headers=[("Content-Type", "text/html; charset=utf-8")], body=body,
    )
