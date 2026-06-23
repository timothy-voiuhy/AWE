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

import logging

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

    async def request(
        self,
        method: str,
        url: str,
        headers: list[tuple[str, str]],
        body: bytes,
    ) -> ProxyResponse:
        clean = strip_hop_by_hop(headers)
        # Replace the browser's Accept-Encoding with only what httpx can decode.
        # Forwarding encodings we can't decompress (e.g. br without brotli installed)
        # causes the proxy to send compressed bytes with no Content-Encoding header.
        clean = [(k, v) for k, v in clean if k.lower() != "accept-encoding"]
        clean.append(("Accept-Encoding", _ACCEPT_ENCODING))
        try:
            r = await self._client.request(method, url, headers=clean, content=body)
        except httpx.TimeoutException as exc:
            log.warning("Upstream timeout: %s %s — %s", method, url, exc)
            return _error_response(504, "Gateway Timeout", str(exc))
        except httpx.ConnectError as exc:
            log.warning("Upstream connect error: %s %s — %s", method, url, exc)
            return _error_response(502, "Bad Gateway", str(exc))
        except Exception as exc:
            log.exception("Upstream unexpected error: %s %s", method, url)
            return _error_response(502, "Bad Gateway", str(exc))

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

    async def aclose(self) -> None:
        try:
            await self._client.aclose()
        except Exception:
            pass


def _error_response(status: int, reason: str, detail: str) -> ProxyResponse:
    body = (
        f"<html><body><h1>{status} {reason}</h1>"
        f"<pre>{detail}</pre></body></html>"
    ).encode()
    return ProxyResponse(
        status_code=status,
        reason=reason,
        http_version="HTTP/1.1",
        headers=[("Content-Type", "text/html; charset=utf-8")],
        body=body,
    )
