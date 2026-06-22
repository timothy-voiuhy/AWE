"""
HTTP/1.1 message parsing and serialisation.

Handles:
- Request-line / status-line parsing
- Header block parsing (multi-value, case-insensitive lookup)
- Body reading: Content-Length and chunked Transfer-Encoding  (async)
- Hop-by-hop header stripping (RFC 7230 §6.1)
- Response serialisation — always Content-Length, never chunked
"""
from __future__ import annotations

import asyncio

# RFC 7230 §6.1 — never forward these between proxy and client/server
_HOP_BY_HOP: frozenset[str] = frozenset({
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
})


# ── parsing ───────────────────────────────────────────────────────────────────

def parse_header_block(raw: bytes) -> tuple[str, list[tuple[str, str]]]:
    text  = raw.rstrip(b"\r\n").decode("iso-8859-1", errors="replace")
    lines = text.split("\r\n")
    first_line = lines[0]
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if not line:
            continue
        sep = line.find(":")
        if sep == -1:
            continue
        headers.append((line[:sep].strip(), line[sep + 1:].strip()))
    return first_line, headers


def header_map(headers: list[tuple[str, str]]) -> dict[str, str]:
    return {k.lower(): v for k, v in headers}


# ── async I/O ─────────────────────────────────────────────────────────────────

async def read_request(
    reader: asyncio.StreamReader,
) -> tuple[str, str, str, list[tuple[str, str]], bytes]:
    """Read one complete HTTP/1.1 request from *reader*.

    Returns (method, target, http_version, headers, body).
    Raises ConnectionResetError on clean close, ValueError on parse error.
    """
    try:
        raw = await reader.readuntil(b"\r\n\r\n")
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError):
        raise ConnectionResetError("Connection closed before headers complete")

    first_line, headers = parse_header_block(raw)
    parts = first_line.split(" ", 2)
    if len(parts) != 3:
        raise ValueError(f"Malformed request line: {first_line!r}")
    method, target, version = parts[0].upper(), parts[1], parts[2].strip()
    body = await _read_body(reader, header_map(headers))
    return method, target, version, headers, body


async def _read_body(reader: asyncio.StreamReader, hmap: dict[str, str]) -> bytes:
    te = hmap.get("transfer-encoding", "").lower()
    if te == "chunked":
        return await _read_chunked(reader)
    raw_cl = hmap.get("content-length", "").strip()
    if raw_cl:
        try:
            cl = int(raw_cl)
        except ValueError:
            return b""
        try:
            return await reader.readexactly(cl)
        except asyncio.IncompleteReadError:
            raise ConnectionResetError("Connection closed mid-body")
    return b""


async def _read_chunked(reader: asyncio.StreamReader) -> bytes:
    body = bytearray()
    while True:
        try:
            size_line = await reader.readuntil(b"\r\n")
        except asyncio.IncompleteReadError:
            break
        size_str = size_line.strip().split(b";")[0]
        try:
            size = int(size_str, 16)
        except ValueError:
            break
        if size == 0:
            try:
                await reader.readuntil(b"\r\n\r\n")   # optional trailers
            except asyncio.IncompleteReadError:
                pass
            break
        try:
            body.extend(await reader.readexactly(size))
            await reader.readexactly(2)               # CRLF after chunk
        except asyncio.IncompleteReadError:
            break
    return bytes(body)


# ── hop-by-hop stripping ──────────────────────────────────────────────────────

def strip_hop_by_hop(headers: list[tuple[str, str]]) -> list[tuple[str, str]]:
    hmap  = header_map(headers)
    extra: set[str] = {
        h.strip().lower()
        for h in hmap.get("connection", "").split(",")
        if h.strip()
    }
    remove = _HOP_BY_HOP | extra
    return [(k, v) for k, v in headers if k.lower() not in remove]


# ── serialisation ─────────────────────────────────────────────────────────────

def build_response(
    status_code: int,
    reason: str,
    headers: list[tuple[str, str]],
    body: bytes,
) -> bytes:
    clean = strip_hop_by_hop(headers)
    clean = [(k, v) for k, v in clean if k.lower() != "content-length"]
    clean.append(("Content-Length", str(len(body))))
    clean.append(("Connection", "keep-alive"))
    header_block = "".join(f"{k}: {v}\r\n" for k, v in clean)
    status_line  = f"HTTP/1.1 {status_code} {reason}\r\n"
    return (status_line + header_block + "\r\n").encode("iso-8859-1") + body


def build_request_bytes(
    method: str,
    path: str,
    headers: list[tuple[str, str]],
    body: bytes,
) -> bytes:
    clean        = strip_hop_by_hop(headers)
    header_block = "".join(f"{k}: {v}\r\n" for k, v in clean)
    return f"{method} {path} HTTP/1.1\r\n{header_block}\r\n".encode("iso-8859-1") + body


def is_keep_alive(headers: list[tuple[str, str]], version: str) -> bool:
    conn = header_map(headers).get("connection", "").lower()
    if version.endswith("1.1"):
        return conn != "close"
    return conn == "keep-alive"
