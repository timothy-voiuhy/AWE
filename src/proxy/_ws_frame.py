"""
RFC 6455 WebSocket frame codec.

read_frame()   — async, reads exactly one frame from asyncio.StreamReader.
encode_frame() — sync, serialises a frame back to wire bytes.
payload_text() — returns a human-readable string for display / storage.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timezone

OPCODE_NAMES: dict[int, str] = {
    0x0: "continuation",
    0x1: "text",
    0x2: "binary",
    0x8: "close",
    0x9: "ping",
    0xA: "pong",
}

_MAX_PAYLOAD_LOG = 65_536   # bytes kept in MongoDB; larger payloads are truncated


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class WSFrame:
    direction: str          # "↑" client→server | "↓" server→client
    opcode:    int
    payload:   bytes
    timestamp: str = field(default_factory=_now)

    def opcode_name(self) -> str:
        return OPCODE_NAMES.get(self.opcode, f"0x{self.opcode:X}")


async def read_frame(reader, masked_in: bool) -> WSFrame:
    """
    Read exactly one RFC 6455 frame from *reader*.
    *masked_in* must be True for client→server frames (browsers always mask).
    Raises asyncio.IncompleteReadError on clean EOF.
    """
    header = await reader.readexactly(2)

    opcode  = header[0] & 0x0F
    masked  = bool(header[1] & 0x80)
    raw_len = header[1] & 0x7F

    if raw_len == 126:
        ext = await reader.readexactly(2)
        payload_len = int.from_bytes(ext, "big")
    elif raw_len == 127:
        ext = await reader.readexactly(8)
        payload_len = int.from_bytes(ext, "big")
    else:
        payload_len = raw_len

    mask_key = b""
    if masked:
        mask_key = await reader.readexactly(4)

    payload = await reader.readexactly(payload_len)
    if masked:
        payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))

    return WSFrame(direction="?", opcode=opcode, payload=payload)


def encode_frame(opcode: int, payload: bytes, mask: bool = False) -> bytes:
    """Serialise a single RFC 6455 frame (FIN=1, RSV=0)."""
    length = len(payload)
    header = bytearray()

    header.append(0x80 | (opcode & 0x0F))          # FIN=1

    mask_bit = 0x80 if mask else 0x00
    if length <= 125:
        header.append(mask_bit | length)
    elif length <= 0xFFFF:
        header.append(mask_bit | 126)
        header += length.to_bytes(2, "big")
    else:
        header.append(mask_bit | 127)
        header += length.to_bytes(8, "big")

    if mask:
        mask_key = os.urandom(4)
        header += mask_key
        payload  = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))

    return bytes(header) + payload


def payload_text(frame: WSFrame) -> str:
    """Human-readable payload string for display / MongoDB storage."""
    if frame.opcode == 0x1:                         # text
        try:
            return frame.payload.decode("utf-8")
        except UnicodeDecodeError:
            return frame.payload.decode("utf-8", errors="replace")
    elif frame.opcode in (0x2, 0x8):                # binary / close
        data   = frame.payload[:_MAX_PAYLOAD_LOG]
        suffix = "…" if len(frame.payload) > _MAX_PAYLOAD_LOG else ""
        return data.hex() + suffix
    elif frame.opcode == 0x9:
        body = frame.payload.decode("utf-8", errors="replace")
        return f"[ping] {body}" if body else "[ping]"
    elif frame.opcode == 0xA:
        body = frame.payload.decode("utf-8", errors="replace")
        return f"[pong] {body}" if body else "[pong]"
    elif frame.opcode == 0x0:
        return f"[continuation] {len(frame.payload)} bytes"
    return f"[0x{frame.opcode:X}] {len(frame.payload)} bytes"
