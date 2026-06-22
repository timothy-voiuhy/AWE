from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class ProxyRequest:
    method: str
    url: str
    headers: list[tuple[str, str]]
    body: bytes
    host: str
    port: int
    scheme: str  # "http" | "https"


@dataclass
class ProxyResponse:
    status_code: int
    reason: str
    http_version: str
    # Ordered list — preserves multiple Set-Cookie and other multi-value headers.
    headers: list[tuple[str, str]]
    body: bytes
