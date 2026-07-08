"""
Shared marker for traffic AWE generates about itself.

When the GraphQL workbench, WebSocket workbench, or any other AWE tool
sends test traffic through the proxy, it attaches this header so the
proxy can recognise "this request came from one of our own panels, not
a browser/client I'm passively observing".

The header is stripped before the request ever reaches the real target
(so it never leaks) and its value is stored as `tool_source` on the
captured MongoDB document instead. Consumers of captured traffic
(SiteMap, TrafficExtractor, the JWT/GraphQL/WebSocket review queues)
use `tool_source` to skip re-surfacing traffic the user just generated
themselves.
"""
from __future__ import annotations

TOOL_MARKER_HEADER = "X-Awe-Tool-Source"


def pop_tool_marker(
    headers: list[tuple[str, str]],
) -> tuple[list[tuple[str, str]], str | None]:
    """Strip TOOL_MARKER_HEADER from headers, returning (clean_headers, value)."""
    marker = None
    out: list[tuple[str, str]] = []
    for k, v in headers:
        if k.lower() == TOOL_MARKER_HEADER.lower():
            marker = v
            continue
        out.append((k, v))
    return out, marker
