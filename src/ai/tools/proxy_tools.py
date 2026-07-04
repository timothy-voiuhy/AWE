"""AI tool wrappers over the captured proxy traffic (awe_proxy_traffic.traffic)."""
from __future__ import annotations

import json

from bson import ObjectId
from forgeai import ToolRegistry

from ai.context import AiToolContext


def _make_query_proxy_traffic(ctx: AiToolContext):
    def query_proxy_traffic(host_contains: str = "", method: str = "", status_code: int = 0, limit: int = 20) -> str:
        """Query captured HTTP proxy traffic (requests/responses seen by the browser tap).

        Args:
            host_contains: Substring filter on the request host.
            method: Optional HTTP method filter, e.g. GET, POST.
            status_code: Optional exact response status code filter (0 = any).
            limit: Maximum number of entries to return, most recent first.
        """
        if ctx.proxy_col is None:
            return "Error: proxy traffic collection is unavailable"
        filt: dict = {}
        if host_contains:
            filt["host"] = {"$regex": host_contains, "$options": "i"}
        if method:
            filt["method"] = method.upper()
        if status_code:
            filt["status_code"] = status_code
        cursor = ctx.proxy_col.find(filt).sort("timestamp", -1).limit(limit)
        entries = []
        for d in cursor:
            d["id"] = str(d.pop("_id"))
            entries.append(d)
        return json.dumps(entries, default=str)

    return query_proxy_traffic


def _make_get_proxy_traffic_entry(ctx: AiToolContext):
    def get_proxy_traffic_entry(entry_id: str) -> str:
        """Get the full request/response detail for one captured traffic entry.

        Args:
            entry_id: Entry id, from query_proxy_traffic.
        """
        if ctx.proxy_col is None:
            return "Error: proxy traffic collection is unavailable"
        try:
            doc = ctx.proxy_col.find_one({"_id": ObjectId(entry_id)})
        except Exception as exc:
            return f"Error: invalid entry_id — {exc}"
        if doc is None:
            return f"Error: no traffic entry found with id '{entry_id}'"
        doc["id"] = str(doc.pop("_id"))
        return json.dumps(doc, default=str)

    return get_proxy_traffic_entry


def register_all(registry: ToolRegistry, ctx: AiToolContext) -> None:
    registry.register(_make_query_proxy_traffic(ctx))
    registry.register(_make_get_proxy_traffic_entry(ctx))
