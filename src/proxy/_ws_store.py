"""
WebSocket connection + frame store — MongoDB backend.

Uses the same awe_proxy_traffic database as TrafficStore, adding two
new collections:

  ws_connections  — one document per WebSocket connection
  ws_frames       — one document per intercepted frame

Thread-safe: all writes are queued and drained by a daemon thread so
create_connection / append_frame / close_connection never block the
asyncio event loop.
"""
from __future__ import annotations

import logging
import queue
import threading
from datetime import datetime, timezone

from bson import ObjectId

from proxy._ws_frame import WSFrame, _MAX_PAYLOAD_LOG, payload_text

log = logging.getLogger(__name__)

_SENTINEL = None   # signals the writer thread to stop


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _flatten(doc: dict | None) -> dict | None:
    if doc is None:
        return None
    d = dict(doc)
    if "_id" in d:
        d["id"] = str(d.pop("_id"))
    return d


class WSStore:
    """
    Shared store for WebSocket connection metadata and frame payloads.

    One instance lives in ProxyServer (for writes from the asyncio loop).
    WebSocketPage creates its own instance for reads — both talk to the
    same MongoDB collections.
    """

    def __init__(self) -> None:
        self._queue: queue.Queue = queue.Queue(maxsize=50_000)
        self._writer = threading.Thread(
            target=self._writer_loop, daemon=True, name="ws-store-writer",
        )
        self._writer.start()

    # ── write API ─────────────────────────────────────────────────────────────
    # These are called from the asyncio event-loop thread; they must NEVER block.

    def create_connection(self, host: str, path: str) -> str:
        """
        Reserve a new ws_connections document.  The ObjectId is generated
        locally so callers get a non-empty conn_id immediately without any
        I/O.  The actual DB insert happens on the writer thread.
        """
        conn_id = str(ObjectId())
        self._queue.put_nowait({
            "_type":    "create",
            "conn_id":  conn_id,
            "host":     host,
            "path":     path or "/",
            "opened_at": _now(),
        })
        return conn_id

    def append_frame(self, conn_id: str, frame: WSFrame) -> None:
        """Enqueue a frame for async write. Non-blocking."""
        if not conn_id:
            return
        txt = payload_text(frame)
        try:
            self._queue.put_nowait({
                "_type":       "frame",
                "conn_id":     conn_id,
                "direction":   frame.direction,
                "opcode":      frame.opcode,
                "opcode_name": frame.opcode_name(),
                "payload_text": txt[:_MAX_PAYLOAD_LOG],
                "payload_len": len(frame.payload),
                "timestamp":   frame.timestamp,
            })
        except queue.Full:
            log.warning("ws_store queue full — dropping frame for conn %s", conn_id)

    def close_connection(self, conn_id: str) -> None:
        """Enqueue a connection-close update."""
        if not conn_id:
            return
        try:
            self._queue.put_nowait({
                "_type":     "close",
                "conn_id":   conn_id,
                "closed_at": _now(),
            })
        except queue.Full:
            pass

    def shutdown(self) -> None:
        """Flush remaining items and stop the writer thread (called at proxy shutdown)."""
        self._queue.put(_SENTINEL)
        self._writer.join(timeout=5)

    # ── read API ──────────────────────────────────────────────────────────────
    # Called from the GUI main thread; direct (synchronous) pymongo calls are fine here.

    def list_connections(self) -> list[dict]:
        try:
            from database.mongo import get_proxy_traffic_db
            docs = get_proxy_traffic_db().ws_connections.find(
                {}, sort=[("opened_at", -1)]
            )
            return [_flatten(d) for d in docs]
        except Exception:
            log.exception("WSStore.list_connections failed")
            return []

    def get_frames(self, conn_id: str) -> list[dict]:
        try:
            from database.mongo import get_proxy_traffic_db
            docs = get_proxy_traffic_db().ws_frames.find(
                {"conn_id": conn_id}, sort=[("timestamp", 1)]
            )
            return [_flatten(d) for d in docs]
        except Exception:
            log.exception("WSStore.get_frames failed")
            return []

    def get_connection(self, conn_id: str) -> dict | None:
        try:
            from database.mongo import get_proxy_traffic_db
            return _flatten(
                get_proxy_traffic_db().ws_connections.find_one(
                    {"_id": ObjectId(conn_id)}
                )
            )
        except Exception:
            return None

    def clear_all(self) -> None:
        try:
            from database.mongo import get_proxy_traffic_db
            db = get_proxy_traffic_db()
            db.ws_connections.drop()
            db.ws_frames.drop()
        except Exception:
            log.exception("WSStore.clear_all failed")

    # ── writer thread ─────────────────────────────────────────────────────────

    def _writer_loop(self) -> None:
        db = None
        while True:
            entry = self._queue.get()
            if entry is _SENTINEL:
                break
            if db is None:
                try:
                    from database.mongo import get_proxy_traffic_db
                    db = get_proxy_traffic_db()
                    db.ws_connections.create_index([("opened_at", -1)])
                    db.ws_frames.create_index([("conn_id", 1), ("timestamp", 1)])
                except Exception:
                    log.exception("WSStore: cannot connect to MongoDB")
                    continue
            try:
                typ = entry["_type"]
                if typ == "create":
                    db.ws_connections.insert_one({
                        "_id":        ObjectId(entry["conn_id"]),
                        "host":       entry["host"],
                        "path":       entry["path"],
                        "opened_at":  entry["opened_at"],
                        "closed_at":  None,
                        "frame_count": 0,
                    })
                elif typ == "frame":
                    row = {k: v for k, v in entry.items() if k != "_type"}
                    db.ws_frames.insert_one(row)
                    db.ws_connections.update_one(
                        {"_id": ObjectId(entry["conn_id"])},
                        {"$inc": {"frame_count": 1}},
                    )
                elif typ == "close":
                    db.ws_connections.update_one(
                        {"_id": ObjectId(entry["conn_id"])},
                        {"$set": {"closed_at": entry["closed_at"]}},
                    )
            except Exception:
                log.exception("WSStore write failed for entry type %s", entry.get("_type"))
