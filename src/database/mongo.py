"""
MongoDB connection management for AWE.

One database per project: "awe_{safe_project_name}"
The connection is lazy — MongoClient is only created on first access.

Collections:
  scan_sessions  — one doc per pipeline run
  tool_runs      — one doc per tool execution, references session _id
  results        — one doc per unique result; dedup key = (session_id, category, result_key)

Usage:
    from database.mongo import get_db
    db = get_db(project_dir)
    db.scan_sessions.find_one(...)
"""
import re
from functools import lru_cache

import pymongo
from pymongo import MongoClient
from pymongo.database import Database

_DEFAULT_URI = "mongodb://localhost:27017"


def _safe_db_name(project_dir: str) -> str:
    """Convert a filesystem path to a valid MongoDB database name."""
    name = re.sub(r"[^a-zA-Z0-9_]", "_", project_dir.strip("/").replace("/", "_"))
    name = re.sub(r"_+", "_", name).strip("_")
    return f"awe_{name}"[:38]   # MongoDB max db name ≤ 38 chars on some platforms


@lru_cache(maxsize=16)
def _client(uri: str = _DEFAULT_URI) -> MongoClient:
    return MongoClient(uri, serverSelectionTimeoutMS=3000)


def get_db(project_dir: str, uri: str = _DEFAULT_URI) -> Database:
    db_name = _safe_db_name(project_dir)
    db = _client(uri)[db_name]
    _ensure_indexes(db)
    return db


def ping(uri: str = _DEFAULT_URI) -> tuple[bool, str]:
    """Returns (ok, message). Used for health checks."""
    try:
        c = _client(uri)
        c.admin.command("ping")
        si = c.server_info()
        return True, f"MongoDB {si.get('version', '?')} — connected"
    except Exception as exc:
        return False, str(exc)


def _ensure_indexes(db: Database):
    # scan_sessions
    db.scan_sessions.create_index("project_dir")
    db.scan_sessions.create_index("status")
    db.scan_sessions.create_index("started_at")

    # tool_runs
    db.tool_runs.create_index("session_id")
    db.tool_runs.create_index([("session_id", 1), ("tool_key", 1)])
    db.tool_runs.create_index("status")

    # results — compound unique index for dedup
    db.results.create_index(
        [("session_id", 1), ("category", 1), ("result_key", 1)],
        unique=True,
    )
    db.results.create_index([("session_id", 1), ("category", 1)])
