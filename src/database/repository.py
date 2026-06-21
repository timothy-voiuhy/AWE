"""
AweRepository — all MongoDB read/write operations for AWE.

All public methods are thread-safe (pymongo connections are thread-safe).
ObjectId ↔ str conversion is handled internally; callers always use str IDs.
"""
import dataclasses
import json
from datetime import datetime, timezone
from typing import Any

from bson import ObjectId
from pymongo.database import Database

from database.mongo import get_db


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _oid(id_str: str) -> ObjectId:
    return ObjectId(id_str)


def _str(oid) -> str:
    return str(oid)


class AweRepository:
    def __init__(self, project_dir: str, uri: str = "mongodb://localhost:27017"):
        self._db: Database = get_db(project_dir, uri)
        self._project_dir = project_dir

    # ── Scan Sessions ─────────────────────────────────────────────────────────

    def create_session(
        self,
        pipeline_key: str,
        pipeline_name: str,
        target: str,
        output_dir: str,
        params: dict | None = None,
        in_scope: list[str] | None = None,
        out_of_scope: list[str] | None = None,
    ) -> str:
        doc = {
            "project_dir":    self._project_dir,
            "pipeline_key":   pipeline_key,
            "pipeline_name":  pipeline_name,
            "target":         target,
            "status":         "running",
            "started_at":     _now(),
            "completed_at":   None,
            "output_dir":     output_dir,
            "params":         params or {},
            "in_scope":       in_scope or [],
            "out_of_scope":   out_of_scope or [],
        }
        result = self._db.scan_sessions.insert_one(doc)
        return _str(result.inserted_id)

    def update_session_status(self, session_id: str, status: str):
        update: dict[str, Any] = {"status": status}
        if status in ("completed", "failed", "cancelled"):
            update["completed_at"] = _now()
        self._db.scan_sessions.update_one(
            {"_id": _oid(session_id)}, {"$set": update}
        )

    def get_session(self, session_id: str) -> dict | None:
        doc = self._db.scan_sessions.find_one({"_id": _oid(session_id)})
        return _flatten(doc)

    def list_sessions(self, limit: int = 50) -> list[dict]:
        cursor = self._db.scan_sessions.find(
            {"project_dir": self._project_dir},
            sort=[("started_at", -1)],
            limit=limit,
        )
        return [_flatten(d) for d in cursor]

    def delete_session(self, session_id: str):
        oid = _oid(session_id)
        self._db.results.delete_many({"session_id": session_id})
        self._db.tool_runs.delete_many({"session_id": session_id})
        self._db.scan_sessions.delete_one({"_id": oid})

    # ── Tool Runs ─────────────────────────────────────────────────────────────

    def create_tool_run(
        self,
        session_id: str,
        tool_key: str,
        display_name: str,
        category: str,
        stage: int = 0,
    ) -> str:
        doc = {
            "session_id":   session_id,
            "tool_key":     tool_key,
            "display_name": display_name,
            "category":     category,
            "stage":        stage,
            "status":       "pending",
            "started_at":   None,
            "completed_at": None,
            "result_count": 0,
            "error_msg":    None,
        }
        result = self._db.tool_runs.insert_one(doc)
        return _str(result.inserted_id)

    def update_tool_run_started(self, run_id: str):
        self._db.tool_runs.update_one(
            {"_id": _oid(run_id)},
            {"$set": {"status": "running", "started_at": _now()}},
        )

    def update_tool_run_done(
        self,
        run_id: str,
        status: str,
        result_count: int = 0,
        error_msg: str | None = None,
    ):
        self._db.tool_runs.update_one(
            {"_id": _oid(run_id)},
            {"$set": {
                "status":       status,
                "completed_at": _now(),
                "result_count": result_count,
                "error_msg":    error_msg,
            }},
        )

    def update_tool_run_skipped(self, run_id: str, reason: str = ""):
        self._db.tool_runs.update_one(
            {"_id": _oid(run_id)},
            {"$set": {
                "status":       "skipped",
                "completed_at": _now(),
                "error_msg":    reason,
            }},
        )

    def get_tool_runs(self, session_id: str) -> list[dict]:
        cursor = self._db.tool_runs.find(
            {"session_id": session_id}, sort=[("stage", 1), ("started_at", 1)]
        )
        return [_flatten(d) for d in cursor]

    # ── Results ───────────────────────────────────────────────────────────────

    def upsert_results(
        self,
        session_id: str,
        tool_run_id: str,
        category: str,
        results: list,   # list of BaseResult subclasses
    ) -> int:
        """
        Upsert results into the DB. Duplicate result_keys within the same
        session+category are merged (sources are union'd).
        Returns the number of new unique results written.
        """
        if not results:
            return 0

        from pymongo import UpdateOne
        ops = [
            UpdateOne(
                {"session_id": session_id, "category": category, "result_key": r.key},
                {
                    "$setOnInsert": {
                        "session_id":   session_id,
                        "tool_run_id":  tool_run_id,
                        "category":     category,
                        "result_key":   r.key,
                        "data":         dataclasses.asdict(r),
                        "created_at":   _now(),
                    },
                    "$addToSet": {"sources": {"$each": r.sources}},
                },
                upsert=True,
            )
            for r in results
        ]
        result = self._db.results.bulk_write(ops, ordered=False)
        return result.upserted_count

    def get_results(
        self,
        session_id: str,
        category: str | None = None,
        tool_run_id: str | None = None,
        limit: int = 0,
    ) -> list[dict]:
        filt: dict[str, Any] = {"session_id": session_id}
        if category:
            filt["category"] = category
        if tool_run_id:
            filt["tool_run_id"] = tool_run_id
        cursor = self._db.results.find(filt)
        if limit:
            cursor = cursor.limit(limit)
        return [_flatten(d) for d in cursor]

    def get_combined_values(self, session_id: str, category: str) -> list[str]:
        """
        Returns the primary string value for each unique result in a category.
        Used to build input files for downstream pipeline stages.
        """
        _VALUE_FIELD = {
            "subdomain": "domain",
            "dns":       "name",
            "portscan":  None,   # returns host:port
            "http":      "url",
            "crawl":     "url",
            "params":    "endpoint",
            "fuzz":      None,
            "vuln":      "url",
            "osint":     "value",
        }
        field = _VALUE_FIELD.get(category, "value")
        cursor = self._db.results.find(
            {"session_id": session_id, "category": category},
            {"data": 1, "_id": 0},
        )
        values = []
        for doc in cursor:
            data = doc.get("data", {})
            if category == "portscan":
                host = data.get("host", "")
                port = data.get("port", "")
                if host and port:
                    values.append(f"{host}:{port}")
            elif field and field in data:
                v = data[field]
                if v:
                    values.append(v)
        return values

    def count_results(self, session_id: str, category: str | None = None) -> int:
        filt: dict[str, Any] = {"session_id": session_id}
        if category:
            filt["category"] = category
        return self._db.results.count_documents(filt)

    def get_failed_tool_keys(self, session_id: str) -> list[str]:
        cursor = self._db.tool_runs.find(
            {"session_id": session_id, "status": "failed"},
            {"tool_key": 1},
        )
        return [d["tool_key"] for d in cursor]

    # ── Custom Pipelines ──────────────────────────────────────────────────────

    def save_custom_pipeline(self, pipeline_dict: dict):
        """Upsert a custom pipeline by key."""
        from datetime import datetime, timezone
        pipeline_dict["project_dir"] = self._project_dir
        pipeline_dict["updated_at"]  = datetime.now(timezone.utc).isoformat()
        self._db.custom_pipelines.update_one(
            {"key": pipeline_dict["key"], "project_dir": self._project_dir},
            {"$set": pipeline_dict},
            upsert=True,
        )

    def list_custom_pipelines(self) -> list[dict]:
        return list(self._db.custom_pipelines.find(
            {"project_dir": self._project_dir}
        ))

    def delete_custom_pipeline(self, key: str):
        self._db.custom_pipelines.delete_one(
            {"key": key, "project_dir": self._project_dir}
        )

    def session_summary(self, session_id: str) -> dict[str, int]:
        pipeline = [
            {"$match": {"session_id": session_id}},
            {"$group": {"_id": "$category", "count": {"$sum": 1}}},
        ]
        return {d["_id"]: d["count"] for d in self._db.results.aggregate(pipeline)}


# ── helpers ───────────────────────────────────────────────────────────────────

def _flatten(doc: dict | None) -> dict | None:
    if doc is None:
        return None
    d = dict(doc)
    if "_id" in d:
        d["id"] = str(d.pop("_id"))
    return d
