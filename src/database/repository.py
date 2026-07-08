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
        if status in ("completed", "failed", "cancelled", "stopped"):
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

    def save_tool_run_log(self, run_id: str, lines: list[str]) -> None:
        self._db.tool_runs.update_one(
            {"_id": _oid(run_id)},
            {"$set": {"log_lines": lines}},
        )

    def get_tool_run_logs(self, session_id: str) -> dict[str, list[str]]:
        """Return {tool_key: [log_lines]} for every tool run in a session."""
        cursor = self._db.tool_runs.find(
            {"session_id": session_id},
            {"tool_key": 1, "log_lines": 1},
        )
        return {
            d["tool_key"]: d.get("log_lines", [])
            for d in cursor
            if d.get("tool_key")
        }

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

    def delete_results(
        self,
        category: str,
        result_keys: list[str],
        session_id: str | None = None,
    ) -> int:
        """Delete stored result docs matching category+result_key — backs the
        Results page's row-level Delete context menu action.

        Scoped to a single session_id when the Results page is narrowed to
        one pipeline session (load_session()); otherwise every session in the
        project, including the proxy/manual-import pseudo-sessions, so a
        "deleted" finding doesn't reappear from another session's copy the
        next time the merged view reloads.
        """
        if not result_keys:
            return 0
        filt: dict[str, Any] = {"category": category, "result_key": {"$in": result_keys}}
        if session_id:
            filt["session_id"] = session_id
        else:
            sids = self._all_session_ids_including_proxy()
            if not sids:
                return 0
            filt["session_id"] = {"$in": sids}
        result = self._db.results.delete_many(filt)
        self._db.reviewed_results.delete_many({
            "project_dir": self._project_dir,
            "category": category,
            "key": {"$in": result_keys},
        })
        return result.deleted_count

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

    # ── Project-scope helpers (across all sessions for this project) ──────────

    _VALUE_FIELD: dict[str, str | None] = {
        "subdomain":  "domain",
        "dns":        "name",
        "portscan":   None,   # returns host:port
        "http":       "url",
        "crawl":      "url",
        "params":     "endpoint",
        "fuzz":       None,
        "vuln":       "url",
        "osint":      "value",
        "screenshot": "url",
    }

    def _all_session_ids(self) -> list[str]:
        """All session IDs for this project (excludes proxy pseudo-session)."""
        cursor = self._db.scan_sessions.find(
            {
                "project_dir":  self._project_dir,
                "pipeline_key": {"$ne": "proxy_traffic"},
            },
            {"_id": 1},
        )
        return [_str(d["_id"]) for d in cursor]

    def _all_session_ids_including_proxy(self) -> list[str]:
        """Every session ID for this project, including the proxy pseudo-session —
        used for the project-wide Results view so browser-tapped traffic is merged
        in alongside tool-run sessions."""
        cursor = self._db.scan_sessions.find(
            {"project_dir": self._project_dir}, {"_id": 1}
        )
        return [_str(d["_id"]) for d in cursor]

    def get_results_project(self, category: str | None = None) -> list[dict]:
        """All results across every session in this project (tool-run sessions plus
        the proxy pseudo-session) — the data source for the Results page's default
        whole-project view."""
        sids = self._all_session_ids_including_proxy()
        if not sids:
            return []
        filt: dict[str, Any] = {"session_id": {"$in": sids}}
        if category:
            filt["category"] = category
        return [_flatten(d) for d in self._db.results.find(filt)]

    def _completed_session_ids(self) -> list[str]:
        """Session IDs where status == completed (excludes proxy pseudo-session)."""
        cursor = self._db.scan_sessions.find(
            {
                "project_dir":  self._project_dir,
                "status":       "completed",
                "pipeline_key": {"$ne": "proxy_traffic"},
            },
            {"_id": 1},
        )
        return [_str(d["_id"]) for d in cursor]

    def _get_values_for_sessions(self, session_ids: list[str], category: str) -> list[str]:
        """Extract deduplicated primary values for a category from the given sessions."""
        if not session_ids:
            return []
        field = self._VALUE_FIELD.get(category, "value")
        cursor = self._db.results.find(
            {"session_id": {"$in": session_ids}, "category": category},
            {"data": 1, "_id": 0},
        )
        seen: set[str] = set()
        values: list[str] = []
        for doc in cursor:
            data = doc.get("data", {})
            if category == "portscan":
                host = data.get("host", "")
                port = data.get("port", "")
                v = f"{host}:{port}" if host and port else ""
            elif field:
                v = data.get(field, "")
            else:
                v = ""
            if v and v not in seen:
                seen.add(v)
                values.append(v)
        return values

    def get_combined_values(self, session_id: str, category: str) -> list[str]:
        """
        Returns the primary string value for each unique result in a category.
        Used to build input files for downstream pipeline stages.
        """
        return self._get_values_for_sessions([session_id], category)

    def get_combined_values_project(self, category: str) -> list[str]:
        """
        Returns deduplicated primary values for a category across ALL sessions
        in this project (including the currently running one).
        Used when reuse_project_results is enabled in the executor.
        """
        return self._get_values_for_sessions(self._all_session_ids(), category)

    def count_results(self, session_id: str, category: str | None = None) -> int:
        filt: dict[str, Any] = {"session_id": session_id}
        if category:
            filt["category"] = category
        return self._db.results.count_documents(filt)

    def count_results_project(self, category: str) -> int:
        """Count results for a category across ALL sessions in this project."""
        sids = self._all_session_ids()
        if not sids:
            return 0
        return self._db.results.count_documents(
            {"session_id": {"$in": sids}, "category": category}
        )

    def tool_ran_in_project(self, tool_key: str) -> bool:
        """
        True if this tool completed with at least one result in any finished
        session for this project. Used to skip redundant re-runs.
        """
        sids = self._completed_session_ids()
        if not sids:
            return False
        return self._db.tool_runs.find_one({
            "session_id":   {"$in": sids},
            "tool_key":     tool_key,
            "status":       "completed",
            "result_count": {"$gt": 0},
        }) is not None

    def get_failed_tool_keys(self, session_id: str) -> list[str]:
        cursor = self._db.tool_runs.find(
            {"session_id": session_id, "status": "failed"},
            {"tool_key": 1},
        )
        return [d["tool_key"] for d in cursor]

    def get_tool_run_statuses(self, session_id: str) -> dict[str, str]:
        """Return {tool_key: status} for all tool runs in this session."""
        cursor = self._db.tool_runs.find(
            {"session_id": session_id},
            {"tool_key": 1, "status": 1},
        )
        return {d["tool_key"]: d["status"] for d in cursor}

    def reset_running_tool_runs(self, session_id: str) -> None:
        """Mark any lingering running/pending tool runs as stopped.
        Called before resuming a session that was interrupted (user stop or app close)."""
        self._db.tool_runs.update_many(
            {"session_id": session_id, "status": {"$in": ["running", "pending"]}},
            {"$set": {"status": "stopped", "error_msg": "interrupted (app closed)"}},
        )

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

    # ── Project Scope ─────────────────────────────────────────────────────────

    def save_scope(self, config: "ScopeConfig") -> None:
        from database.scope import ScopeConfig
        doc = config.to_dict()
        doc["project_dir"] = self._project_dir
        doc["updated_at"]  = _now()
        self._db.project_scope.update_one(
            {"project_dir": self._project_dir},
            {"$set": doc},
            upsert=True,
        )

    def get_scope(self) -> "ScopeConfig":
        from database.scope import ScopeConfig
        doc = self._db.project_scope.find_one({"project_dir": self._project_dir})
        if doc:
            return ScopeConfig.from_dict(doc)
        return ScopeConfig()   # empty = open scope (matches everything)

    # ── Auth Sessions (Session Factory) ──────────────────────────────────────

    def create_auth_session(
        self,
        name: str,
        headers: list,
        params: list,
    ) -> str:
        doc = {
            "project_dir": self._project_dir,
            "name":        name,
            "headers":     headers,
            "params":      params,
            "created_at":  _now(),
        }
        result = self._db.auth_sessions.insert_one(doc)
        return _str(result.inserted_id)

    def list_auth_sessions(self) -> list[dict]:
        cursor = self._db.auth_sessions.find(
            {"project_dir": self._project_dir},
            sort=[("created_at", 1)],
        )
        return [_flatten(d) for d in cursor]

    def get_auth_session(self, session_id: str) -> dict | None:
        doc = self._db.auth_sessions.find_one({"_id": _oid(session_id)})
        return _flatten(doc)

    def update_auth_session(
        self,
        session_id: str,
        name: str,
        headers: list,
        params: list,
    ) -> None:
        self._db.auth_sessions.update_one(
            {"_id": _oid(session_id)},
            {"$set": {"name": name, "headers": headers, "params": params}},
        )

    def delete_auth_session(self, session_id: str) -> None:
        self._db.auth_sessions.delete_one({"_id": _oid(session_id)})

    # ── Review Queue (passively-detected candidates awaiting user review) ────
    #
    # queue_name: "jwt" | "graphql" | "websocket" — one nav-badge-worth of items.
    # dedup_key identifies the underlying artifact (e.g. a token's hash, a
    # websocket conn_id) so the same thing detected repeatedly across traffic
    # is never queued twice, mirroring how Burp doesn't re-flag an already-seen
    # issue. Once a dedup_key exists for a (project_dir, queue_name), it is
    # never recreated even if later dismissed/reviewed.

    def create_review_item(
        self,
        queue_name: str,
        kind: str,
        summary: str,
        payload: dict,
        dedup_key: str,
    ) -> str | None:
        """Insert a new pending review item, or return None if this exact
        artifact (by dedup_key) has already been queued before."""
        existing = self._db.review_queue.find_one({
            "project_dir": self._project_dir,
            "queue_name":  queue_name,
            "dedup_key":   dedup_key,
        })
        if existing:
            return None
        doc = {
            "project_dir": self._project_dir,
            "queue_name":  queue_name,
            "kind":        kind,
            "summary":     summary,
            "payload":     payload,
            "dedup_key":   dedup_key,
            "status":      "pending",
            "created_at":  _now(),
            "reviewed_at": None,
        }
        result = self._db.review_queue.insert_one(doc)
        return _str(result.inserted_id)

    def list_review_items(self, queue_name: str, status: str | None = "pending") -> list[dict]:
        filt: dict[str, Any] = {"project_dir": self._project_dir, "queue_name": queue_name}
        if status:
            filt["status"] = status
        cursor = self._db.review_queue.find(filt, sort=[("created_at", -1)])
        return [_flatten(d) for d in cursor]

    def count_pending_review(self, queue_name: str) -> int:
        return self._db.review_queue.count_documents({
            "project_dir": self._project_dir,
            "queue_name":  queue_name,
            "status":      "pending",
        })

    def mark_review_item(self, item_id: str, status: str) -> None:
        """status: 'reviewed' | 'dismissed'."""
        self._db.review_queue.update_one(
            {"_id": _oid(item_id)},
            {"$set": {"status": status, "reviewed_at": _now()}},
        )

    # ── UI Page State ─────────────────────────────────────────────────────────

    def save_page_state(self, page: str, state: dict) -> None:
        """Upsert workspace state for a named page (e.g. 'jwt', 'decoder', 'comparer')."""
        self._db.ui_page_states.update_one(
            {"project_dir": self._project_dir, "page": page},
            {"$set": {"project_dir": self._project_dir, "page": page,
                      "state": state, "updated_at": _now()}},
            upsert=True,
        )

    def load_page_state(self, page: str) -> dict:
        """Return saved workspace state for a page, or {} if none."""
        doc = self._db.ui_page_states.find_one(
            {"project_dir": self._project_dir, "page": page}
        )
        return doc.get("state", {}) if doc else {}

    # ── Proxy Traffic pseudo-session ──────────────────────────────────────────

    PROXY_SESSION_KEY = "proxy_traffic"

    def get_or_create_proxy_session(self, target: str) -> str:
        """Return the session_id for the persistent proxy_traffic pseudo-session."""
        doc = self._db.scan_sessions.find_one({
            "project_dir":  self._project_dir,
            "pipeline_key": self.PROXY_SESSION_KEY,
        })
        if doc:
            return _str(doc["_id"])
        new_doc = {
            "project_dir":   self._project_dir,
            "pipeline_key":  self.PROXY_SESSION_KEY,
            "pipeline_name": "Proxy Traffic (browser tap)",
            "target":        target,
            "status":        "running",
            "started_at":    _now(),
            "completed_at":  None,
            "output_dir":    "",
            "params":        {},
            "in_scope":      [],
            "out_of_scope":  [],
        }
        result = self._db.scan_sessions.insert_one(new_doc)
        return _str(result.inserted_id)

    def get_proxy_tool_run_id(self, session_id: str) -> str:
        """Return the tool_run_id for the proxy_traffic_extractor run."""
        doc = self._db.tool_runs.find_one({
            "session_id": session_id,
            "tool_key":   "proxy_traffic_extractor",
        })
        if doc:
            return _str(doc["_id"])
        new_doc = {
            "session_id":   session_id,
            "tool_key":     "proxy_traffic_extractor",
            "display_name": "Proxy Traffic Extractor",
            "category":     "crawl",
            "stage":        0,
            "status":       "running",
            "started_at":   _now(),
            "completed_at": None,
            "result_count": 0,
            "error_msg":    None,
        }
        result = self._db.tool_runs.insert_one(new_doc)
        return _str(result.inserted_id)

    # ── Manual import pseudo-session ──────────────────────────────────────────

    MANUAL_IMPORT_SESSION_KEY = "manual_import"

    def get_or_create_manual_import_session(self, target: str = "") -> str:
        """Return the session_id for the persistent manual-import pseudo-session
        — used by the Results page's Import button to seed subdomains/endpoints
        from external text files. Mirrors get_or_create_proxy_session()."""
        doc = self._db.scan_sessions.find_one({
            "project_dir":  self._project_dir,
            "pipeline_key": self.MANUAL_IMPORT_SESSION_KEY,
        })
        if doc:
            return _str(doc["_id"])
        new_doc = {
            "project_dir":   self._project_dir,
            "pipeline_key":  self.MANUAL_IMPORT_SESSION_KEY,
            "pipeline_name": "Manual Import",
            "target":        target,
            "status":        "completed",
            "started_at":    _now(),
            "completed_at":  _now(),
            "output_dir":    "",
            "params":        {},
            "in_scope":      [],
            "out_of_scope":  [],
        }
        result = self._db.scan_sessions.insert_one(new_doc)
        return _str(result.inserted_id)

    def get_manual_import_tool_run_id(self, session_id: str) -> str:
        """Return the shared tool_run_id for manual imports into this session —
        one run accumulates every import batch, like proxy_traffic_extractor."""
        doc = self._db.tool_runs.find_one({
            "session_id": session_id,
            "tool_key":   "manual_import",
        })
        if doc:
            return _str(doc["_id"])
        new_doc = {
            "session_id":   session_id,
            "tool_key":     "manual_import",
            "display_name": "Manual Import",
            "category":     "mixed",
            "stage":        0,
            "status":       "completed",
            "started_at":   _now(),
            "completed_at": _now(),
            "result_count": 0,
            "error_msg":    None,
        }
        result = self._db.tool_runs.insert_one(new_doc)
        return _str(result.inserted_id)

    # ── Testing Methodology ───────────────────────────────────────────────────

    def seed_methodology_registry(self, categories: list[dict]) -> None:
        """
        Upsert the full vulnerability registry into a shared DB collection
        so other parts of the app (reports, dashboards) can query it.
        Each vulnerability is stored as one document keyed by vuln_id.
        """
        from pymongo import UpdateOne
        ops = []
        for cat in categories:
            cat_id   = cat["id"]
            cat_name = cat["name"]
            for vuln in cat.get("vulnerabilities", []):
                ops.append(UpdateOne(
                    {"vuln_id": vuln["id"]},
                    {"$set": {
                        "vuln_id":          vuln["id"],
                        "name":             vuln["name"],
                        "category_id":      cat_id,
                        "category_name":    cat_name,
                        "description_file": vuln.get("description_file", ""),
                        "accent":           cat.get("accent", "#9399B2"),
                        "icon":             cat.get("icon", "◉"),
                    }},
                    upsert=True,
                ))
        if ops:
            self._db.methodology_registry.bulk_write(ops, ordered=False)

    def save_methodology_state(self, states: dict) -> None:
        """
        Persist per-vulnerability testing state (status + notes) for this
        project.  `states` maps vuln_id → {status, notes}.
        """
        from pymongo import UpdateOne
        ops = [
            UpdateOne(
                {"project_dir": self._project_dir, "vuln_id": vid},
                {"$set": {
                    "project_dir": self._project_dir,
                    "vuln_id":     vid,
                    "status":      s.get("status", "not_tested"),
                    "notes":       s.get("notes", ""),
                    "updated_at":  _now(),
                }},
                upsert=True,
            )
            for vid, s in states.items()
            if not vid.startswith("__")
        ]
        if ops:
            self._db.methodology_states.bulk_write(ops, ordered=False)

    def load_methodology_states(self) -> dict:
        """Return {vuln_id: {status, notes}} for this project."""
        cursor = self._db.methodology_states.find(
            {"project_dir": self._project_dir},
            {"vuln_id": 1, "status": 1, "notes": 1, "_id": 0},
        )
        return {
            d["vuln_id"]: {"status": d.get("status", "not_tested"),
                           "notes":  d.get("notes", "")}
            for d in cursor
        }

    def get_methodology_summary(self) -> dict[str, int]:
        """Return {status: count} across all vulnerabilities for this project."""
        pipeline = [
            {"$match": {"project_dir": self._project_dir}},
            {"$group": {"_id": "$status", "count": {"$sum": 1}}},
        ]
        return {d["_id"]: d["count"]
                for d in self._db.methodology_states.aggregate(pipeline)}

    # ── Results Window: reviewed rows ─────────────────────────────────────────

    def mark_result_reviewed(self, category: str, key: str, reviewed: bool = True) -> None:
        """Persist reviewed/unreviewed state for one result row, keyed by its
        `.key` within a category (e.g. a subdomain name or endpoint URL)."""
        self._db.reviewed_results.update_one(
            {"project_dir": self._project_dir, "category": category, "key": key},
            {"$set": {"project_dir": self._project_dir, "category": category,
                      "key": key, "reviewed": reviewed, "updated_at": _now()}},
            upsert=True,
        )

    def get_reviewed_keys(self, category: str) -> set[str]:
        """Return the set of reviewed result keys for this project/category."""
        cursor = self._db.reviewed_results.find(
            {"project_dir": self._project_dir, "category": category, "reviewed": True},
            {"key": 1, "_id": 0},
        )
        return {d["key"] for d in cursor}


# ── helpers ───────────────────────────────────────────────────────────────────

def _flatten(doc: dict | None) -> dict | None:
    if doc is None:
        return None
    d = dict(doc)
    if "_id" in d:
        d["id"] = str(d.pop("_id"))
    return d
