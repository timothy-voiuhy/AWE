import asyncio
import secrets
import threading
from datetime import datetime, timezone
from pathlib import Path

from .schemas import IntruderJob, IntruderRequest, IntruderResult


class IntruderJobNotFound(LookupError):
    pass


class IntruderJobManager:
    """Runs Intruder attacks and stores them in AWE's per-project Mongo DB."""

    def __init__(self, service, workspace_dir: Path, mongo_uri: str):
        self.service = service
        self.workspace_dir = workspace_dir
        self.mongo_uri = mongo_uri
        self.cancel_events: dict[str, threading.Event] = {}
        self.initialized_projects: set[str] = set()
        self.lock = threading.RLock()

    def _db(self, project_id: str):
        from database.mongo import get_db
        db = get_db(str((self.workspace_dir / project_id).resolve()), self.mongo_uri)
        with self.lock:
            if project_id not in self.initialized_projects:
                self._initialize_db(db)
                self.initialized_projects.add(project_id)
        return db

    def _initialize_db(self, db) -> None:
        db.intruder_jobs.create_index([("project_id", 1), ("created_at", -1)])
        db.intruder_results.create_index([("job_id", 1), ("sequence", 1)], unique=True)
        now = datetime.now(timezone.utc).isoformat()
        db.intruder_jobs.update_many(
            {"status": {"$in": ["queued", "running", "cancelling"]}},
            {"$set": {"status": "failed", "completed_at": now,
                      "error": "Backend restarted before this Intruder job completed"}},
        )

    def start(self, project_id: str, request: IntruderRequest) -> IntruderJob:
        job = IntruderJob(id=secrets.token_hex(12), project_id=project_id,
                          status="queued", created_at=datetime.now(timezone.utc),
                          total=len(self.service.generate_requests(request)))
        self._db(project_id).intruder_jobs.insert_one({
            "_id": job.id, "id": job.id, "project_id": project_id,
            "status": job.status, "created_at": job.created_at.isoformat(),
            "completed_at": None, "total": job.total, "completed": 0,
            "error": "", "request": request.model_dump(mode="json"),
        })
        event = threading.Event()
        with self.lock:
            self.cancel_events[job.id] = event
        threading.Thread(target=self._run, args=(job.id, project_id, request, event),
                         daemon=True, name=f"awe-intruder-{job.id}").start()
        return self.get(project_id, job.id)

    def _run(self, job_id, project_id, request, event):
        self._update(project_id, job_id, status="running")
        try:
            results = asyncio.run(self.service.run(
                request, cancel_event=event,
                progress=lambda result: self._progress(project_id, job_id, result)))
            self._replace_results(project_id, job_id, results)
            self._update(project_id, job_id,
                         status="cancelled" if event.is_set() else "completed",
                         completed=len(results), completed_at=datetime.now(timezone.utc).isoformat())
        except Exception as exc:
            self._update(project_id, job_id, status="failed", error=str(exc),
                         completed_at=datetime.now(timezone.utc).isoformat())
        finally:
            with self.lock:
                self.cancel_events.pop(job_id, None)

    def _progress(self, project_id, job_id, result):
        db = self._db(project_id)
        db.intruder_results.replace_one({"job_id": job_id, "sequence": result.sequence},
                                        {"job_id": job_id, "sequence": result.sequence,
                                         "result": result.model_dump(mode="json")}, upsert=True)
        self._update(project_id, job_id,
                     completed=db.intruder_results.count_documents({"job_id": job_id}))

    def _replace_results(self, project_id, job_id, results):
        db = self._db(project_id)
        db.intruder_results.delete_many({"job_id": job_id})
        if results:
            db.intruder_results.insert_many([{"job_id": job_id, "sequence": r.sequence,
                                              "result": r.model_dump(mode="json")} for r in results])

    def _update(self, project_id, job_id, **changes):
        self._db(project_id).intruder_jobs.update_one({"_id": job_id}, {"$set": changes})

    def _model(self, project_id, row):
        db = self._db(project_id)
        result_rows = db.intruder_results.find({"job_id": row["id"]}).sort("sequence", 1)
        return IntruderJob(id=row["id"], project_id=row["project_id"], status=row["status"],
                           created_at=row["created_at"], completed_at=row.get("completed_at"),
                           total=row.get("total", 0), completed=row.get("completed", 0),
                           error=row.get("error", ""),
                           results=[IntruderResult.model_validate(item["result"]) for item in result_rows])

    def get(self, project_id: str, job_id: str) -> IntruderJob:
        row = self._db(project_id).intruder_jobs.find_one({"_id": job_id})
        if row is None:
            raise IntruderJobNotFound(job_id)
        return self._model(project_id, row)

    def list(self, project_id: str) -> list[IntruderJob]:
        rows = self._db(project_id).intruder_jobs.find({"project_id": project_id}).sort("created_at", -1)
        return [self._model(project_id, row) for row in rows]

    def cancel(self, project_id: str, job_id: str) -> IntruderJob:
        job = self.get(project_id, job_id)
        if job.status not in {"queued", "running", "cancelling"}:
            return job
        with self.lock:
            event = self.cancel_events.get(job_id)
            if event is None:
                raise IntruderJobNotFound(job_id)
            event.set()
        self._update(project_id, job_id, status="cancelling")
        return self.get(project_id, job_id)
