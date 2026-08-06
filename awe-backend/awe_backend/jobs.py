from __future__ import annotations

import secrets
import sys
import threading
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

from .pipelines import PipelineCatalog
from .schemas import PipelineEvent, PipelineJob


def _now() -> datetime:
    return datetime.now(timezone.utc)


class JobNotFoundError(LookupError):
    pass


class PipelineJobManager:
    """Owns background PipelineRunner instances and their observable state."""

    def __init__(
        self,
        legacy_src_dir: Path,
        mongo_uri: str,
        max_events: int = 1000,
        template_loader=None,
        runner_factory=None,
    ):
        self._legacy_src_dir = legacy_src_dir.resolve()
        self._mongo_uri = mongo_uri
        self._max_events = max_events
        self._template_loader = template_loader or self._load_template
        self._runner_factory = runner_factory or self._create_runner
        self._jobs: dict[str, PipelineJob] = {}
        self._runners: dict[str, object] = {}
        self._lock = threading.RLock()

    def start(
        self,
        project_id: str,
        project_dir: Path,
        pipeline_key: str,
        target: str,
        params: dict,
        in_scope: list[str],
        out_of_scope: list[str],
    ) -> PipelineJob:
        template = self._template_loader(pipeline_key)
        if template is None:
            raise ValueError(f"Unknown pipeline: {pipeline_key}")

        job_id = secrets.token_hex(12)
        job = PipelineJob(
            id=job_id,
            project_id=project_id,
            pipeline_key=pipeline_key,
            status="queued",
            created_at=_now(),
        )
        runner = self._runner_factory(
            template=template,
            project_dir=str(project_dir),
            target=target,
            params=params,
            in_scope=in_scope,
            out_of_scope=out_of_scope,
            mongo_uri=self._mongo_uri,
        )
        self._connect(job_id, runner)
        with self._lock:
            self._jobs[job_id] = job
            self._runners[job_id] = runner
        threading.Thread(
            target=self._run,
            args=(job_id, runner),
            name=f"awe-pipeline-{job_id}",
            daemon=True,
        ).start()
        return self.get(job_id)

    def _load_template(self, pipeline_key: str):
        return PipelineCatalog(self._legacy_src_dir).get_legacy_template(pipeline_key)

    def _create_runner(self, **kwargs):
        source = str(self._legacy_src_dir)
        if source not in sys.path:
            sys.path.insert(0, source)
        from pipeline.runner import PipelineRunner

        return PipelineRunner(**kwargs)

    def get(self, job_id: str) -> PipelineJob:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                raise JobNotFoundError(job_id)
            return job.model_copy(deep=True)

    def list_for_project(self, project_id: str) -> list[PipelineJob]:
        with self._lock:
            jobs = [job.model_copy(deep=True) for job in self._jobs.values() if job.project_id == project_id]
        return sorted(jobs, key=lambda item: item.created_at, reverse=True)

    def stop(self, job_id: str) -> PipelineJob:
        with self._lock:
            job = self._jobs.get(job_id)
            runner = self._runners.get(job_id)
            if job is None or runner is None:
                raise JobNotFoundError(job_id)
            if job.status in ("queued", "running"):
                job.status = "stopping"
                self._append_event(job, "pipeline.stopping", {})
                runner.stop()
            return job.model_copy(deep=True)

    def _connect(self, job_id: str, runner) -> None:
        runner.session_started.connect(lambda session_id: self._update(job_id, "pipeline.session_started", {"session_id": session_id}, session_id=session_id))
        runner.step_started.connect(lambda key, name, stage: self._update(job_id, "pipeline.tool_started", {"tool_key": key, "name": name, "stage": stage}))
        runner.step_log.connect(lambda key, line: self._update(job_id, "pipeline.tool_log", {"tool_key": key, "line": line}))
        runner.step_done.connect(lambda key, status, count: self._update(job_id, "pipeline.tool_done", {"tool_key": key, "status": status, "result_count": count}))
        runner.stage_done.connect(lambda stage: self._update(job_id, "pipeline.stage_done", {"stage": stage}))
        runner.progress.connect(lambda completed, total: self._update(job_id, "pipeline.progress", {"completed": completed, "total": total}, progress=(completed, total)))
        runner.pipeline_done.connect(lambda session_id, success, message: self._finish(job_id, session_id, success, message))

    def _run(self, job_id: str, runner) -> None:
        with self._lock:
            job = self._jobs[job_id]
            job.status = "running"
            job.started_at = _now()
            self._append_event(job, "pipeline.started", {})
        try:
            runner.run()
            with self._lock:
                job = self._jobs[job_id]
                if job.status in ("running", "stopping"):
                    stopped = job.status == "stopping"
                    job.status = "stopped" if stopped else "completed"
                    job.completed_at = _now()
                    self._append_event(job, f"pipeline.{job.status}", {})
        except Exception as exc:
            with self._lock:
                job = self._jobs[job_id]
                job.status = "failed"
                job.message = str(exc)
                job.completed_at = _now()
                self._append_event(job, "pipeline.failed", {"message": str(exc)})
        finally:
            with self._lock:
                self._runners.pop(job_id, None)

    def _update(self, job_id: str, event_type: str, data: dict, session_id: str = "", progress: tuple[int, int] | None = None) -> None:
        with self._lock:
            job = self._jobs[job_id]
            if session_id:
                job.session_id = session_id
            if progress:
                job.progress_completed, job.progress_total = progress
            self._append_event(job, event_type, data)

    def _finish(self, job_id: str, session_id: str, success: bool, message: str) -> None:
        with self._lock:
            job = self._jobs[job_id]
            stopped = job.status == "stopping"
            job.status = "stopped" if stopped else ("completed" if success else "failed")
            job.session_id = session_id
            job.message = message
            job.completed_at = _now()
            self._append_event(job, f"pipeline.{job.status}", {"message": message})

    def _append_event(self, job: PipelineJob, event_type: str, data: dict) -> None:
        sequence = job.events[-1].sequence + 1 if job.events else 1
        job.events.append(PipelineEvent(sequence=sequence, type=event_type, timestamp=_now(), data=data))
        if len(job.events) > self._max_events:
            job.events = list(deque(job.events, maxlen=self._max_events))
