from pathlib import Path
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from awe_backend.api import (
    get_job_manager,
    get_pipeline_catalog,
    get_project_store,
    get_repository_factory,
)
from awe_backend.main import create_app
from awe_backend.config import Settings
from awe_backend.projects import ProjectStore
from awe_backend.schemas import PipelineJob, PipelineStep, PipelineTemplate


class FakePipelineCatalog:
    def list(self):
        return [
            PipelineTemplate(
                key="quick",
                name="Quick scan",
                description="A test pipeline",
                category="quick",
                steps=[
                    PipelineStep(
                        tool_key="example",
                        stage=0,
                        condition="always",
                        input_category=None,
                    )
                ],
            )
        ]


class FakeJobManager:
    def __init__(self):
        self.jobs = {}

    def start(self, project_id, pipeline_key, **_):
        job = PipelineJob(
            id="job-1",
            project_id=project_id,
            pipeline_key=pipeline_key,
            status="queued",
            created_at=datetime.now(timezone.utc),
        )
        self.jobs[job.id] = job
        return job

    def get(self, job_id):
        return self.jobs[job_id]

    def list_for_project(self, project_id):
        return [job for job in self.jobs.values() if job.project_id == project_id]

    def stop(self, job_id):
        job = self.jobs[job_id]
        job.status = "stopping"
        return job


class FakeRepository:
    def list_sessions(self, limit):
        return [{
            "id": "session-1", "pipeline_key": "quick", "pipeline_name": "Quick",
            "target": "example.com", "status": "completed",
            "started_at": "2026-01-01T00:00:00+00:00", "completed_at": None,
            "params": {}, "in_scope": [], "out_of_scope": [],
        }][:limit]

    def get_session(self, session_id):
        return {"id": session_id} if session_id == "session-1" else None

    def get_results(self, session_id, category=None, limit=0):
        return [{
            "id": "result-1", "session_id": session_id, "tool_run_id": "tool-1",
            "category": category or "http", "result_key": "https://example.com",
            "data": {"url": "https://example.com"}, "sources": ["httpx"],
            "created_at": "2026-01-01T00:00:00+00:00",
        }][:limit]

def test_health_and_project_endpoints(tmp_path: Path):
    app = create_app(Settings(auth_enabled=False, workspace_dir=tmp_path))
    app.dependency_overrides[get_project_store] = lambda: ProjectStore(tmp_path)
    app.dependency_overrides[get_pipeline_catalog] = FakePipelineCatalog
    fake_jobs = FakeJobManager()
    app.dependency_overrides[get_job_manager] = lambda: fake_jobs
    app.dependency_overrides[get_repository_factory] = lambda: lambda _: FakeRepository()

    with TestClient(app) as client:
        health = client.get("/api/v1/health")
        assert health.status_code == 200
        assert health.json()["status"] == "ok"

        pipelines = client.get("/api/v1/pipelines")
        assert pipelines.status_code == 200
        assert pipelines.json()[0]["key"] == "quick"

        created = client.post(
            "/api/v1/projects",
            json={"name": "Example", "target": "https://example.com"},
        )
        assert created.status_code == 201
        project = created.json()

        listed = client.get("/api/v1/projects")
        assert listed.status_code == 200
        assert listed.json() == [project]

        renamed = client.patch(
            f"/api/v1/projects/{project['id']}", json={"name": "Renamed"}
        )
        assert renamed.status_code == 200
        assert renamed.json()["name"] == "Renamed"

        default_scope = client.get(f"/api/v1/projects/{project['id']}/scope")
        assert default_scope.json() == {"entries": [], "include_subdomains": True}

        scope = {
            "entries": [
                {"value": "example.com", "entry_type": "domain", "in_scope": True},
                {"value": "admin.example.com", "entry_type": "domain", "in_scope": False},
            ],
            "include_subdomains": True,
        }
        saved_scope = client.put(
            f"/api/v1/projects/{project['id']}/scope", json=scope
        )
        assert saved_scope.status_code == 200
        assert saved_scope.json() == scope

        started = client.post(
            f"/api/v1/projects/{project['id']}/pipeline-runs",
            json={"pipeline_key": "quick", "params": {}},
        )
        assert started.status_code == 202
        assert started.json()["status"] == "queued"

        with client.websocket_connect(
            f"/api/v1/projects/{project['id']}/pipeline-runs/job-1/events"
        ) as websocket:
            update = websocket.receive_json()
            assert update["job"]["id"] == "job-1"

        runs = client.get(f"/api/v1/projects/{project['id']}/pipeline-runs")
        assert len(runs.json()) == 1

        cancelled = client.post(
            f"/api/v1/projects/{project['id']}/pipeline-runs/job-1/cancel"
        )
        assert cancelled.json()["status"] == "stopping"

        sessions = client.get(f"/api/v1/projects/{project['id']}/sessions")
        assert sessions.status_code == 200
        assert sessions.json()[0]["id"] == "session-1"

        results = client.get(
            f"/api/v1/projects/{project['id']}/sessions/session-1/results?category=http"
        )
        assert results.status_code == 200
        assert results.json()[0]["result_key"] == "https://example.com"

        missing = client.get("/api/v1/projects/not-a-valid-id")
        assert missing.status_code == 404
