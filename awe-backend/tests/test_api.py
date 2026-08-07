from pathlib import Path
from datetime import datetime, timezone

from fastapi.testclient import TestClient
from pymongo.errors import ServerSelectionTimeoutError
from bson import ObjectId

from awe_backend.api import (
    get_docker_service,
    get_intruder_service,
    get_job_manager,
    get_pipeline_catalog,
    get_project_store,
    get_repository_factory,
    get_replay_service,
    get_vault_service,
    get_proxy_control,
    get_websocket_client,
)
from awe_backend.main import create_app
from awe_backend.config import Settings
from awe_backend.projects import ProjectStore
from awe_backend.schemas import DockerContainer, IntruderResult, PipelineJob, PipelineStep, PipelineTemplate, RepeaterResponse
from awe_backend.vault import VaultService


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
        self.last_start = {}

    def start(self, project_id, pipeline_key, **kwargs):
        self.last_start = {"project_id": project_id, "pipeline_key": pipeline_key, **kwargs}
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
    deleted_sessions = []
    def list_sessions(self, limit):
        return [{
            "id": "session-1", "pipeline_key": "quick", "pipeline_name": "Quick",
            "target": "example.com", "status": "completed",
            "started_at": "2026-01-01T00:00:00+00:00", "completed_at": None,
            "params": {}, "in_scope": [], "out_of_scope": [],
        }][:limit]

    def get_session(self, session_id):
        return {"id": session_id, "pipeline_key": "quick", "target": "example.com", "in_scope": ["example.com"], "out_of_scope": []} if session_id == "session-1" else None

    def get_results(self, session_id, category=None, limit=0):
        return [{
            "id": "result-1", "session_id": session_id, "tool_run_id": "tool-1",
            "category": category or "http", "result_key": "https://example.com",
            "data": {"url": "https://example.com"}, "sources": ["httpx"],
            "created_at": "2026-01-01T00:00:00+00:00",
        }][:limit]

    def get_results_project(self, category=None):
        return self.get_results("session-1", category=category, limit=5000)

    def get_tool_runs(self, session_id):
        return [{"id":"run-1","session_id":session_id,"tool_key":"example","display_name":"Example","stage":0,"status":"failed","started_at":"2026-01-01T00:00:00+00:00","completed_at":None,"result_count":0,"error_msg":"exit 1","log_lines":["failed"]}]

    def delete_session(self, session_id):
        self.deleted_sessions.append(session_id)


class FakeTrafficCursor(list):
    def sort(self, *_): return self
    def limit(self, value): return FakeTrafficCursor(self[:value])


class FakeTrafficCollection:
    doc = {"_id": ObjectId(), "host": "example.com", "path": "/api", "method": "GET", "status_code": 200, "timestamp": "2026-01-01T00:00:00+00:00", "request": {"url": "https://example.com/api"}, "response": {"body": "ok"}}
    def find(self, query): return FakeTrafficCursor([self.doc])
    def find_one(self, query): return self.doc if query.get("_id") == self.doc["_id"] else None
    def delete_one(self, query):
        class Result: deleted_count = 1
        return Result()
    def delete_many(self, query):
        self.deleted_query = query
        class Result: deleted_count = 2
        return Result()


class FakeRepositoryFactory:
    def __call__(self, _): return FakeRepository()
    def traffic(self): return FakeTrafficCollection()
    def websocket_db(self): return FakeWebSocketDatabase()


class FakeWebSocketCollection:
    def __init__(self, rows): self.rows = rows
    def find(self, _): return FakeTrafficCursor(self.rows)


class FakeWebSocketDatabase:
    ws_connections = FakeWebSocketCollection([{"_id": ObjectId(), "host": "example.com", "path": "/socket", "opened_at": "2026-01-01", "closed_at": None, "frame_count": 1}])
    ws_frames = FakeWebSocketCollection([{"_id": ObjectId(), "conn_id": "connection-1", "direction": "client_to_server", "opcode_name": "text", "payload_text": "hello", "payload_len": 5, "timestamp": "2026-01-01"}])


class FakeReplayService:
    async def send(self, request):
        return RepeaterResponse(status_code=200, reason="OK", headers={"content-type": "text/plain"}, body=f"echo:{request.method}", elapsed_ms=4)


class FakeDockerService:
    def __init__(self):
        self.stopped = []
        self.removed = []

    def list(self):
        return [DockerContainer(id="abc123", name="awe_test", image="alpine", status="running", created="2026-01-01")]

    def stop(self, container_id):
        self.stopped.append(container_id)

    def remove(self, container_id):
        self.removed.append(container_id)


class FakeIntruderService:
    async def run(self, request):
        return [IntruderResult(sequence=1, payload=request.payloads[0], status_code=200, length=2, elapsed_ms=3)]


class FakeWebSocketClient:
    async def send(self, url, message): return f"echo:{message}"


class FakeProxyControl:
    def __init__(self): self.config = None; self.resolution = None
    def set_intercept(self, enabled, patterns): self.config = (enabled, patterns)
    def pending(self): return [{"id":"req-1","host":"example.com","method":"POST","url":"https://example.com/api","headers":[["content-type","text/plain"]],"body_b64":"aGk="}]
    def resolve(self, request_id, decision, headers, body_b64): self.resolution = (request_id, decision, headers, body_b64)

def test_health_and_project_endpoints(tmp_path: Path, monkeypatch):
    app = create_app(Settings(auth_enabled=False, workspace_dir=tmp_path))
    app.dependency_overrides[get_project_store] = lambda: ProjectStore(tmp_path)
    app.dependency_overrides[get_pipeline_catalog] = FakePipelineCatalog
    fake_jobs = FakeJobManager()
    app.dependency_overrides[get_job_manager] = lambda: fake_jobs
    app.dependency_overrides[get_repository_factory] = FakeRepositoryFactory
    app.dependency_overrides[get_replay_service] = FakeReplayService
    fake_docker = FakeDockerService()
    app.dependency_overrides[get_docker_service] = lambda: fake_docker
    app.dependency_overrides[get_vault_service] = lambda: VaultService("test-secret")
    app.dependency_overrides[get_intruder_service] = FakeIntruderService
    app.dependency_overrides[get_websocket_client] = FakeWebSocketClient
    fake_control = FakeProxyControl()
    app.dependency_overrides[get_proxy_control] = lambda: fake_control

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

        settings_payload = {
            "default_threads": 24,
            "default_rate_limit": 75,
            "default_concurrency": 8,
            "proxy_port": 9090,
            "upstream_proxy": "http://127.0.0.1:8080",
        }
        saved_settings = client.put(
            f"/api/v1/projects/{project['id']}/settings", json=settings_payload
        )
        assert saved_settings.status_code == 200
        assert client.get(
            f"/api/v1/projects/{project['id']}/settings"
        ).json() == settings_payload

        containers = client.get("/api/v1/docker/containers")
        assert containers.status_code == 200
        assert containers.json()[0]["name"] == "awe_test"
        assert client.post("/api/v1/docker/containers/abc123/stop").status_code == 204
        assert client.delete("/api/v1/docker/containers/abc123").status_code == 204
        assert fake_docker.stopped == ["abc123"]
        assert fake_docker.removed == ["abc123"]

        vault_payload = {
            "name": "API key",
            "kind": "token",
            "value": "secret-value",
        }
        vault_item = client.post(
            f"/api/v1/projects/{project['id']}/vault", json=vault_payload
        )
        assert vault_item.status_code == 201
        item_id = vault_item.json()["id"]
        assert client.get(f"/api/v1/projects/{project['id']}/vault").json()[0]["value"] == "secret-value"
        assert client.delete(
            f"/api/v1/projects/{project['id']}/vault/{item_id}"
        ).status_code == 204

        intruder = client.post(f"/api/v1/projects/{project['id']}/intruder/runs", json={"method":"GET","url":"https://example.com/users/§payload§","payloads":["admin"],"placeholder":"§payload§"})
        assert intruder.status_code == 200
        assert intruder.json()[0]["payload"] == "admin"
        outside_intruder = client.post(f"/api/v1/projects/{project['id']}/intruder/runs", json={"method":"GET","url":"https://outside.test/§payload§","payloads":["x"]})
        assert outside_intruder.status_code == 403

        sockets = client.get(f"/api/v1/projects/{project['id']}/websockets")
        assert sockets.status_code == 200
        assert sockets.json()[0]["host"] == "example.com"
        frames = client.get(f"/api/v1/projects/{project['id']}/websockets/connection-1/frames")
        assert frames.json()[0]["payload_text"] == "hello"
        sent = client.post(f"/api/v1/projects/{project['id']}/websockets/send", json={"url":"wss://example.com/socket","message":"hello"})
        assert sent.json() == {"reply":"echo:hello"}

        assert client.put(f"/api/v1/projects/{project['id']}/intercept", json={"enabled":True,"patterns":["example\\.com$"]}).status_code == 204
        assert fake_control.config == (True, ["example\\.com$"])
        pending = client.get(f"/api/v1/projects/{project['id']}/intercept/pending")
        assert pending.json()[0]["id"] == "req-1"
        assert client.post(f"/api/v1/projects/{project['id']}/intercept/req-1/resolve", json={"decision":"forward","headers":[],"body_b64":""}).status_code == 204
        assert fake_control.resolution[1] == "forward"

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

        project_results = client.get(f"/api/v1/projects/{project['id']}/results")
        assert project_results.status_code == 200
        assert project_results.json()[0]["sources"] == ["httpx"]

        tool_runs = client.get(f"/api/v1/projects/{project['id']}/sessions/session-1/tool-runs")
        assert tool_runs.status_code == 200
        assert tool_runs.json()[0]["error_msg"] == "exit 1"

        targeted = client.post(f"/api/v1/projects/{project['id']}/pipeline-runs", json={"pipeline_key":"quick","session_id":"session-1","tool_keys":["example"]})
        assert targeted.status_code == 202
        assert fake_jobs.last_start["tool_keys"] == ["example"]

        traffic = client.get(f"/api/v1/projects/{project['id']}/traffic")
        assert traffic.status_code == 200
        assert traffic.json()[0]["host"] == "example.com"
        traffic_id = traffic.json()[0]["id"]
        detail = client.get(f"/api/v1/projects/{project['id']}/traffic/{traffic_id}")
        assert detail.status_code == 200
        assert client.delete(f"/api/v1/projects/{project['id']}/traffic/{traffic_id}").status_code == 204
        subtree = client.delete(f"/api/v1/projects/{project['id']}/traffic", params={"host":"example.com","path_prefix":"api"})
        assert subtree.status_code == 204
        monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2] / "src"))
        from proxy.traffic_extractor import TrafficExtractor
        import workers.proxy_extractor_worker as extractor_worker
        monkeypatch.setattr(TrafficExtractor, "extract", lambda self, collection, scope: ({"crawl": [object()]}, {"jwt": [], "graphql": []}))
        monkeypatch.setattr(extractor_worker, "_write_results", lambda *args: {"session_id":"proxy-session","run_id":"proxy-run","written_by_category":{"crawl":1},"review_counts":{}})
        synced = client.post(f"/api/v1/projects/{project['id']}/traffic/sync-results")
        assert synced.status_code == 200
        assert synced.json()["extracted_counts"] == {"crawl": 1}

        replayed = client.post(f"/api/v1/projects/{project['id']}/repeater/send", json={"method": "POST", "url": "https://example.com/api", "body": "hello"})
        assert replayed.status_code == 200
        assert replayed.json()["body"] == "echo:POST"
        blocked_replay = client.post(f"/api/v1/projects/{project['id']}/repeater/send", json={"url": "https://outside.test/"})
        assert blocked_replay.status_code == 403

        deleted = client.delete(f"/api/v1/projects/{project['id']}/sessions/session-1")
        assert deleted.status_code == 204

        def unavailable_repository(_):
            raise ServerSelectionTimeoutError("offline")

        app.dependency_overrides[get_repository_factory] = lambda: unavailable_repository
        unavailable = client.get(f"/api/v1/projects/{project['id']}/sessions")
        assert unavailable.status_code == 503
        assert unavailable.json() == {"detail": "Database unavailable"}

        missing = client.get("/api/v1/projects/not-a-valid-id")
        assert missing.status_code == 404
