import os
import time
import pytest
from awe_backend.intruder_jobs import IntruderJobManager
from awe_backend.schemas import IntruderRequest, IntruderResult

pytestmark = pytest.mark.skipif(not os.getenv("AWE_TEST_MONGO_URI"), reason="MongoDB integration test")

class Service:
    async def run(self, request, cancel_event=None, progress=None):
        rows=[]
        for sequence,payload in enumerate(request.payloads,1):
            if cancel_event.is_set(): break
            row=IntruderResult(sequence=sequence,payload=payload,status_code=200,length=2,elapsed_ms=1)
            rows.append(row);progress(row)
        return rows

def test_intruder_job_lifecycle(tmp_path):
    manager=IntruderJobManager(Service(), tmp_path, os.environ["AWE_TEST_MONGO_URI"])
    job=manager.start('project',IntruderRequest(url='https://example.com/?q=§payload§',payloads=['a','b']))
    for _ in range(100):
        job=manager.get("project", job.id)
        if job.status=='completed': break
        time.sleep(.01)
    assert job.status=='completed'
    assert job.completed==2
    assert manager.list('project')[0].id==job.id


def test_intruder_jobs_survive_manager_restart(tmp_path):
    manager = IntruderJobManager(Service(), tmp_path, os.environ["AWE_TEST_MONGO_URI"])
    job = manager.start(
        "project",
        IntruderRequest(url="https://example.com/?q=§payload§", payloads=["persisted"]),
    )
    for _ in range(100):
        job = manager.get("project", job.id)
        if job.status == "completed":
            break
        time.sleep(.01)

    restored = IntruderJobManager(Service(), tmp_path, os.environ["AWE_TEST_MONGO_URI"]).get("project", job.id)
    assert restored.status == "completed"
    assert restored.results[0].payload == "persisted"


def test_unfinished_job_is_marked_failed_after_restart(tmp_path):
    manager = IntruderJobManager(Service(), tmp_path, os.environ["AWE_TEST_MONGO_URI"])
    manager._db("project").intruder_jobs.insert_one({"_id": "interrupted", "id": "interrupted", "project_id": "project", "status": "running", "created_at": "2026-01-01T00:00:00+00:00", "completed_at": None, "total": 1, "completed": 0, "error": "", "request": {}})

    restored = IntruderJobManager(Service(), tmp_path, os.environ["AWE_TEST_MONGO_URI"]).get("project", "interrupted")
    assert restored.status == "failed"
    assert "restarted" in restored.error
    assert restored.completed_at is not None
