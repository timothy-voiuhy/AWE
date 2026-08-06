import threading
import time
from pathlib import Path
from types import SimpleNamespace

from awe_backend.jobs import PipelineJobManager


class Hook:
    def __init__(self):
        self.callbacks = []

    def connect(self, callback):
        self.callbacks.append(callback)

    def emit(self, *args):
        for callback in self.callbacks:
            callback(*args)


class FakeRunner:
    def __init__(self, fail=False, block=False, **_):
        self.fail = fail
        self.block = block
        self.stopped = threading.Event()
        for name in (
            "session_started", "step_started", "step_log", "step_done",
            "stage_done", "pipeline_done", "progress",
        ):
            setattr(self, name, Hook())

    def run(self):
        self.session_started.emit("session-1")
        self.step_started.emit("tool", "Test Tool", 0)
        self.step_log.emit("tool", "working")
        self.progress.emit(1, 1)
        if self.fail:
            raise RuntimeError("runner failed")
        if self.block:
            self.stopped.wait(timeout=2)
        self.step_done.emit("tool", "stopped" if self.stopped.is_set() else "completed", 1)
        self.pipeline_done.emit("session-1", not self.stopped.is_set(), "done")

    def stop(self):
        self.stopped.set()


def wait_for_terminal(manager, job_id):
    for _ in range(100):
        job = manager.get(job_id)
        if job.status in ("completed", "failed", "stopped"):
            return job
        time.sleep(0.01)
    raise AssertionError("job did not finish")


def manager_with_runner(runner):
    return PipelineJobManager(
        Path("src"),
        "mongodb://unused",
        template_loader=lambda _: SimpleNamespace(key="test"),
        runner_factory=lambda **_: runner,
    )


def test_job_records_ordered_events_and_completion(tmp_path):
    manager = manager_with_runner(FakeRunner())
    job = manager.start("project", tmp_path, "test", "example.com", {}, [], [])
    finished = wait_for_terminal(manager, job.id)

    assert finished.status == "completed"
    assert finished.session_id == "session-1"
    assert (finished.progress_completed, finished.progress_total) == (1, 1)
    assert [event.sequence for event in finished.events] == list(range(1, len(finished.events) + 1))
    assert any(event.type == "pipeline.tool_log" for event in finished.events)


def test_job_captures_failure(tmp_path):
    manager = manager_with_runner(FakeRunner(fail=True))
    job = manager.start("project", tmp_path, "test", "example.com", {}, [], [])
    finished = wait_for_terminal(manager, job.id)

    assert finished.status == "failed"
    assert finished.message == "runner failed"


def test_job_can_be_cancelled(tmp_path):
    runner = FakeRunner(block=True)
    manager = manager_with_runner(runner)
    job = manager.start("project", tmp_path, "test", "example.com", {}, [], [])
    manager.stop(job.id)
    finished = wait_for_terminal(manager, job.id)

    assert finished.status == "stopped"
    assert runner.stopped.is_set()
