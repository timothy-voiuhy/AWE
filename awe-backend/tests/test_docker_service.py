from types import SimpleNamespace

import pytest

from awe_backend.docker_service import DockerService


class FakeContainer:
    def __init__(self, name="awe_tool", status="exited"):
        self.name = name
        self.status = status
        self.short_id = "short"
        self.id = "full"
        self.image = SimpleNamespace(tags=["awe/tool:latest"], short_id="image")
        self.attrs = {"State": {"StartedAt": "2026-01-01T00:00:00Z"}}
        self.started = False
        self.stopped = False
        self.removed = False

    def start(self): self.started = True
    def stop(self, timeout=5): self.stopped = True
    def remove(self, force=False): self.removed = True
    def logs(self, tail=500): return b"one\ntwo\n"


class FakeContainers:
    def __init__(self, items): self.items = items
    def get(self, container_id): return next(item for item in self.items if item.id == container_id or item.short_id == container_id)
    def list(self, **kwargs): return self.items


def service_with(*containers):
    service = DockerService()
    client = SimpleNamespace(containers=FakeContainers(list(containers)))
    service._client = lambda: client
    return service


def test_service_container_can_restart_but_not_be_removed():
    mongo = FakeContainer("awe_mongodb")
    service = service_with(mongo)
    service.start(mongo.id)
    assert mongo.started
    with pytest.raises(PermissionError, match="cannot be removed"):
        service.remove(mongo.id)


def test_non_service_container_cannot_use_restart_endpoint():
    tool = FakeContainer()
    with pytest.raises(PermissionError, match="service containers"):
        service_with(tool).start(tool.id)


def test_prune_preserves_services_and_removes_stopped_tools():
    mongo = FakeContainer("awe_mongodb")
    tool = FakeContainer()
    assert service_with(mongo, tool).prune() == 1
    assert not mongo.removed
    assert tool.removed


def test_container_listing_marks_services_and_logs_are_scoped():
    mongo = FakeContainer("awe_mongodb", "running")
    item = service_with(mongo).list()[0]
    assert item.is_service is True
    assert service_with(mongo).logs(mongo.id) == ["one", "two"]
    outside = FakeContainer("other")
    with pytest.raises(PermissionError):
        service_with(outside).logs(outside.id)
