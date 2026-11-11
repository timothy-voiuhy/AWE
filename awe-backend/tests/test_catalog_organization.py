import pytest
from fastapi.testclient import TestClient
from awe_backend.catalog_organization import CatalogOrganization
from awe_backend.config import Settings
from awe_backend.main import create_app
from awe_backend.routes.catalog_organization import context


ITEMS = {"tool:nginx_rift": "Exploits", "tool:php2shell": "Exploits", "tool:httpx": "subdomain", "transform:project:composite:test": "subdomain"}


def category(data, name):
    return next(item for item in data["categories"] if item["name"] == name)


def test_nested_placement_survives_reload_and_parent_rename(tmp_path):
    service = CatalogOrganization(tmp_path)
    exploits = category(service.snapshot(ITEMS), "Exploits")["id"]
    web = category(service.save_category(ITEMS, "Web", exploits), "Web")["id"]
    php = category(service.save_category(ITEMS, "PHP", web), "PHP")["id"]
    service.assign(ITEMS, ["tool:php2shell", "tool:nginx_rift"], php)
    service.save_category(ITEMS, "Offensive research", None, exploits)
    reloaded = CatalogOrganization(tmp_path).snapshot(ITEMS)
    assert reloaded["assignments"]["tool:php2shell"] == php
    assert category(reloaded, "Web")["parent_id"] == exploits
    assert reloaded["defaults"]["Exploits"] == exploits
    assert reloaded["placements"]["tool:php2shell"] == php
    assert reloaded["placements"]["tool:httpx"] == reloaded["defaults"]["subdomain"]
    assert not any(item["name"] == "Exploits" for item in reloaded["categories"])


def test_invalid_changes_are_atomic_and_deletion_preserves_children(tmp_path):
    service = CatalogOrganization(tmp_path)
    exploits = category(service.snapshot(ITEMS), "Exploits")["id"]
    web = category(service.save_category(ITEMS, "Web", exploits), "Web")["id"]
    before = service.path.read_bytes()
    for action in [
        lambda: service.save_category(ITEMS, "Exploits", web, exploits),
        lambda: service.save_category(ITEMS, " web ", exploits),
        lambda: service.save_category(ITEMS, " ", None),
        lambda: service.assign(ITEMS, ["tool:missing"], web),
        lambda: service.delete_category(ITEMS, "uncategorized"),
    ]:
        with pytest.raises(ValueError):
            action()
        assert service.path.read_bytes() == before
    service.assign(ITEMS, ["tool:php2shell"], exploits)
    result = service.delete_category(ITEMS, exploits)
    assert category(result, "Web")["parent_id"] is None
    assert result["assignments"]["tool:php2shell"] == "uncategorized"
    assert service.snapshot(ITEMS)["defaults"]["Exploits"] == "uncategorized"
    assert not any(item["name"] == "Exploits" for item in service.snapshot(ITEMS)["categories"])


def test_nesting_limit_and_parent_validation(tmp_path):
    service = CatalogOrganization(tmp_path)
    parent = None
    for index in range(8):
        parent = category(service.save_category(ITEMS, f"Level {index}", parent), f"Level {index}")["id"]
    with pytest.raises(ValueError, match="eight levels"):
        service.save_category(ITEMS, "Too deep", parent)
    with pytest.raises(ValueError, match="does not exist"):
        service.save_category(ITEMS, "Orphan", "missing")


def test_category_api_crud_and_bulk_assignment(tmp_path):
    app = create_app(Settings(auth_enabled=False, workspace_dir=tmp_path))
    service = CatalogOrganization(tmp_path)
    app.dependency_overrides[context] = lambda: (service, ITEMS)
    client = TestClient(app)
    base = "/api/v1/projects/test/catalog"
    initial = client.get(f"{base}/organization")
    assert initial.status_code == 200
    created = client.post(f"{base}/categories", json={"name": "Research", "parent_id": None})
    assert created.status_code == 201
    identity = category(created.json(), "Research")["id"]
    moved = client.put(f"{base}/assignments", json={"item_keys": ["tool:httpx", "transform:project:composite:test"], "category_id": identity})
    assert moved.status_code == 200
    assert set(moved.json()["assignments"].values()) == {identity}
    assert client.patch(f"{base}/categories/{identity}", json={"name": "Renamed", "parent_id": None}).status_code == 200
    assert client.put(f"{base}/assignments", json={"item_keys": ["missing"], "category_id": identity}).status_code == 422
    assert client.patch(f"{base}/categories/missing", json={"name": "x"}).status_code == 404
    deleted = client.delete(f"{base}/categories/{identity}")
    assert deleted.status_code == 200
    assert set(deleted.json()["assignments"].values()) == {"uncategorized"}
