from pathlib import Path

import pytest

from awe_backend.projects import ProjectNotFoundError, ProjectStore
from awe_backend.schemas import ProjectCreate, ProjectUpdate, ScopeConfig, ScopeEntry


def test_project_lifecycle(tmp_path: Path):
    store = ProjectStore(tmp_path)

    created = store.create(ProjectCreate(name="Example", target="https://example.com"))

    assert len(created.id) == 16
    assert store.get(created.id).target == "https://example.com"
    assert store.list() == [created]

    updated = store.update(created.id, ProjectUpdate(name="Renamed"))
    assert updated.name == "Renamed"
    assert updated.target == created.target
    assert updated.updated_at >= created.updated_at

    assert store.get_scope(created.id) == ScopeConfig()
    scope = ScopeConfig(entries=[ScopeEntry(value="example.com")])
    assert store.put_scope(created.id, scope) == scope
    assert store.get_scope(created.id) == scope


def test_project_ids_cannot_escape_workspace(tmp_path: Path):
    store = ProjectStore(tmp_path)

    with pytest.raises(ProjectNotFoundError):
        store.get("../../outside")
