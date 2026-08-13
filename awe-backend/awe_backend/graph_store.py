"""Project-scoped persistence for Maltego-style investigations.

The derived graph remains owned by the existing result projection. This store
only persists the investigation shell and analyst-created graph objects, so a
new scan cannot erase a user's work.
"""
from __future__ import annotations

import json
import secrets
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock

from .schemas import (
    GraphEntity,
    GraphInvestigation,
    GraphRelationship,
    InvestigationCreate,
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


class InvestigationNotFoundError(LookupError):
    pass


class GraphRevisionError(RuntimeError):
    pass


class InvestigationStore:
    """Small atomic JSON store suitable for project-local graph state.

    A Mongo-backed implementation can replace this class later without
    changing the API contract. Keeping investigation edits in project storage
    also makes local workspaces portable and preserves existing AWE behavior.
    """

    filename = ".awe-investigations.json"

    def __init__(self, project_dir: Path):
        self.project_dir = project_dir
        self.path = project_dir / self.filename
        self._lock = RLock()

    def _read(self) -> dict:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {"investigations": []}
        except (FileNotFoundError, OSError, ValueError):
            return {"investigations": []}

    def _write(self, data: dict) -> None:
        self.project_dir.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(data, indent=2), encoding="utf-8")
        temporary.replace(self.path)

    @staticmethod
    def _investigation(raw: dict) -> GraphInvestigation:
        return GraphInvestigation.model_validate(raw)

    def list(self, project_id: str) -> list[GraphInvestigation]:
        with self._lock:
            rows = [self._investigation(item) for item in self._read().get("investigations", [])]
        return sorted((row for row in rows if row.project_id == project_id), key=lambda row: row.updated_at, reverse=True)

    def get(self, project_id: str, investigation_id: str) -> GraphInvestigation:
        for row in self.list(project_id):
            if row.id == investigation_id:
                return row
        raise InvestigationNotFoundError(investigation_id)

    def create(self, project_id: str, payload: InvestigationCreate, root_ids: list[str] | None = None) -> GraphInvestigation:
        now = _now()
        row = GraphInvestigation(
            id=secrets.token_hex(12), project_id=project_id, name=payload.name.strip(),
            created_at=now, updated_at=now, root_ids=root_ids or [],
        )
        with self._lock:
            data = self._read()
            data.setdefault("investigations", []).append(row.model_dump(mode="json"))
            self._write(data)
        return row

    def save(self, row: GraphInvestigation, expected_revision: int | None = None) -> GraphInvestigation:
        with self._lock:
            data = self._read()
            rows = data.setdefault("investigations", [])
            for index, item in enumerate(rows):
                if item.get("id") != row.id:
                    continue
                current = self._investigation(item)
                if expected_revision is not None and current.revision != expected_revision:
                    raise GraphRevisionError(f"Investigation changed (expected {expected_revision}, got {current.revision})")
                updated = row.model_copy(update={"revision": current.revision + 1, "updated_at": _now()})
                rows[index] = updated.model_dump(mode="json")
                self._write(data)
                return updated
        raise InvestigationNotFoundError(row.id)

    def delete(self, project_id: str, investigation_id: str) -> None:
        with self._lock:
            data = self._read()
            before = len(data.get("investigations", []))
            data["investigations"] = [
                item for item in data.get("investigations", [])
                if not (item.get("id") == investigation_id and item.get("project_id") == project_id)
            ]
            if len(data["investigations"]) == before:
                raise InvestigationNotFoundError(investigation_id)
            self._write(data)

    def entities(self, row: GraphInvestigation) -> list[GraphEntity]:
        return [GraphEntity.model_validate(item) for item in self._read().get("entities", {}).get(row.id, [])]

    def relationships(self, row: GraphInvestigation) -> list[GraphRelationship]:
        return [GraphRelationship.model_validate(item) for item in self._read().get("relationships", {}).get(row.id, [])]

    def add_entity(self, row: GraphInvestigation, entity: GraphEntity) -> GraphEntity:
        with self._lock:
            data = self._read()
            entities = data.setdefault("entities", {}).setdefault(row.id, [])
            entities.append(entity.model_dump(mode="json"))
            self._write(data)
        return entity

    def update_entity(self, row: GraphInvestigation, entity: GraphEntity) -> GraphEntity:
        with self._lock:
            data = self._read()
            entities = data.setdefault("entities", {}).setdefault(row.id, [])
            for index, item in enumerate(entities):
                if item.get("id") == entity.id:
                    entities[index] = entity.model_dump(mode="json")
                    self._write(data)
                    return entity
        raise KeyError(entity.id)

    def delete_entity(self, row: GraphInvestigation, entity_id: str) -> None:
        with self._lock:
            data = self._read()
            entities = data.setdefault("entities", {}).setdefault(row.id, [])
            data.setdefault("entities", {})[row.id] = [item for item in entities if item.get("id") != entity_id]
            relationships = data.setdefault("relationships", {}).setdefault(row.id, [])
            data["relationships"][row.id] = [item for item in relationships if item.get("source_id") != entity_id and item.get("target_id") != entity_id]
            self._write(data)

    def add_relationship(self, row: GraphInvestigation, relationship: GraphRelationship) -> GraphRelationship:
        with self._lock:
            data = self._read()
            relationships = data.setdefault("relationships", {}).setdefault(row.id, [])
            relationships.append(relationship.model_dump(mode="json"))
            self._write(data)
        return relationship

    def delete_relationship(self, row: GraphInvestigation, relationship_id: str) -> None:
        with self._lock:
            data = self._read()
            relationships = data.setdefault("relationships", {}).setdefault(row.id, [])
            data["relationships"][row.id] = [item for item in relationships if item.get("id") != relationship_id]
            self._write(data)

