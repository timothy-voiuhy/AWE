"""Filesystem-backed project catalogue.

This deliberately exposes opaque IDs instead of server paths. Existing AWE
project directories can be adopted later by a one-time migration without
changing the public API.
"""

import json
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path

from .schemas import Project, ProjectCreate, ProjectUpdate, ScopeConfig

_METADATA_FILE = ".awe-project.json"
_SCOPE_FILE = ".awe-scope.json"
_PROJECT_ID = re.compile(r"^[a-z0-9]{16}$")


class ProjectNotFoundError(LookupError):
    pass


class ProjectStore:
    def __init__(self, workspace_dir: Path):
        self.workspace_dir = workspace_dir.resolve()

    def list(self) -> list[Project]:
        if not self.workspace_dir.exists():
            return []
        projects: list[Project] = []
        for metadata in self.workspace_dir.glob(f"*/{_METADATA_FILE}"):
            try:
                projects.append(self._read(metadata.parent.name))
            except (OSError, ValueError, KeyError, json.JSONDecodeError):
                continue
        return sorted(projects, key=lambda item: item.updated_at, reverse=True)

    def create(self, payload: ProjectCreate) -> Project:
        self.workspace_dir.mkdir(parents=True, exist_ok=True)
        while True:
            project_id = secrets.token_hex(8)
            project_dir = self.workspace_dir / project_id
            try:
                project_dir.mkdir(exist_ok=False)
                break
            except FileExistsError:
                continue

        now = datetime.now(timezone.utc)
        project = Project(
            id=project_id,
            name=payload.name.strip(),
            target=payload.target.strip(),
            created_at=now,
            updated_at=now,
        )
        self._write(project)
        return project

    def get(self, project_id: str) -> Project:
        return self._read(project_id)

    def project_dir(self, project_id: str) -> Path:
        project_dir = self._project_dir(project_id)
        if not (project_dir / _METADATA_FILE).is_file():
            raise ProjectNotFoundError(project_id)
        return project_dir

    def update(self, project_id: str, payload: ProjectUpdate) -> Project:
        project = self._read(project_id)
        changes = payload.model_dump(exclude_unset=True)
        if "name" in changes:
            changes["name"] = changes["name"].strip()
        if "target" in changes:
            changes["target"] = changes["target"].strip()
        updated = project.model_copy(
            update={**changes, "updated_at": datetime.now(timezone.utc)}
        )
        self._write(updated)
        return updated

    def get_scope(self, project_id: str) -> ScopeConfig:
        project_dir = self._project_dir(project_id)
        if not (project_dir / _METADATA_FILE).is_file():
            raise ProjectNotFoundError(project_id)
        scope_file = project_dir / _SCOPE_FILE
        try:
            return ScopeConfig.model_validate_json(scope_file.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return ScopeConfig()

    def put_scope(self, project_id: str, scope: ScopeConfig) -> ScopeConfig:
        project_dir = self._project_dir(project_id)
        if not (project_dir / _METADATA_FILE).is_file():
            raise ProjectNotFoundError(project_id)
        scope_file = project_dir / _SCOPE_FILE
        temporary = scope_file.with_suffix(".tmp")
        temporary.write_text(scope.model_dump_json(indent=2), encoding="utf-8")
        temporary.replace(scope_file)
        return scope

    def _project_dir(self, project_id: str) -> Path:
        if not _PROJECT_ID.fullmatch(project_id):
            raise ProjectNotFoundError(project_id)
        return self.workspace_dir / project_id

    def _read(self, project_id: str) -> Project:
        metadata = self._project_dir(project_id) / _METADATA_FILE
        try:
            return Project.model_validate_json(metadata.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise ProjectNotFoundError(project_id) from exc

    def _write(self, project: Project) -> None:
        metadata = self._project_dir(project.id) / _METADATA_FILE
        temporary = metadata.with_suffix(".tmp")
        temporary.write_text(project.model_dump_json(indent=2), encoding="utf-8")
        temporary.replace(metadata)
