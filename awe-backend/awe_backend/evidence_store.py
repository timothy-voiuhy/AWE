from __future__ import annotations

import json
import secrets
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock

from .schemas import EvidenceInput, EvidenceRecord


class EvidenceNotFoundError(LookupError):
    pass


class EvidenceStore:
    filename = ".awe-evidence.json"

    def __init__(self, project_dir: Path):
        self.project_dir = project_dir
        self.path = project_dir / self.filename
        self._lock = RLock()

    def _read(self) -> dict:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {"evidence": []}
        except (FileNotFoundError, OSError, ValueError):
            return {"evidence": []}

    def _write(self, data: dict) -> None:
        self.project_dir.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(data, indent=2), encoding="utf-8")
        temporary.replace(self.path)

    def list(self, project_id: str, investigation_id: str = "", source_id: str = "", entity_id: str = "") -> list[EvidenceRecord]:
        with self._lock:
            records = [
                EvidenceRecord.model_validate(item)
                for item in self._read().get("evidence", [])
                if isinstance(item, dict) and item.get("project_id") == project_id
            ]
        if investigation_id:
            records = [item for item in records if item.investigation_id == investigation_id]
        if source_id:
            records = [item for item in records if item.source_id == source_id]
        if entity_id:
            records = [item for item in records if entity_id in item.entity_ids]
        return sorted(records, key=lambda item: item.created_at, reverse=True)

    def get(self, project_id: str, evidence_id: str) -> EvidenceRecord:
        for record in self.list(project_id):
            if record.id == evidence_id:
                return record
        raise EvidenceNotFoundError(evidence_id)

    def create(self, project_id: str, payload: EvidenceInput) -> EvidenceRecord:
        record = EvidenceRecord(
            id=secrets.token_hex(12),
            project_id=project_id,
            created_at=datetime.now(timezone.utc),
            **payload.model_dump(),
        )
        with self._lock:
            data = self._read()
            data.setdefault("evidence", []).append(record.model_dump(mode="json"))
            self._write(data)
        return record

    def delete(self, project_id: str, evidence_id: str) -> None:
        with self._lock:
            data = self._read()
            records = data.setdefault("evidence", [])
            kept = [item for item in records if not (item.get("project_id") == project_id and item.get("id") == evidence_id)]
            if len(kept) == len(records):
                raise EvidenceNotFoundError(evidence_id)
            data["evidence"] = kept
            self._write(data)
