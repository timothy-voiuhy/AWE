"""Stores API handlers and helpers."""

from ..evidence_store import EvidenceStore
from ..graph_store import InvestigationStore
from ..schemas import EvidenceInput
from ..schemas import EvidenceRecord
from pathlib import Path


def _graph_store(project_dir: Path) -> InvestigationStore:
    return InvestigationStore(project_dir)


def _evidence_store(project_dir: Path) -> EvidenceStore:
    return EvidenceStore(project_dir)


def _create_evidence_record(
    project_id: str,
    project_dir: Path,
    payload: EvidenceInput,
) -> EvidenceRecord | None:
    try:
        return _evidence_store(project_dir).create(project_id, payload)
    except (OSError, ValueError):
        return None
