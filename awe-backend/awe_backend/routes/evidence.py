"""Evidence API handlers and helpers."""

from ..evidence_store import EvidenceNotFoundError
from ..projects import ProjectNotFoundError
from ..projects import ProjectStore
from ..schemas import EvidenceInput
from ..schemas import EvidenceRecord
from fastapi import Depends
from fastapi import HTTPException
from fastapi import Response
from fastapi import status
from .dependencies import get_project_store
from .stores import _evidence_store
from fastapi import APIRouter

router = APIRouter()


@router.get("/projects/{project_id}/evidence", response_model=list[EvidenceRecord], tags=["evidence"])
def list_evidence(
    project_id: str,
    investigation_id: str = "",
    source_id: str = "",
    entity_id: str = "",
    store: ProjectStore = Depends(get_project_store),
) -> list[EvidenceRecord]:
    try:
        project_dir = store.project_dir(project_id)
        return _evidence_store(project_dir).list(project_id, investigation_id, source_id, entity_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc


@router.post("/projects/{project_id}/evidence", response_model=EvidenceRecord, status_code=201, tags=["evidence"])
def create_evidence(project_id: str, payload: EvidenceInput, store: ProjectStore = Depends(get_project_store)) -> EvidenceRecord:
    try:
        project_dir = store.project_dir(project_id)
        return _evidence_store(project_dir).create(project_id, payload)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc


@router.get("/projects/{project_id}/evidence/{evidence_id}", response_model=EvidenceRecord, tags=["evidence"])
def get_evidence(project_id: str, evidence_id: str, store: ProjectStore = Depends(get_project_store)) -> EvidenceRecord:
    try:
        project_dir = store.project_dir(project_id)
        return _evidence_store(project_dir).get(project_id, evidence_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc
    except EvidenceNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Evidence not found") from exc


@router.delete("/projects/{project_id}/evidence/{evidence_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["evidence"])
def delete_evidence(project_id: str, evidence_id: str, store: ProjectStore = Depends(get_project_store)) -> Response:
    try:
        project_dir = store.project_dir(project_id)
        _evidence_store(project_dir).delete(project_id, evidence_id)
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc
    except EvidenceNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Evidence not found") from exc
