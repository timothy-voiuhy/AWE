"""Traffic API handlers and helpers."""

from ..config import Settings
from ..config import get_settings
from ..projects import ProjectNotFoundError
from ..projects import ProjectStore
from ..repositories import LegacyRepositoryFactory
from ..schemas import EvidenceInput
from ..schemas import EvidenceRecord
from ..schemas import TrafficEntry
from bson import ObjectId
from fastapi import Depends
from fastapi import HTTPException
from fastapi import Response
from fastapi import status
from pymongo.errors import PyMongoError
import re
from .dependencies import get_project_store, get_repository_factory
from .stores import _evidence_store
from .traffic_helpers import _traffic_belongs_to_project, _traffic_entry, _traffic_project_query, _traffic_summary
from fastapi import APIRouter

router = APIRouter()


@router.get("/projects/{project_id}/traffic", response_model=list[TrafficEntry], tags=["proxy"])
def list_traffic(
    project_id: str,
    host: str | None = None,
    method: str | None = None,
    limit: int = 5000,
    store: ProjectStore = Depends(get_project_store),
    repositories: LegacyRepositoryFactory = Depends(get_repository_factory),
) -> list[TrafficEntry]:
    try:
        project = store.get(project_id)
        scope = store.get_scope(project_id)
        # External browsers do not all support proxy credentials.  The proxy
        # therefore keeps those captures unassigned instead of guessing a
        # project.  Include them here only when their URL is in this project's
        # scope; explicitly tagged captures remain strictly project-scoped.
        query: dict = _traffic_project_query(project_id, project.target, scope)
        if host:
            query["host"] = host
        if method:
            query["method"] = method.upper()
        docs = repositories.traffic().find(query).sort("timestamp", -1).limit(max(1, min(limit, 5000)))
        return [
            _traffic_summary(doc)
            for doc in docs
            if _traffic_belongs_to_project(doc, project_id, project.target, scope)
        ]
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc
    except PyMongoError as exc:
        raise HTTPException(status_code=503, detail="Database unavailable") from exc


@router.get("/projects/{project_id}/traffic/{traffic_id}", response_model=TrafficEntry, tags=["proxy"])
def get_traffic(
    project_id: str,
    traffic_id: str,
    store: ProjectStore = Depends(get_project_store),
    repositories: LegacyRepositoryFactory = Depends(get_repository_factory),
) -> TrafficEntry:
    try:
        project = store.get(project_id)
        scope = store.get_scope(project_id)
        doc = repositories.traffic().find_one({"_id": ObjectId(traffic_id)})
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc
    except (PyMongoError, ValueError) as exc:
        if isinstance(exc, PyMongoError):
            raise HTTPException(status_code=503, detail="Database unavailable") from exc
        raise HTTPException(status_code=404, detail="Traffic entry not found") from exc
    if not doc or not _traffic_belongs_to_project(doc, project_id, project.target, scope):
        raise HTTPException(status_code=404, detail="Traffic entry not found")
    return _traffic_entry(doc)


@router.post("/projects/{project_id}/traffic/{traffic_id}/evidence", response_model=EvidenceRecord, status_code=201, tags=["proxy", "evidence"])
def create_traffic_evidence(
    project_id: str,
    traffic_id: str,
    store: ProjectStore = Depends(get_project_store),
    repositories: LegacyRepositoryFactory = Depends(get_repository_factory),
) -> EvidenceRecord:
    try:
        project = store.get(project_id)
        project_dir = store.project_dir(project_id)
        scope = store.get_scope(project_id)
        doc = repositories.traffic().find_one({"_id": ObjectId(traffic_id)})
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc
    except (PyMongoError, ValueError) as exc:
        if isinstance(exc, PyMongoError):
            raise HTTPException(status_code=503, detail="Database unavailable") from exc
        raise HTTPException(status_code=404, detail="Traffic entry not found") from exc
    if not doc or not _traffic_belongs_to_project(doc, project_id, project.target, scope):
        raise HTTPException(status_code=404, detail="Traffic entry not found")
    entry = _traffic_entry(doc)
    return _evidence_store(project_dir).create(project_id, EvidenceInput(
        title=f"{entry.method} {entry.host}{entry.path}",
        summary=f"Captured HTTP transaction with status {entry.status_code}",
        kind="http",
        source_type="traffic",
        source_id=entry.id,
        tags=["traffic", entry.method.lower(), str(entry.status_code)],
        data={
            "host": entry.host,
            "path": entry.path,
            "method": entry.method,
            "status_code": entry.status_code,
            "timestamp": entry.timestamp,
            "request": entry.request,
            "response": entry.response,
        },
    ))


@router.delete("/projects/{project_id}/traffic/{traffic_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["proxy"])
def delete_traffic(
    project_id: str,
    traffic_id: str,
    store: ProjectStore = Depends(get_project_store),
    repositories: LegacyRepositoryFactory = Depends(get_repository_factory),
) -> Response:
    try:
        project = store.get(project_id)
        scope = store.get_scope(project_id)
        collection = repositories.traffic()
        object_id = ObjectId(traffic_id)
        doc = collection.find_one({"_id": object_id})
        if not doc or not _traffic_belongs_to_project(doc, project_id, project.target, scope):
            raise HTTPException(status_code=404, detail="Traffic entry not found")
        result = collection.delete_one({"_id": object_id})
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc
    except HTTPException:
        raise
    except (PyMongoError, ValueError) as exc:
        if isinstance(exc, PyMongoError):
            raise HTTPException(status_code=503, detail="Database unavailable") from exc
        raise HTTPException(status_code=404, detail="Traffic entry not found") from exc
    if not result.deleted_count:
        raise HTTPException(status_code=404, detail="Traffic entry not found")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete("/projects/{project_id}/traffic", status_code=status.HTTP_204_NO_CONTENT, tags=["proxy"])
def delete_traffic_subtree(
    project_id: str,
    host: str,
    path_prefix: str = "",
    store: ProjectStore = Depends(get_project_store),
    repositories: LegacyRepositoryFactory = Depends(get_repository_factory),
) -> Response:
    try:
        project = store.get(project_id)
        scope = store.get_scope(project_id)
        query: dict = _traffic_project_query(project_id, project.target, scope)
        query["host"] = host
        if path_prefix:
            prefix = "/" + path_prefix.strip("/")
            query["path"] = {"$regex": f"^{re.escape(prefix)}(?:/.*)?$"}
        collection = repositories.traffic()
        ids = [
            doc["_id"]
            for doc in collection.find(query)
            if _traffic_belongs_to_project(doc, project_id, project.target, scope)
        ]
        if ids:
            collection.delete_many({"_id": {"$in": ids}})
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc
    except PyMongoError as exc:
        raise HTTPException(status_code=503, detail="Database unavailable") from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/projects/{project_id}/traffic/sync-results", tags=["proxy", "results"])
def sync_traffic_results(
    project_id: str,
    store: ProjectStore = Depends(get_project_store),
    repositories: LegacyRepositoryFactory = Depends(get_repository_factory),
    settings: Settings = Depends(get_settings),
) -> dict:
    try:
        project = store.get(project_id)
        project_dir = store.project_dir(project_id)
        scope_data = store.get_scope(project_id).model_dump()
        collection = repositories.traffic()
        repositories(project_dir)  # load the legacy source path before imports
        from database.scope import ScopeConfig as LegacyScopeConfig
        from proxy.traffic_extractor import TrafficExtractor
        from workers.proxy_extractor_worker import _write_results
        extracted, review_candidates = TrafficExtractor().extract(
            collection,
            LegacyScopeConfig.from_dict(scope_data),
            query=_traffic_project_query(project_id, project.target, store.get_scope(project_id)),
        )
        summary = _write_results(str(project_dir), settings.mongo_uri, project.target, extracted, review_candidates)
        return {**summary, "extracted_counts": {key: len(value) for key, value in extracted.items()}}
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc
    except PyMongoError as exc:
        raise HTTPException(status_code=503, detail="Database unavailable") from exc
