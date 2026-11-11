"""Graph API handlers and helpers."""

from ..config import Settings
from ..config import get_settings
from ..docker_operations import DockerOperationManager
from ..docker_operations import DockerOperationNotFound
from ..docker_service import DockerService
from ..graph_store import GraphRevisionError
from ..graph_store import InvestigationNotFoundError
from ..projects import ProjectNotFoundError
from ..projects import ProjectStore
from ..repositories import LegacyRepositoryFactory
from ..schemas import DockerOperation
from ..schemas import EvidenceInput
from ..schemas import GraphBundle
from ..schemas import GraphEntity
from ..schemas import GraphEntityInput
from ..schemas import GraphIdentityInput
from ..schemas import GraphInvestigation
from ..schemas import GraphMergeInput
from ..schemas import GraphMergeResult
from ..schemas import GraphPreferencesInput
from ..schemas import GraphRelationship
from ..schemas import GraphRelationshipInput
from ..schemas import InvestigationCreate
from ..schemas import NetworkGraph
from ..schemas import NetworkManualNode
from ..schemas import NetworkNode
from ..schemas import TransformDefinitionInput
from ..schemas import TransformJob
from ..schemas import TransformManifest
from ..schemas import TransformResume
from ..schemas import TransformStart
from bson import ObjectId
from dataclasses import asdict
from dataclasses import is_dataclass
from datetime import datetime
from datetime import timezone
from fastapi import Depends
from fastapi import HTTPException
from fastapi import Query
from fastapi import status
from pathlib import Path
from urllib.parse import urlsplit
import docker
import hashlib
import json
import re
import secrets
import sys
import threading
from .dependencies import get_docker_operation_manager, get_docker_service, get_project_store, get_repository_factory
from .network_builder import _network_graph
from .stores import _evidence_store, _graph_store
from .transform_catalog import _graph_result_edge, _graph_result_kind, _graph_result_value, _graph_transforms, _load_project_transforms, _normalise_composite_results, _redact_transform_params, _save_project_transforms, _transform_seed
from fastapi import APIRouter

router = APIRouter()


_GRAPH_TRANSFORM_JOBS: dict[str, TransformJob] = {}


_GRAPH_TRANSFORM_RESUME_LOCK = threading.RLock()


_GRAPH_TRANSFORM_SECRETS: dict[str, dict] = {}


_GRAPH_TRANSFORM_JOBS_FILE = ".awe-transform-jobs.json"


_MAX_PERSISTED_TRANSFORM_JOBS = 500


def _project_transform_jobs_file(project_dir: Path) -> Path:
    return project_dir / _GRAPH_TRANSFORM_JOBS_FILE


def _load_project_transform_jobs(project_dir: Path) -> list[TransformJob]:
    path = _project_transform_jobs_file(project_dir)
    if not path.is_file():
        return []
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        jobs = [TransformJob.model_validate(item) for item in raw if isinstance(item, dict)]
        for job in jobs:
            _GRAPH_TRANSFORM_JOBS.setdefault(job.id, job)
        return jobs
    except (OSError, ValueError):
        return []


def _save_project_transform_jobs(project_dir: Path, project_id: str) -> None:
    jobs = [job for job in _GRAPH_TRANSFORM_JOBS.values() if job.project_id == project_id]
    jobs.sort(key=lambda item: item.created_at, reverse=True)
    path = _project_transform_jobs_file(project_dir)
    path.write_text(json.dumps([item.model_dump(mode="json") for item in jobs[:_MAX_PERSISTED_TRANSFORM_JOBS]], indent=2), encoding="utf-8")


def _sync_transform_job_from_operation(job: TransformJob, docker_operations: DockerOperationManager, log_limit: int = 100) -> tuple[TransformJob, bool]:
    if not job.operation_id:
        return job, False
    try:
        operation = docker_operations.get(job.operation_id)
    except DockerOperationNotFound:
        if job.status in {"queued", "running"}:
            updated = job.model_copy(update={
                "status": "failed",
                "message": job.message or "Docker operation is no longer available after backend restart",
                "completed_at": job.completed_at or datetime.now(timezone.utc),
            })
            return updated, updated != job
        return job, False
    status_map = {"queued": "queued", "running": "running", "completed": "completed", "failed": "failed", "cancelled": "cancelled", "cancelling": "running"}
    status = status_map.get(operation.status, "failed")
    completed = datetime.now(timezone.utc) if operation.status in {"completed", "failed", "cancelled"} else None
    updated = job.model_copy(update={
        "status": status,
        "message": operation.message or job.message,
        "completed_at": job.completed_at or completed,
        "progress_completed": operation.progress_completed,
        "progress_total": operation.progress_total,
        "logs": operation.logs[-log_limit:],
    })
    if operation.status == "completed" and "ingested_count" in operation.result:
        updated = updated.model_copy(update={
            "outputs_ingested": True,
            "message": f"Completed and ingested {operation.result['ingested_count']} typed outputs" if operation.result.get('ingested_count') else "Completed—logs available",
        })
    return updated, updated != job


def _ingest_graph_results(
    project_id: str,
    project_dir: Path,
    investigation_id: str,
    target: str,
    repositories: LegacyRepositoryFactory,
    manifest: TransformManifest,
    parsed: list,
    source_id: str = "",
    provenance_id: str = "",
) -> int:
    """Persist typed parser output and relationships into an investigation."""
    graph_store = _graph_store(project_dir)
    investigation = graph_store.get(project_id, investigation_id)
    parent_id = source_id or f"target:{target}"
    created_entities: list[str] = []
    linked_entities: list[str] = []
    linked_relationships: list[str] = []
    existing_entities = {item.id for item in graph_store.entities(investigation)}
    existing_relationships = {item.id for item in graph_store.relationships(investigation)}
    for index, result in enumerate(parsed[:1000]):
        data = asdict(result) if is_dataclass(result) else (result if isinstance(result, dict) else {"value": str(result)})
        kind = _graph_result_kind(data, manifest)
        value = _graph_result_value(data, kind)
        if not value:
            continue
        if kind == "subdomain" and (data.get("url") or data.get("status_code")):
            data = {**data, "live": True}
        entity_id = f"transform:{provenance_id or secrets.token_hex(8)}:{index}"
        entity = GraphEntity(
            id=entity_id, kind=kind, label=value[:500], value=value[:4096], data=data,
            source="transform", provenance=[{"transform_job_id": provenance_id, "tool_key": manifest.tool_key}],
        )
        if entity_id not in existing_entities:
            graph_store.add_entity(investigation, entity)
            existing_entities.add(entity_id)
            created_entities.append(entity_id)
        linked_entities.append(entity_id)
        relationship = GraphRelationship(
            id=f"{entity_id}:edge", source_id=parent_id, target_id=entity_id,
            kind=_graph_result_edge(kind), source="transform",
            provenance=[{"transform_job_id": provenance_id, "tool_key": manifest.tool_key}],
        )
        if relationship.id not in existing_relationships:
            graph_store.add_relationship(investigation, relationship)
            existing_relationships.add(relationship.id)
        linked_relationships.append(relationship.id)
    entity_ids = list(dict.fromkeys([*investigation.entity_ids, *linked_entities]))
    relationship_ids = list(dict.fromkeys([*investigation.relationship_ids, *linked_relationships]))
    if entity_ids != investigation.entity_ids or relationship_ids != investigation.relationship_ids:
        graph_store.save(investigation.model_copy(update={
            "entity_ids": entity_ids,
            "relationship_ids": relationship_ids,
        }), investigation.revision)
    return len(created_entities)


@router.get("/projects/{project_id}/network", response_model=NetworkGraph, tags=["network"])
def get_network_graph(project_id: str, store: ProjectStore = Depends(get_project_store), repositories: LegacyRepositoryFactory = Depends(get_repository_factory)) -> NetworkGraph:
    try:
        project=store.get(project_id); return _network_graph(store.project_dir(project_id), project.target, repositories)
    except ProjectNotFoundError as exc: raise HTTPException(status_code=404, detail="Project not found") from exc


@router.post("/projects/{project_id}/network/manual", response_model=NetworkNode, tags=["network"])
def add_network_manual(project_id: str, payload: NetworkManualNode, store: ProjectStore = Depends(get_project_store), repositories: LegacyRepositoryFactory = Depends(get_repository_factory)) -> NetworkNode:
    try:
        project_dir=store.project_dir(project_id); repo=repositories(project_dir); key=f"manual:{payload.kind}:{payload.label}:{payload.parent_id}"; data={**payload.data,"kind":payload.kind,"label":payload.label,"parent_id":payload.parent_id}; repo._db.results.update_one({"project_id":project_id,"category":"network_manual","result_key":key},{"$set":{"project_id":project_id,"category":"network_manual","result_key":key,"data":data}},upsert=True); return NetworkNode(id=key,kind=payload.kind,label=payload.label,data=data)
    except ProjectNotFoundError as exc: raise HTTPException(status_code=404, detail="Project not found") from exc


def _ensure_investigation(project_id: str, project_dir: Path, target: str, repositories: LegacyRepositoryFactory) -> GraphInvestigation:
    graph_store = _graph_store(project_dir)
    rows = graph_store.list(project_id)
    if rows:
        return rows[0]
    return graph_store.create(project_id, InvestigationCreate(name="Default investigation"), [f"target:{target}"] if target else [])


def _graph_provenance(data: dict) -> list[dict[str, str]]:
    raw_sources = data.get("sources", [])
    sources = raw_sources if isinstance(raw_sources, (list, tuple, set)) else [raw_sources]
    return [{"source": str(source)} for source in sources if source]


def _graph_bundle(project_id: str, project_dir: Path, target: str, repositories: LegacyRepositoryFactory, investigation_id: str = "", focus_id: str = "", depth: int = 1, limit: int = 0) -> GraphBundle:
    graph_store = _graph_store(project_dir)
    investigation = graph_store.get(project_id, investigation_id) if investigation_id else _ensure_investigation(project_id, project_dir, target, repositories)
    derived = _network_graph(project_dir, target, repositories)
    entities = [GraphEntity(id=node.id, kind=node.kind, label=node.label, value=str(node.data.get("domain") or node.data.get("url") or node.label), data=node.data, source="derived", scope="unknown", provenance=_graph_provenance(node.data)) for node in derived.nodes]
    relationships = [GraphRelationship(id=f"derived:{edge.source_id}:{edge.target_id}:{edge.kind}", source_id=edge.source_id, target_id=edge.target_id, kind=edge.kind, label=edge.label, source="derived") for edge in derived.edges]
    manual_entities = graph_store.entities(investigation)
    manual_relationships = graph_store.relationships(investigation)
    existing_entities = {item.id for item in entities}
    entities.extend(item for item in manual_entities if item.id not in existing_entities)
    existing_relationships = {item.id for item in relationships}
    relationships.extend(item for item in manual_relationships if item.id not in existing_relationships)
    if focus_id and any(entity.id == focus_id for entity in entities):
        adjacency: dict[str, set[str]] = {entity.id: set() for entity in entities}
        for relationship in relationships:
            adjacency.setdefault(relationship.source_id, set()).add(relationship.target_id)
            adjacency.setdefault(relationship.target_id, set()).add(relationship.source_id)
        included = {focus_id}
        frontier = {focus_id}
        for _ in range(depth):
            frontier = {neighbor for current in frontier for neighbor in adjacency.get(current, set())} - included
            included.update(frontier)
        entities = [entity for entity in entities if entity.id in included]
        relationships = [relationship for relationship in relationships if relationship.source_id in included and relationship.target_id in included]
    if limit and len(entities) > limit:
        ordered_entities = entities
        if focus_id:
            ordered_entities = [entity for entity in entities if entity.id == focus_id] + [entity for entity in entities if entity.id != focus_id]
        entity_ids = {entity.id for entity in ordered_entities[:limit]}
        entities = [entity for entity in entities if entity.id in entity_ids]
        relationships = [relationship for relationship in relationships if relationship.source_id in entity_ids and relationship.target_id in entity_ids]
    return GraphBundle(investigation=investigation, entities=entities, relationships=relationships, revision=investigation.revision)


@router.get("/projects/{project_id}/investigations", response_model=list[GraphInvestigation], tags=["network"])
def list_investigations(project_id: str, store: ProjectStore = Depends(get_project_store), repositories: LegacyRepositoryFactory = Depends(get_repository_factory)) -> list[GraphInvestigation]:
    try:
        project_dir = store.project_dir(project_id)
        return _graph_store(project_dir).list(project_id) or [_ensure_investigation(project_id, project_dir, store.get(project_id).target, repositories)]
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc


@router.post("/projects/{project_id}/investigations", response_model=GraphInvestigation, status_code=201, tags=["network"])
def create_investigation(project_id: str, payload: InvestigationCreate, store: ProjectStore = Depends(get_project_store)) -> GraphInvestigation:
    try:
        project = store.get(project_id)
        return _graph_store(store.project_dir(project_id)).create(project_id, payload, [f"target:{project.target}"] if project.target else [])
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc


@router.delete("/projects/{project_id}/investigations/{investigation_id}", status_code=204, tags=["network"])
def delete_investigation(project_id: str, investigation_id: str, store: ProjectStore = Depends(get_project_store)) -> None:
    try:
        _graph_store(store.project_dir(project_id)).delete(project_id, investigation_id)
    except (ProjectNotFoundError, InvestigationNotFoundError) as exc:
        raise HTTPException(status_code=404, detail="Investigation not found") from exc


@router.get("/projects/{project_id}/investigations/{investigation_id}/graph", response_model=GraphBundle, tags=["network"])
def get_investigation_graph(project_id: str, investigation_id: str, focus_id: str = Query(default="", max_length=300), depth: int = Query(default=1, ge=0, le=5), limit: int = Query(default=0, ge=0, le=5000), store: ProjectStore = Depends(get_project_store), repositories: LegacyRepositoryFactory = Depends(get_repository_factory)) -> GraphBundle:
    try:
        project = store.get(project_id)
        return _graph_bundle(project_id, store.project_dir(project_id), project.target, repositories, investigation_id, focus_id, depth, limit)
    except (ProjectNotFoundError, InvestigationNotFoundError) as exc:
        raise HTTPException(status_code=404, detail="Investigation not found") from exc


@router.post("/projects/{project_id}/investigations/{investigation_id}/entities", response_model=GraphEntity, status_code=201, tags=["network"])
def create_graph_entity(project_id: str, investigation_id: str, payload: GraphEntityInput, store: ProjectStore = Depends(get_project_store)) -> GraphEntity:
    try:
        project_dir = store.project_dir(project_id); graph_store = _graph_store(project_dir); row = graph_store.get(project_id, investigation_id)
        entity = GraphEntity(id=f"manual:{secrets.token_hex(10)}", source="manual", **payload.model_dump())
        graph_store.add_entity(row, entity)
        graph_store.save(row.model_copy(update={"entity_ids": [*row.entity_ids, entity.id]}), row.revision)
        return entity
    except (ProjectNotFoundError, InvestigationNotFoundError) as exc:
        raise HTTPException(status_code=404, detail="Investigation not found") from exc
    except GraphRevisionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.put("/projects/{project_id}/investigations/{investigation_id}/entities/{entity_id}/identity", response_model=GraphEntity, tags=["network"])
def update_graph_identity(project_id: str, investigation_id: str, entity_id: str, payload: GraphIdentityInput, store: ProjectStore = Depends(get_project_store)) -> GraphEntity:
    try:
        graph_store = _graph_store(store.project_dir(project_id)); row = graph_store.get(project_id, investigation_id)
        entity = next((item for item in graph_store.entities(row) if item.id == entity_id), None)
        if not entity:
            raise HTTPException(status_code=404, detail="Only persisted analyst or transform entities can have identity metadata changed")
        aliases: list[str] = []
        for value in payload.aliases:
            clean = str(value).strip()
            if clean and clean not in aliases and clean not in {entity.label, entity.value}:
                aliases.append(clean)
        updated = entity.model_copy(update={"canonical_id": payload.canonical_id.strip() or entity.canonical_id or entity.id, "aliases": aliases[:100], "confidence": payload.confidence if payload.confidence is not None else entity.confidence})
        graph_store.update_entity(row, updated)
        graph_store.save(row, row.revision)
        return updated
    except (ProjectNotFoundError, InvestigationNotFoundError) as exc:
        raise HTTPException(status_code=404, detail="Investigation not found") from exc
    except GraphRevisionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/projects/{project_id}/investigations/{investigation_id}/entities/{entity_id}/merge", response_model=GraphMergeResult, tags=["network"])
def merge_graph_entity(project_id: str, investigation_id: str, entity_id: str, payload: GraphMergeInput, store: ProjectStore = Depends(get_project_store)) -> GraphMergeResult:
    try:
        graph_store = _graph_store(store.project_dir(project_id)); row = graph_store.get(project_id, investigation_id)
        persisted = {item.id: item for item in graph_store.entities(row)}
        if entity_id not in persisted or payload.target_id not in persisted:
            raise HTTPException(status_code=404, detail="Both entities must be persisted analyst or transform entities")
        if entity_id == payload.target_id:
            raise HTTPException(status_code=422, detail="An entity cannot be merged into itself")
        merged, rewired, removed = graph_store.merge_entities(row, entity_id, payload.target_id)
        relationships = graph_store.relationships(row)
        saved = graph_store.save(row.model_copy(update={"entity_ids": [item for item in row.entity_ids if item != entity_id], "relationship_ids": [item.id for item in relationships]}), row.revision)
        return GraphMergeResult(entity=merged, merged_entity_ids=[entity_id], rewired_relationships=rewired, removed_relationships=removed, revision=saved.revision)
    except (ProjectNotFoundError, InvestigationNotFoundError) as exc:
        raise HTTPException(status_code=404, detail="Investigation not found") from exc
    except GraphRevisionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"Entity not found: {exc.args[0]}") from exc


@router.post("/projects/{project_id}/investigations/{investigation_id}/relationships", response_model=GraphRelationship, status_code=201, tags=["network"])
def create_graph_relationship(project_id: str, investigation_id: str, payload: GraphRelationshipInput, store: ProjectStore = Depends(get_project_store), repositories: LegacyRepositoryFactory = Depends(get_repository_factory)) -> GraphRelationship:
    try:
        project = store.get(project_id); project_dir = store.project_dir(project_id); graph_store = _graph_store(project_dir); row = graph_store.get(project_id, investigation_id)
        bundle = _graph_bundle(project_id, project_dir, project.target, repositories, investigation_id)
        ids = {entity.id for entity in bundle.entities}
        if payload.source_id not in ids or payload.target_id not in ids:
            raise HTTPException(status_code=422, detail="Both relationship endpoints must exist in the investigation")
        relationship = GraphRelationship(id=f"manual:{secrets.token_hex(10)}", source="manual", **payload.model_dump())
        graph_store.add_relationship(row, relationship)
        graph_store.save(row.model_copy(update={"relationship_ids": [*row.relationship_ids, relationship.id]}), row.revision)
        return relationship
    except (ProjectNotFoundError, InvestigationNotFoundError) as exc:
        raise HTTPException(status_code=404, detail="Investigation not found") from exc


@router.delete("/projects/{project_id}/investigations/{investigation_id}/entities/{entity_id}", status_code=204, tags=["network"])
def delete_graph_entity(project_id: str, investigation_id: str, entity_id: str, store: ProjectStore = Depends(get_project_store)) -> None:
    try:
        graph_store = _graph_store(store.project_dir(project_id)); row = graph_store.get(project_id, investigation_id)
        graph_store.delete_entity(row, entity_id)
        graph_store.save(row.model_copy(update={"entity_ids": [item for item in row.entity_ids if item != entity_id]}), row.revision)
    except (ProjectNotFoundError, InvestigationNotFoundError) as exc:
        raise HTTPException(status_code=404, detail="Investigation not found") from exc


@router.delete("/projects/{project_id}/investigations/{investigation_id}/relationships/{relationship_id}", status_code=204, tags=["network"])
def delete_graph_relationship(project_id: str, investigation_id: str, relationship_id: str, store: ProjectStore = Depends(get_project_store)) -> None:
    try:
        graph_store = _graph_store(store.project_dir(project_id)); row = graph_store.get(project_id, investigation_id)
        graph_store.delete_relationship(row, relationship_id)
        graph_store.save(row.model_copy(update={"relationship_ids": [item for item in row.relationship_ids if item != relationship_id]}), row.revision)
    except (ProjectNotFoundError, InvestigationNotFoundError) as exc:
        raise HTTPException(status_code=404, detail="Investigation not found") from exc


@router.put("/projects/{project_id}/investigations/{investigation_id}/preferences", response_model=GraphInvestigation, tags=["network"])
def save_graph_preferences(project_id: str, investigation_id: str, payload: GraphPreferencesInput, store: ProjectStore = Depends(get_project_store)) -> GraphInvestigation:
    try:
        graph_store = _graph_store(store.project_dir(project_id)); row = graph_store.get(project_id, investigation_id)
        return graph_store.save(row.model_copy(update={"preferences": payload.preferences}), payload.revision)
    except (ProjectNotFoundError, InvestigationNotFoundError) as exc:
        raise HTTPException(status_code=404, detail="Investigation not found") from exc
    except GraphRevisionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/projects/{project_id}/transforms", response_model=list[TransformManifest], tags=["network"])
def list_graph_transforms(project_id: str, store: ProjectStore = Depends(get_project_store), settings: Settings = Depends(get_settings)) -> list[TransformManifest]:
    try:
        project_dir = store.project_dir(project_id)
        return _graph_transforms(settings, project_dir)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc


@router.post("/projects/{project_id}/transform-definitions", response_model=TransformManifest, status_code=201, tags=["network"])
def save_transform_definition(project_id: str, payload: TransformDefinitionInput, store: ProjectStore = Depends(get_project_store), settings: Settings = Depends(get_settings)) -> TransformManifest:
    try:
        project_dir = store.project_dir(project_id)
        source = str(settings.legacy_src_dir.resolve())
        if source not in sys.path: sys.path.insert(0, source)
        from containers.tool_registry import TOOL_REGISTRY
        missing = sorted({tool for stage in payload.stages for tool in stage.tool_keys if tool not in TOOL_REGISTRY})
        if missing:
            raise HTTPException(status_code=422, detail=f"Unknown tool(s): {', '.join(missing)}")
        transform_id = payload.id or f"custom:{re.sub(r'[^a-z0-9_]+', '_', payload.display_name.strip().lower()).strip('_') or secrets.token_hex(4)}"
        if not transform_id.startswith(("custom:", "composite:")):
            transform_id = f"custom:{transform_id}"
        manifest = TransformManifest(
            id=transform_id,
            tool_key=transform_id,
            display_name=payload.display_name,
            category=payload.category,
            description=payload.description,
            input_types=payload.input_types,
            output_types=payload.output_types,
            relationship_types=payload.relationship_types,
            mode=payload.mode,
            requires_approval=payload.requires_approval or payload.mode in {"active", "high_risk"},
            scope_required=payload.scope_required,
            parameters=payload.parameters,
            stages=payload.stages,
        )
        custom = [item for item in _load_project_transforms(project_dir) if item.id != manifest.id]
        custom.append(manifest)
        _save_project_transforms(project_dir, custom)
        return manifest
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc


@router.delete("/projects/{project_id}/transform-definitions/{transform_id}", status_code=204, tags=["network"])
def delete_transform_definition(project_id: str, transform_id: str, store: ProjectStore = Depends(get_project_store)) -> None:
    try:
        project_dir = store.project_dir(project_id)
        custom = _load_project_transforms(project_dir)
        kept = [item for item in custom if item.id != transform_id]
        if len(kept) == len(custom):
            raise HTTPException(status_code=404, detail="Transform definition not found")
        _save_project_transforms(project_dir, kept)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc


def _persist_transform_results(
    project_dir: Path, target: str, transform: TransformManifest, job_id: str,
    output_dir: Path, repositories: LegacyRepositoryFactory,
) -> tuple[int, list[dict]]:
    """Store each tool's parsed output in the project Results session."""
    repo = repositories(project_dir)
    from pymongo import UpdateOne
    from containers.parsers import PARSERS
    from containers.tool_registry import TOOL_REGISTRY
    now = datetime.now(timezone.utc).isoformat()
    target_host = (urlsplit(target if "://" in target else f"https://{target}").hostname or target).lower().rstrip(".")
    units = [
        (stage_index, tool_index, key, output_dir / f"stage_{stage_index + 1}_{key}")
        for stage_index, stage in enumerate(transform.stages)
        for tool_index, key in enumerate(stage.tool_keys)
    ] if transform.stages else [(0, 0, transform.tool_key, output_dir)]
    rows: dict[tuple[str, str], dict] = {}
    tool_runs: list[tuple[ObjectId, str, str, int, int]] = []
    stage_subdomains: list[dict] = []

    for stage_index, tool_index, key, tool_dir in units:
        tool = TOOL_REGISTRY.get(key)
        parser = PARSERS.get(key)
        if not tool or not parser:
            continue
        category = tool.category
        run_id = ObjectId(hashlib.sha256(f"{job_id}:{stage_index}:{tool_index}:{key}".encode()).hexdigest()[:24])
        parsed = parser(str(tool_dir)) or []
        count = 0
        for result in parsed:
            data = asdict(result) if is_dataclass(result) else (dict(result) if isinstance(result, dict) else {"value": str(result)})
            result_key = str(getattr(result, "key", "") or data.get("domain") or data.get("url") or data.get("value") or data.get("name") or "").strip()
            if category == "subdomain":
                domain = str(data.get("domain") or result_key).lower().rstrip(".")
                if not domain or not (domain == target_host or domain.endswith(f".{target_host}")):
                    continue
                data["domain"] = domain
                result_key = domain
                stage_subdomains.append(data)
            if not result_key:
                continue
            data["transform_job_id"] = job_id
            sources = {str(source) for source in data.get("sources", []) if source}
            sources.add(key)
            row = rows.setdefault((category, result_key), {"data": data, "sources": set(), "tool_run_id": str(run_id)})
            row["sources"].update(sources)
            for field, value in data.items():
                if row["data"].get(field) in (None, "", [], {}) and value not in (None, "", [], {}):
                    row["data"][field] = value
            count += 1
        tool_runs.append((run_id, key, category, stage_index, count))

    repo._db.scan_sessions.update_one(
        {"_id": ObjectId(job_id)},
        {"$setOnInsert": {
            "project_dir": str(project_dir), "pipeline_key": f"transform:{transform.id}",
            "pipeline_name": transform.display_name, "target": target,
            "started_at": now, "output_dir": str(output_dir),
            "params": {"transform_job_id": job_id}, "in_scope": [], "out_of_scope": [],
        }, "$set": {"status": "running"}},
        upsert=True,
    )
    for run_id, key, category, stage_index, count in tool_runs:
        repo._db.tool_runs.update_one(
            {"_id": run_id},
            {"$setOnInsert": {"session_id": job_id, "tool_key": key, "display_name": TOOL_REGISTRY[key].display_name, "category": category, "stage": stage_index, "started_at": now},
             "$set": {"status": "completed", "completed_at": now, "result_count": count}},
            upsert=True,
        )
    if rows:
        repo._db.results.bulk_write([
            UpdateOne(
                {"session_id": job_id, "category": category, "result_key": result_key},
                {"$setOnInsert": {"session_id": job_id, "category": category, "result_key": result_key, "created_at": now},
                 "$set": {"tool_run_id": row["tool_run_id"], "data": row["data"]},
                 "$addToSet": {"sources": {"$each": sorted(row["sources"])}}},
                upsert=True,
            )
            for (category, result_key), row in rows.items()
        ], ordered=False)
    repo._db.scan_sessions.update_one({"_id": ObjectId(job_id)}, {"$set": {"status": "completed", "completed_at": now}})
    return len(rows), stage_subdomains


def _complete_graph_transform(
    project_id: str, project_dir: Path, target: str, investigation_id: str,
    transform: TransformManifest, entity_ids: list[str], source_entity_id: str,
    params: dict, job_id: str, repositories: LegacyRepositoryFactory,
    parsed: list, output_dir: Path,
) -> dict:
    if "structured" not in transform.output_channels:
        return {"ingested_count": 0, "result_count": 0, "investigation_id": investigation_id}
    result_count, stage_subdomains = _persist_transform_results(project_dir, target, transform, job_id, output_dir, repositories)
    graph_inputs = parsed
    if transform.stages and transform.output_types == ["subdomain"]:
        target_host = (urlsplit(target if "://" in target else f"https://{target}").hostname or target).lower().rstrip(".")
        graph_inputs = []
        for result in parsed:
            data = asdict(result) if is_dataclass(result) else (result if isinstance(result, dict) else {"value": str(result)})
            host = _graph_result_value(data, "subdomain").lower().rstrip(".")
            if host == target_host or host.endswith(f".{target_host}"):
                graph_inputs.append(result)
        graph_inputs.extend(stage_subdomains)
    graph_results = _normalise_composite_results(transform, graph_inputs)
    count = _ingest_graph_results(project_id, project_dir, investigation_id, target, repositories, transform, graph_results, source_entity_id, job_id)
    evidence_store = _evidence_store(project_dir)
    evidence_payload = EvidenceInput(
        investigation_id=investigation_id,
        title=f"{transform.display_name} output",
        summary=f"Stored {result_count} result(s) and ingested {count} graph output(s).",
        kind="tool_output", source_type="transform", source_id=job_id,
        entity_ids=entity_ids, tags=["transform", transform.mode, *transform.output_types[:5]],
        data={
            "transform_id": transform.id, "tool_key": transform.tool_key,
            "operation_output_dir": str(output_dir), "parsed_count": len(graph_results),
            "ingested_count": count, "result_count": result_count,
            "stages": [stage.model_dump() for stage in transform.stages],
            "parameters": _redact_transform_params(transform, params)[0],
        },
    )
    evidence = evidence_store.upsert_source(project_id, evidence_payload)
    return {"ingested_count": count, "result_count": result_count, "investigation_id": investigation_id, "evidence_id": evidence.id}


def _launch_graph_transform_operation(
    project_id: str, project_dir: Path, target: str, investigation_id: str,
    transform: TransformManifest, entity_ids: list[str], source_entity_id: str,
    params: dict, job_id: str, docker_operations: DockerOperationManager,
    docker_service: DockerService, repositories: LegacyRepositoryFactory, *, resume: bool = False,
    prior_logs: list[str] | None = None,
) -> DockerOperation:
    output_dir = project_dir / ".awe-transform-runs" / job_id
    bundle = _graph_bundle(project_id, project_dir, target, repositories, investigation_id)
    selected = {entity.id: entity for entity in bundle.entities}
    seed_values = list(dict.fromkeys(
        str(selected[entity_id].value or selected[entity_id].label).strip()
        for entity_id in entity_ids
        if entity_id in selected and str(selected[entity_id].value or selected[entity_id].label).strip()
    ))

    def on_complete(parsed: list, _output_dir: Path) -> dict:
        return _complete_graph_transform(project_id, project_dir, target, investigation_id, transform, entity_ids, source_entity_id, params, job_id, repositories, parsed, _output_dir)

    if transform.stages:
        return docker_operations.start_composite(transform.tool_key, [stage.model_dump() for stage in transform.stages], params, output_dir, docker_service, on_complete, resume=resume, prior_logs=prior_logs, seed_values=seed_values)
    return docker_operations.start_tool(transform.tool_key, params, output_dir, docker_service, on_complete, resume=resume, prior_logs=prior_logs, seed_values=seed_values)


@router.get("/projects/{project_id}/transform-preflight", response_model=dict, tags=["network"])
def get_transform_preflight(project_id: str, transform_id: str, store: ProjectStore = Depends(get_project_store), settings: Settings = Depends(get_settings), docker_service: DockerService = Depends(get_docker_service)) -> dict:
    from ..image_readiness import transform_preflight
    try:
        store.get(project_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc
    transform = next((item for item in _graph_transforms(settings, store.project_dir(project_id)) if item.id == transform_id), None)
    if not transform: raise HTTPException(status_code=404, detail="Transform not found")
    return transform_preflight(transform, docker_service)


@router.post("/projects/{project_id}/transforms", response_model=TransformJob, status_code=202, tags=["network"])
def start_graph_transform(project_id: str, payload: TransformStart, store: ProjectStore = Depends(get_project_store), settings: Settings = Depends(get_settings), docker_operations: DockerOperationManager = Depends(get_docker_operation_manager), docker_service: DockerService = Depends(get_docker_service), repositories: LegacyRepositoryFactory = Depends(get_repository_factory)) -> TransformJob:
    try:
        project = store.get(project_id); project_dir = store.project_dir(project_id); graph_store = _graph_store(project_dir)
        investigation = _ensure_investigation(project_id, project_dir, project.target, repositories) if not payload.investigation_id else graph_store.get(project_id, payload.investigation_id)
        bundle = _graph_bundle(project_id, project_dir, project.target, repositories, investigation.id)
        entities = {entity.id: entity for entity in bundle.entities}
        manifests = {item.id: item for item in _graph_transforms(settings, project_dir)}
        transform = manifests.get(payload.transform_id)
        if not transform:
            raise HTTPException(status_code=404, detail="Transform not found")
        selected = [entities[item] for item in payload.entity_ids if item in entities]
        if not selected or any(entity.kind not in transform.input_types for entity in selected):
            raise HTTPException(status_code=422, detail="Transform input types do not match the selected entities")
        if transform.requires_approval and not payload.approved:
            raise HTTPException(status_code=409, detail="This transform requires explicit approval")
        from ..image_readiness import transform_preflight, require_ready
        require_ready(transform_preflight(transform, docker_service))
        job_id = secrets.token_hex(12)
        params = dict(payload.parameters)
        if payload.source_job_id:
            # Credentials may carry into a chained transform, but routing values
            # must come from its newly selected graph input (or explicit input).
            inherited = {key: value for key, value in _GRAPH_TRANSFORM_SECRETS.get(payload.source_job_id, {}).items() if key not in {"domain", "host", "url", "endpoint", "input_file"}}
            params = {**inherited, **params}
        for parameter in ("domain", "host", "url", "endpoint"):
            params.setdefault(parameter, _transform_seed(selected[0], parameter))
        operation = _launch_graph_transform_operation(project_id, project_dir, project.target, investigation.id, transform, payload.entity_ids, selected[0].id, params, job_id, docker_operations, docker_service, repositories)
        safe_params, secret_params = _redact_transform_params(transform, params)
        _GRAPH_TRANSFORM_SECRETS[job_id] = secret_params
        job = TransformJob(id=job_id, project_id=project_id, investigation_id=investigation.id, transform_id=transform.id, status="queued", entity_ids=payload.entity_ids, source_job_id=payload.source_job_id, operation_id=operation.id, parameters=safe_params, created_at=datetime.now(timezone.utc))
        _GRAPH_TRANSFORM_JOBS[job.id] = job
        _save_project_transform_jobs(project_dir, project_id)
        return job
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc
    except InvestigationNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Investigation not found") from exc


@router.get("/projects/{project_id}/transforms/jobs", response_model=list[TransformJob], tags=["network"])
def list_graph_transform_jobs(project_id: str, store: ProjectStore = Depends(get_project_store), docker_operations: DockerOperationManager = Depends(get_docker_operation_manager)) -> list[TransformJob]:
    try:
        project_dir = store.project_dir(project_id)
        _load_project_transform_jobs(project_dir)
        jobs: list[TransformJob] = []
        changed = False
        for job_id, item in list(_GRAPH_TRANSFORM_JOBS.items()):
            if item.project_id != project_id:
                continue
            job, job_changed = _sync_transform_job_from_operation(item, docker_operations, 200)
            changed = changed or job_changed
            _GRAPH_TRANSFORM_JOBS[job_id] = job
            jobs.append(job)
        if changed:
            _save_project_transform_jobs(project_dir, project_id)
        return sorted(jobs, key=lambda item: item.created_at, reverse=True)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc


@router.get("/projects/{project_id}/transforms/{job_id}", response_model=TransformJob, tags=["network"])
def get_graph_transform(project_id: str, job_id: str, store: ProjectStore = Depends(get_project_store), docker_operations: DockerOperationManager = Depends(get_docker_operation_manager), settings: Settings = Depends(get_settings)) -> TransformJob:
    try:
        project_dir = store.project_dir(project_id)
        _load_project_transform_jobs(project_dir)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc
    job = _GRAPH_TRANSFORM_JOBS.get(job_id)
    if not job or job.project_id != project_id:
        raise HTTPException(status_code=404, detail="Transform job not found")
    if job.operation_id:
        try:
            operation = docker_operations.get(job.operation_id)
            status_map = {"queued": "queued", "running": "running", "completed": "completed", "failed": "failed", "cancelled": "cancelled", "cancelling": "running"}
            if operation.status != "queued" or job.status == "queued":
                job = job.model_copy(update={"status": status_map.get(operation.status, "failed"), "message": operation.message or job.message, "completed_at": datetime.now(timezone.utc) if operation.status in {"completed", "failed", "cancelled"} else None, "progress_completed": operation.progress_completed, "progress_total": operation.progress_total, "logs": operation.logs[-100:]})
                if operation.status == "completed" and not job.outputs_ingested and "ingested_count" in operation.result:
                    job = job.model_copy(update={"outputs_ingested": True, "message": f"Completed and ingested {operation.result['ingested_count']} typed outputs" if operation.result.get('ingested_count') else "Completed—logs available"})
                elif operation.status == "completed" and not job.outputs_ingested:
                    try:
                        from containers.parsers import PARSERS
                        from ..projects import ProjectStore
                        project_store = ProjectStore(settings.workspace_dir)
                        project = project_store.get(project_id); project_dir = project_store.project_dir(project_id)
                        manifest = next((item for item in _graph_transforms(settings, project_dir) if item.id == job.transform_id), None)
                        parser = PARSERS.get(manifest.tool_key) if manifest else None
                        if parser and operation.result.get("output_dir"):
                            parsed = parser(operation.result["output_dir"]) or []
                            ingested = _ingest_graph_results(project_id, project_dir, job.investigation_id, project.target, None, manifest, parsed, job.entity_ids[0] if job.entity_ids else "", job.id)
                            job = job.model_copy(update={"outputs_ingested": True, "message": f"Completed and ingested {ingested} typed outputs"})
                    except Exception as exc:
                        job = job.model_copy(update={"message": f"Completed; output ingestion skipped: {exc}"})
                _GRAPH_TRANSFORM_JOBS[job_id] = job
                _save_project_transform_jobs(project_dir, project_id)
        except DockerOperationNotFound:
            if job.status in {"queued", "running"}:
                job = job.model_copy(update={
                    "status": "failed",
                    "message": job.message or "Docker operation is no longer available after backend restart",
                    "completed_at": job.completed_at or datetime.now(timezone.utc),
                })
                _GRAPH_TRANSFORM_JOBS[job_id] = job
                _save_project_transform_jobs(project_dir, project_id)
    return job


@router.post("/projects/{project_id}/transforms/{job_id}/resume", response_model=TransformJob, status_code=202, tags=["network"])
def resume_graph_transform(project_id: str, job_id: str, payload: TransformResume, store: ProjectStore = Depends(get_project_store), settings: Settings = Depends(get_settings), docker_operations: DockerOperationManager = Depends(get_docker_operation_manager), docker_service: DockerService = Depends(get_docker_service), repositories: LegacyRepositoryFactory = Depends(get_repository_factory)) -> TransformJob:
    with _GRAPH_TRANSFORM_RESUME_LOCK:
        try:
            project = store.get(project_id)
            project_dir = store.project_dir(project_id)
            _load_project_transform_jobs(project_dir)
        except ProjectNotFoundError as exc:
            raise HTTPException(status_code=404, detail="Project not found") from exc
        job = _GRAPH_TRANSFORM_JOBS.get(job_id)
        if not job or job.project_id != project_id:
            raise HTTPException(status_code=404, detail="Transform job not found")
        job, changed = _sync_transform_job_from_operation(job, docker_operations)
        if changed:
            _GRAPH_TRANSFORM_JOBS[job_id] = job
            _save_project_transform_jobs(project_dir, project_id)
        if job.status not in {"failed", "cancelled"}:
            raise HTTPException(status_code=409, detail="Only failed or cancelled transforms can be resumed")
        from ..session_service import session_service
        if any(s["run_id"] == job.operation_id and s["status"] in {"starting", "active", "listening"} for s in session_service().rows.values()):
            raise HTTPException(status_code=409, detail="Attach to or terminate the existing session before resuming this transform")
        transform = next((item for item in _graph_transforms(settings, project_dir) if item.id == job.transform_id), None)
        if not transform:
            raise HTTPException(status_code=409, detail="The transform definition is no longer available")
        if transform.requires_approval and not payload.approved:
            raise HTTPException(status_code=409, detail="This transform requires explicit approval")
        secret_keys = {str(item.get("key")) for item in transform.parameters if item.get("type") == "secret" or item.get("default") == "secret" or item.get("sensitive") is True}
        if set(payload.parameters) - secret_keys:
            raise HTTPException(status_code=422, detail="Only secret parameters may be supplied when resuming")
        supplied = {key: value for key, value in payload.parameters.items() if value not in (None, "")}
        params = {**job.parameters, **_GRAPH_TRANSFORM_SECRETS.get(job_id, {}), **supplied}
        missing = [key for key in secret_keys if params.get(key) == "[redacted]"]
        if missing:
            raise HTTPException(status_code=422, detail=f"Re-enter secret parameters to resume: {', '.join(sorted(missing))}")
        try:
            investigation = _graph_store(project_dir).get(project_id, job.investigation_id)
        except InvestigationNotFoundError as exc:
            raise HTTPException(status_code=409, detail="The investigation is no longer available") from exc
        bundle = _graph_bundle(project_id, project_dir, project.target, repositories, investigation.id)
        entities = {entity.id: entity for entity in bundle.entities}
        selected = [entities[item] for item in job.entity_ids if item in entities]
        if not selected or len(selected) != len(job.entity_ids) or any(entity.kind not in transform.input_types for entity in selected):
            raise HTTPException(status_code=409, detail="The original input entities are no longer compatible")
        for parameter in ("domain", "host", "url", "endpoint"):
            params.setdefault(parameter, _transform_seed(selected[0], parameter))
        output_dir = project_dir / ".awe-transform-runs" / job_id
        from ..image_readiness import transform_preflight, require_ready
        require_ready(transform_preflight(transform, docker_service))
        try:
            docker_operations.validate_checkpoint(output_dir, transform.tool_key, [stage.model_dump() for stage in transform.stages], params)
            if job.operation_id:
                docker_operations.cleanup_interrupted_container(job.operation_id, docker_service)
        except (ValueError, RuntimeError, docker.errors.DockerException, OSError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        operation = _launch_graph_transform_operation(project_id, project_dir, project.target, investigation.id, transform, job.entity_ids, selected[0].id, params, job_id, docker_operations, docker_service, repositories, resume=True, prior_logs=job.logs)
        _GRAPH_TRANSFORM_SECRETS[job_id] = {key: params[key] for key in secret_keys if key in params}
        resumed = job.model_copy(update={"status": "queued", "operation_id": operation.id, "message": "Resuming transform", "completed_at": None, "outputs_ingested": False, "progress_completed": 0, "progress_total": operation.progress_total, "logs": operation.logs})
        _GRAPH_TRANSFORM_JOBS[job_id] = resumed
        _save_project_transform_jobs(project_dir, project_id)
        return resumed


@router.post("/projects/{project_id}/transforms/{job_id}/cancel", response_model=TransformJob, tags=["network"])
def cancel_graph_transform(project_id: str, job_id: str, store: ProjectStore = Depends(get_project_store), docker_operations: DockerOperationManager = Depends(get_docker_operation_manager)) -> TransformJob:
    with _GRAPH_TRANSFORM_RESUME_LOCK:
        try:
            project_dir = store.project_dir(project_id)
            _load_project_transform_jobs(project_dir)
        except ProjectNotFoundError as exc:
            raise HTTPException(status_code=404, detail="Project not found") from exc
        job = _GRAPH_TRANSFORM_JOBS.get(job_id)
        if not job or job.project_id != project_id:
            raise HTTPException(status_code=404, detail="Transform job not found")
        job, _ = _sync_transform_job_from_operation(job, docker_operations)
        if job.status not in {"queued", "running", "approval_required"}:
            raise HTTPException(status_code=409, detail="Only active transforms can be cancelled")
        if job.operation_id:
            try: docker_operations.cancel(job.operation_id)
            except DockerOperationNotFound: pass
        job = job.model_copy(update={"status": "cancelled", "message": "Cancellation requested"})
        _GRAPH_TRANSFORM_JOBS[job_id] = job
        _save_project_transform_jobs(project_dir, project_id)
        return job
