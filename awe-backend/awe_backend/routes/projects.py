"""Projects API handlers and helpers."""

from ..jobs import PipelineJobManager
from ..pipelines import PipelineCatalog
from ..projects import ProjectNotFoundError
from ..projects import ProjectStore
from ..repositories import LegacyRepositoryFactory
from ..schemas import AuthSessionEntry
from ..schemas import AuthSessionInput
from ..schemas import DashboardOverview
from ..schemas import DashboardProject
from ..schemas import PipelineTemplate
from ..schemas import Project
from ..schemas import ProjectCreate
from ..schemas import ProjectNotes
from ..schemas import ProjectUpdate
from ..schemas import ScopeConfig
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from fastapi import Depends
from fastapi import HTTPException
from fastapi import Response
from fastapi import status
from pymongo.errors import PyMongoError
from .dependencies import get_job_manager, get_pipeline_catalog, get_project_store, get_repository_factory
from fastapi import APIRouter

router = APIRouter()


@router.get("/pipelines", response_model=list[PipelineTemplate], tags=["pipelines"])
def list_pipelines(
    catalog: PipelineCatalog = Depends(get_pipeline_catalog),
) -> list[PipelineTemplate]:
    return catalog.list()


@router.get("/projects", response_model=list[Project], tags=["projects"])
def list_projects(store: ProjectStore = Depends(get_project_store)) -> list[Project]:
    return store.list()


@router.get("/dashboard", response_model=DashboardOverview, tags=["projects"])
def get_dashboard(
    store: ProjectStore = Depends(get_project_store),
    repositories: LegacyRepositoryFactory = Depends(get_repository_factory),
    jobs: PipelineJobManager = Depends(get_job_manager),
) -> DashboardOverview:
    projects = store.list()
    summaries: list[DashboardProject] = []
    for project in projects:
        metrics = repositories(store.project_dir(project.id)).dashboard_metrics()
        memory_active = sum(
            item.status in {"queued", "running", "stopping"}
            for item in jobs.list_for_project(project.id)
        )
        last_activity = project.updated_at
        if metrics.get("last_session_at"):
            session_activity = datetime.fromisoformat(str(metrics["last_session_at"]).replace("Z", "+00:00"))
            if session_activity.tzinfo is None:
                session_activity = session_activity.replace(tzinfo=timezone.utc)
            last_activity = max(last_activity, session_activity)
        summaries.append(DashboardProject(
            **project.model_dump(),
            session_count=int(metrics.get("session_count", 0)),
            result_count=int(metrics.get("result_count", 0)),
            reviewed_count=int(metrics.get("reviewed_count", 0)),
            active_runs=max(int(metrics.get("active_sessions", 0)), memory_active),
            last_activity=last_activity,
        ))
    summaries.sort(key=lambda item: item.last_activity, reverse=True)
    recent_cutoff = datetime.now(timezone.utc) - timedelta(days=7)
    return DashboardOverview(
        total_projects=len(summaries),
        configured_targets=sum(bool(item.target) for item in summaries),
        recent_projects=sum(item.last_activity >= recent_cutoff for item in summaries),
        total_sessions=sum(item.session_count for item in summaries),
        total_results=sum(item.result_count for item in summaries),
        reviewed_results=sum(item.reviewed_count for item in summaries),
        active_runs=sum(item.active_runs for item in summaries),
        projects=summaries,
    )


@router.post(
    "/projects",
    response_model=Project,
    status_code=status.HTTP_201_CREATED,
    tags=["projects"],
)
def create_project(
    payload: ProjectCreate, store: ProjectStore = Depends(get_project_store)
) -> Project:
    return store.create(payload)


@router.get("/projects/{project_id}", response_model=Project, tags=["projects"])
def get_project(
    project_id: str, store: ProjectStore = Depends(get_project_store)
) -> Project:
    try:
        return store.get(project_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc


@router.patch("/projects/{project_id}", response_model=Project, tags=["projects"])
def update_project(
    project_id: str,
    payload: ProjectUpdate,
    store: ProjectStore = Depends(get_project_store),
) -> Project:
    try:
        return store.update(project_id, payload)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc


@router.get(
    "/projects/{project_id}/scope", response_model=ScopeConfig, tags=["projects"]
)
def get_project_scope(
    project_id: str, store: ProjectStore = Depends(get_project_store)
) -> ScopeConfig:
    try:
        return store.get_scope(project_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc


@router.put(
    "/projects/{project_id}/scope", response_model=ScopeConfig, tags=["projects"]
)
def put_project_scope(
    project_id: str,
    payload: ScopeConfig,
    store: ProjectStore = Depends(get_project_store),
) -> ScopeConfig:
    try:
        return store.put_scope(project_id, payload)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc


@router.get(
    "/projects/{project_id}/notes", response_model=ProjectNotes, tags=["projects"]
)
def get_project_notes(
    project_id: str, store: ProjectStore = Depends(get_project_store)
) -> ProjectNotes:
    try:
        return ProjectNotes(content=store.get_notes(project_id))
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc


@router.put(
    "/projects/{project_id}/notes", response_model=ProjectNotes, tags=["projects"]
)
def put_project_notes(
    project_id: str,
    payload: ProjectNotes,
    store: ProjectStore = Depends(get_project_store),
) -> ProjectNotes:
    try:
        return ProjectNotes(content=store.put_notes(project_id, payload.content))
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc


@router.get(
    "/projects/{project_id}/auth-sessions",
    response_model=list[AuthSessionEntry],
    tags=["projects"],
)
def list_auth_sessions(
    project_id: str,
    store: ProjectStore = Depends(get_project_store),
    repositories: LegacyRepositoryFactory = Depends(get_repository_factory),
) -> list[AuthSessionEntry]:
    try:
        repository = repositories(store.project_dir(project_id))
        return [AuthSessionEntry.model_validate(item) for item in repository.list_auth_sessions()]
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc
    except PyMongoError as exc:
        raise HTTPException(status_code=503, detail="Database unavailable") from exc


@router.post(
    "/projects/{project_id}/auth-sessions",
    response_model=AuthSessionEntry,
    status_code=status.HTTP_201_CREATED,
    tags=["projects"],
)
def create_auth_session(
    project_id: str,
    payload: AuthSessionInput,
    store: ProjectStore = Depends(get_project_store),
    repositories: LegacyRepositoryFactory = Depends(get_repository_factory),
) -> AuthSessionEntry:
    try:
        repository = repositories(store.project_dir(project_id))
        session_id = repository.create_auth_session(payload.name, payload.headers, payload.params)
        session = repository.get_auth_session(session_id)
        if not session:
            raise HTTPException(status_code=500, detail="Session could not be created")
        return AuthSessionEntry.model_validate(session)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc
    except PyMongoError as exc:
        raise HTTPException(status_code=503, detail="Database unavailable") from exc


@router.put(
    "/projects/{project_id}/auth-sessions/{session_id}",
    response_model=AuthSessionEntry,
    tags=["projects"],
)
def update_auth_session(
    project_id: str,
    session_id: str,
    payload: AuthSessionInput,
    store: ProjectStore = Depends(get_project_store),
    repositories: LegacyRepositoryFactory = Depends(get_repository_factory),
) -> AuthSessionEntry:
    try:
        repository = repositories(store.project_dir(project_id))
        if not repository.get_auth_session(session_id):
            raise HTTPException(status_code=404, detail="Auth session not found")
        repository.update_auth_session(session_id, payload.name, payload.headers, payload.params)
        session = repository.get_auth_session(session_id)
        return AuthSessionEntry.model_validate(session)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc
    except PyMongoError as exc:
        raise HTTPException(status_code=503, detail="Database unavailable") from exc


@router.delete(
    "/projects/{project_id}/auth-sessions/{session_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["projects"],
)
def delete_auth_session(
    project_id: str,
    session_id: str,
    store: ProjectStore = Depends(get_project_store),
    repositories: LegacyRepositoryFactory = Depends(get_repository_factory),
) -> Response:
    try:
        repository = repositories(store.project_dir(project_id))
        if not repository.get_auth_session(session_id):
            raise HTTPException(status_code=404, detail="Auth session not found")
        repository.delete_auth_session(session_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc
    except PyMongoError as exc:
        raise HTTPException(status_code=503, detail="Database unavailable") from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)
