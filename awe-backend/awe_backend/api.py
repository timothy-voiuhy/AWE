import asyncio
from functools import lru_cache

from fastapi import APIRouter, Depends, HTTPException, Request, Response, WebSocket, WebSocketDisconnect, status

from .auth import CSRF_COOKIE, SESSION_COOKIE, AuthService, AuthenticationError
from .config import Settings, get_settings
from .jobs import JobNotFoundError, PipelineJobManager
from .projects import ProjectNotFoundError, ProjectStore
from .pipelines import PipelineCatalog
from .repositories import LegacyRepositoryFactory
from .schemas import (
    HealthResponse,
    AuthSession,
    LoginRequest,
    Project,
    ProjectCreate,
    ProjectUpdate,
    ScopeConfig,
    PipelineTemplate,
    PipelineJob,
    PipelineRunCreate,
    ScanSession,
    StoredResult,
)

router = APIRouter()


@lru_cache
def _store_for_workspace(workspace: str) -> ProjectStore:
    from pathlib import Path

    return ProjectStore(Path(workspace))


def get_project_store(settings: Settings = Depends(get_settings)) -> ProjectStore:
    return _store_for_workspace(str(settings.workspace_dir.resolve()))


def get_pipeline_catalog(settings: Settings = Depends(get_settings)) -> PipelineCatalog:
    return PipelineCatalog(settings.legacy_src_dir)


@lru_cache
def _job_manager(legacy_src: str, mongo_uri: str) -> PipelineJobManager:
    from pathlib import Path

    return PipelineJobManager(Path(legacy_src), mongo_uri)


def get_job_manager(settings: Settings = Depends(get_settings)) -> PipelineJobManager:
    return _job_manager(str(settings.legacy_src_dir.resolve()), settings.mongo_uri)


def get_repository_factory(
    settings: Settings = Depends(get_settings),
) -> LegacyRepositoryFactory:
    return LegacyRepositoryFactory(settings.legacy_src_dir, settings.mongo_uri)


def get_auth_service(settings: Settings = Depends(get_settings)) -> AuthService:
    return AuthService(settings)


@router.get("/health", response_model=HealthResponse, tags=["system"])
def health(settings: Settings = Depends(get_settings)) -> HealthResponse:
    return HealthResponse(status="ok", service=settings.app_name, version="0.1.0")


@router.post("/auth/login", response_model=AuthSession, tags=["authentication"])
def login(
    payload: LoginRequest,
    response: Response,
    auth: AuthService = Depends(get_auth_service),
) -> AuthSession:
    try:
        token, session = auth.login(payload.username, payload.password)
    except AuthenticationError as exc:
        raise HTTPException(status_code=401, detail="Invalid credentials") from exc
    cookie_options = {
        "secure": auth.settings.secure_cookies,
        "samesite": "strict",
        "max_age": auth.settings.session_ttl_seconds,
        "path": "/",
    }
    response.set_cookie(SESSION_COOKIE, token, httponly=True, **cookie_options)
    response.set_cookie(CSRF_COOKIE, session.csrf, httponly=False, **cookie_options)
    return AuthSession(username=session.username, csrf_token=session.csrf)


@router.get("/auth/session", response_model=AuthSession, tags=["authentication"])
def auth_session(
    request: Request,
    auth: AuthService = Depends(get_auth_service),
) -> AuthSession:
    session = auth.verify(request.cookies.get(SESSION_COOKIE, ""))
    return AuthSession(username=session.username, csrf_token=session.csrf)


@router.post("/auth/logout", status_code=status.HTTP_204_NO_CONTENT, tags=["authentication"])
def logout(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")


@router.get("/pipelines", response_model=list[PipelineTemplate], tags=["pipelines"])
def list_pipelines(
    catalog: PipelineCatalog = Depends(get_pipeline_catalog),
) -> list[PipelineTemplate]:
    return catalog.list()


@router.get("/projects", response_model=list[Project], tags=["projects"])
def list_projects(store: ProjectStore = Depends(get_project_store)) -> list[Project]:
    return store.list()


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
    "/projects/{project_id}/pipeline-runs",
    response_model=list[PipelineJob],
    tags=["pipeline runs"],
)
def list_pipeline_runs(
    project_id: str,
    store: ProjectStore = Depends(get_project_store),
    jobs: PipelineJobManager = Depends(get_job_manager),
) -> list[PipelineJob]:
    try:
        store.get(project_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc
    return jobs.list_for_project(project_id)


@router.post(
    "/projects/{project_id}/pipeline-runs",
    response_model=PipelineJob,
    status_code=status.HTTP_202_ACCEPTED,
    tags=["pipeline runs"],
)
def start_pipeline_run(
    project_id: str,
    payload: PipelineRunCreate,
    store: ProjectStore = Depends(get_project_store),
    jobs: PipelineJobManager = Depends(get_job_manager),
) -> PipelineJob:
    try:
        project = store.get(project_id)
        project_dir = store.project_dir(project_id)
        scope = store.get_scope(project_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc
    if not project.target:
        raise HTTPException(status_code=409, detail="Configure a target before running a pipeline")
    try:
        return jobs.start(
            project_id=project_id,
            project_dir=project_dir,
            pipeline_key=payload.pipeline_key,
            target=project.target,
            params=payload.params,
            in_scope=[entry.value for entry in scope.entries if entry.in_scope],
            out_of_scope=[entry.value for entry in scope.entries if not entry.in_scope],
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


def _project_job(project_id: str, job_id: str, jobs: PipelineJobManager) -> PipelineJob:
    try:
        job = jobs.get(job_id)
    except JobNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Pipeline run not found") from exc
    if job.project_id != project_id:
        raise HTTPException(status_code=404, detail="Pipeline run not found")
    return job


@router.get(
    "/projects/{project_id}/pipeline-runs/{job_id}",
    response_model=PipelineJob,
    tags=["pipeline runs"],
)
def get_pipeline_run(
    project_id: str,
    job_id: str,
    jobs: PipelineJobManager = Depends(get_job_manager),
) -> PipelineJob:
    return _project_job(project_id, job_id, jobs)


@router.post(
    "/projects/{project_id}/pipeline-runs/{job_id}/cancel",
    response_model=PipelineJob,
    tags=["pipeline runs"],
)
def cancel_pipeline_run(
    project_id: str,
    job_id: str,
    jobs: PipelineJobManager = Depends(get_job_manager),
) -> PipelineJob:
    _project_job(project_id, job_id, jobs)
    try:
        return jobs.stop(job_id)
    except JobNotFoundError as exc:
        raise HTTPException(status_code=409, detail="Pipeline run is no longer active") from exc


@router.websocket("/projects/{project_id}/pipeline-runs/{job_id}/events")
async def pipeline_run_events(
    websocket: WebSocket,
    project_id: str,
    job_id: str,
    jobs: PipelineJobManager = Depends(get_job_manager),
):
    try:
        job = jobs.get(job_id)
    except JobNotFoundError:
        await websocket.close(code=4404, reason="Pipeline run not found")
        return
    if job.project_id != project_id:
        await websocket.close(code=4404, reason="Pipeline run not found")
        return

    await websocket.accept()
    after = 0
    try:
        while True:
            job = jobs.get(job_id)
            new_events = [event for event in job.events if event.sequence > after]
            if new_events:
                after = new_events[-1].sequence
            await websocket.send_json({
                "job": job.model_dump(mode="json", exclude={"events"}),
                "events": [event.model_dump(mode="json") for event in new_events],
            })
            if job.status in ("completed", "failed", "stopped"):
                await websocket.close(code=1000)
                return
            await asyncio.sleep(0.25)
    except (WebSocketDisconnect, JobNotFoundError):
        return


@router.get(
    "/projects/{project_id}/sessions",
    response_model=list[ScanSession],
    tags=["results"],
)
def list_scan_sessions(
    project_id: str,
    limit: int = 50,
    store: ProjectStore = Depends(get_project_store),
    repositories: LegacyRepositoryFactory = Depends(get_repository_factory),
) -> list[ScanSession]:
    limit = max(1, min(limit, 200))
    try:
        repository = repositories(store.project_dir(project_id))
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc
    return [ScanSession.model_validate(item) for item in repository.list_sessions(limit)]


@router.get(
    "/projects/{project_id}/sessions/{session_id}/results",
    response_model=list[StoredResult],
    tags=["results"],
)
def list_session_results(
    project_id: str,
    session_id: str,
    category: str | None = None,
    limit: int = 1000,
    store: ProjectStore = Depends(get_project_store),
    repositories: LegacyRepositoryFactory = Depends(get_repository_factory),
) -> list[StoredResult]:
    limit = max(1, min(limit, 5000))
    try:
        repository = repositories(store.project_dir(project_id))
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc
    if repository.get_session(session_id) is None:
        raise HTTPException(status_code=404, detail="Scan session not found")
    return [
        StoredResult.model_validate(item)
        for item in repository.get_results(session_id, category=category, limit=limit)
    ]
