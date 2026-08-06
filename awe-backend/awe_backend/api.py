import asyncio
import base64
import fnmatch
from functools import lru_cache
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request, Response, UploadFile, File, WebSocket, WebSocketDisconnect, status
from pymongo.errors import PyMongoError
from bson import ObjectId

from .auth import CSRF_COOKIE, SESSION_COOKIE, AuthService, AuthenticationError
from .config import Settings, get_settings
from .jobs import JobNotFoundError, PipelineJobManager
from .projects import ProjectNotFoundError, ProjectStore
from .pipelines import PipelineCatalog
from .repositories import LegacyRepositoryFactory
from .replay import HttpReplayService
from .docker_service import DockerService
from .vault import VaultService
from .browser import BrowserSessionManager, BrowserUnavailable
from .testing_services import IntruderService, ProxyControlService, WebSocketClientService
import docker
from .schemas import (
    HealthResponse,
    AuthSession,
    LoginRequest,
    SetupRequest,
    SetupStatus,
    Project,
    ProjectCreate,
    ProjectUpdate,
    ScopeConfig,
    PipelineTemplate,
    PipelineJob,
    PipelineRunCreate,
    ScanSession,
    StoredResult,
    TrafficEntry,
    RepeaterRequest,
    RepeaterResponse,
    ProjectSettings,
    DockerContainer,
    VaultItem,
    VaultItemInput,
    VaultCategory, VaultCategoryInput, VaultItemRecord, VaultItemRecordInput,
    IntruderRequest,
    IntruderResult,
    WebSocketConnection,
    WebSocketFrame,
    WebSocketSendRequest,
    WebSocketSendResponse,
    InterceptConfig,
    InterceptRequest,
    InterceptDecision,
    BrowserSession, BrowserNavigate, BrowserViewport,
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


def get_replay_service() -> HttpReplayService:
    return HttpReplayService()


def get_docker_service() -> DockerService: return DockerService()


def get_vault_service(settings: Settings = Depends(get_settings)) -> VaultService:
    return VaultService(settings.secret_key)


@lru_cache
def get_browser_manager() -> BrowserSessionManager:
    return BrowserSessionManager()


def get_intruder_service() -> IntruderService:
    return IntruderService()


def get_proxy_control(settings: Settings = Depends(get_settings)) -> ProxyControlService:
    try:
        return ProxyControlService(settings.legacy_src_dir)
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=503, detail="AWE proxy is unavailable") from exc


def get_websocket_client() -> WebSocketClientService:
    return WebSocketClientService()


@lru_cache
def _auth_service(settings_json: str) -> AuthService:
    return AuthService(Settings.model_validate_json(settings_json))


def get_auth_service(settings: Settings = Depends(get_settings)) -> AuthService:
    return _auth_service(settings.model_dump_json())


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
    _set_auth_cookies(response, auth, token, session.csrf)
    return AuthSession(username=session.username, csrf_token=session.csrf)


def _set_auth_cookies(response: Response, auth: AuthService, token: str, csrf: str) -> None:
    cookie_options = {
        "secure": auth.settings.secure_cookies,
        "samesite": "strict",
        "max_age": auth.settings.session_ttl_seconds,
        "path": "/",
    }
    response.set_cookie(SESSION_COOKIE, token, httponly=True, **cookie_options)
    response.set_cookie(CSRF_COOKIE, csrf, httponly=False, **cookie_options)


@router.get("/auth/setup-status", response_model=SetupStatus, tags=["authentication"])
def setup_status(auth: AuthService = Depends(get_auth_service)) -> SetupStatus:
    return SetupStatus(configured=auth.is_configured())


@router.post(
    "/auth/setup",
    response_model=AuthSession,
    status_code=status.HTTP_201_CREATED,
    tags=["authentication"],
)
def setup_account(
    payload: SetupRequest,
    response: Response,
    auth: AuthService = Depends(get_auth_service),
) -> AuthSession:
    try:
        token, session = auth.setup(payload.username, payload.password)
    except AuthenticationError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    _set_auth_cookies(response, auth, token, session.csrf)
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
        sessions = repository.list_sessions(limit)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc
    except PyMongoError as exc:
        raise HTTPException(status_code=503, detail="Database unavailable") from exc
    return [ScanSession.model_validate(item) for item in sessions]


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
        session = repository.get_session(session_id)
        results = repository.get_results(session_id, category=category, limit=limit) if session else []
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc
    except PyMongoError as exc:
        raise HTTPException(status_code=503, detail="Database unavailable") from exc
    if session is None:
        raise HTTPException(status_code=404, detail="Scan session not found")
    return [
        StoredResult.model_validate(item)
        for item in results
    ]


def _traffic_entry(doc: dict) -> TrafficEntry:
    return TrafficEntry.model_validate({**doc, "id": str(doc["_id"])})


@router.get("/projects/{project_id}/traffic", response_model=list[TrafficEntry], tags=["proxy"])
def list_traffic(
    project_id: str,
    host: str | None = None,
    method: str | None = None,
    limit: int = 200,
    store: ProjectStore = Depends(get_project_store),
    repositories: LegacyRepositoryFactory = Depends(get_repository_factory),
) -> list[TrafficEntry]:
    try:
        store.project_dir(project_id)
        query: dict = {}
        if host:
            query["host"] = host
        if method:
            query["method"] = method.upper()
        docs = repositories.traffic().find(query).sort("timestamp", -1).limit(max(1, min(limit, 1000)))
        return [_traffic_entry(doc) for doc in docs]
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
        store.project_dir(project_id)
        doc = repositories.traffic().find_one({"_id": ObjectId(traffic_id)})
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc
    except (PyMongoError, ValueError) as exc:
        if isinstance(exc, PyMongoError):
            raise HTTPException(status_code=503, detail="Database unavailable") from exc
        raise HTTPException(status_code=404, detail="Traffic entry not found") from exc
    if not doc:
        raise HTTPException(status_code=404, detail="Traffic entry not found")
    return _traffic_entry(doc)


def _host_in_project_scope(url: str, target: str, scope: ScopeConfig) -> bool:
    host = (urlsplit(url).hostname or "").lower()
    if not host or urlsplit(url).scheme not in ("http", "https"):
        return False
    target_host = (urlsplit(target if "://" in target else f"https://{target}").hostname or "").lower()
    excluded = [entry.value.lower().lstrip("*.") for entry in scope.entries if not entry.in_scope]
    if any(host == value or host.endswith(f".{value}") for value in excluded):
        return False
    included = [entry for entry in scope.entries if entry.in_scope]
    if not included:
        return host == target_host or (scope.include_subdomains and host.endswith(f".{target_host}"))
    for entry in included:
        value = entry.value
        if entry.entry_type == "url" and url.startswith(value): return True
        if entry.entry_type == "wildcard" and fnmatch.fnmatch(host, value.lower()): return True
        domain = value.lower().lstrip("*.")
        if host == domain or (scope.include_subdomains and host.endswith(f".{domain}")): return True
    return False


@router.post("/projects/{project_id}/repeater/send", response_model=RepeaterResponse, tags=["testing"])
async def send_repeater_request(
    project_id: str,
    payload: RepeaterRequest,
    store: ProjectStore = Depends(get_project_store),
    replay: HttpReplayService = Depends(get_replay_service),
) -> RepeaterResponse:
    try:
        project = store.get(project_id)
        scope = store.get_scope(project_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc
    if not _host_in_project_scope(payload.url, project.target, scope):
        raise HTTPException(status_code=403, detail="URL is outside the project scope")
    try:
        return await replay.send(payload)
    except httpx.TimeoutException as exc:
        raise HTTPException(status_code=504, detail="Target request timed out") from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"Target request failed: {exc}") from exc


@router.get("/projects/{project_id}/settings", response_model=ProjectSettings, tags=["settings"])
def read_project_settings(project_id: str, store: ProjectStore = Depends(get_project_store)) -> ProjectSettings:
    try: return ProjectSettings.model_validate(store.get_settings(project_id))
    except ProjectNotFoundError as exc: raise HTTPException(status_code=404, detail="Project not found") from exc


@router.put("/projects/{project_id}/settings", response_model=ProjectSettings, tags=["settings"])
def write_project_settings(project_id: str, payload: ProjectSettings, store: ProjectStore = Depends(get_project_store)) -> ProjectSettings:
    try: return ProjectSettings.model_validate(store.put_settings(project_id, payload.model_dump()))
    except ProjectNotFoundError as exc: raise HTTPException(status_code=404, detail="Project not found") from exc


@router.get("/docker/containers", response_model=list[DockerContainer], tags=["docker"])
def list_docker_containers(service: DockerService = Depends(get_docker_service)) -> list[DockerContainer]:
    try: return service.list()
    except docker.errors.DockerException as exc: raise HTTPException(status_code=503, detail="Docker is unavailable") from exc


@router.post("/docker/containers/{container_id}/stop", status_code=204, tags=["docker"])
def stop_docker_container(container_id: str, service: DockerService = Depends(get_docker_service)) -> None:
    try: service.stop(container_id)
    except PermissionError as exc: raise HTTPException(status_code=403, detail=str(exc)) from exc
    except docker.errors.DockerException as exc: raise HTTPException(status_code=404, detail="Container not found") from exc


@router.delete("/docker/containers/{container_id}", status_code=204, tags=["docker"])
def remove_docker_container(container_id: str, service: DockerService = Depends(get_docker_service)) -> None:
    try: service.remove(container_id)
    except PermissionError as exc: raise HTTPException(status_code=403, detail=str(exc)) from exc
    except docker.errors.DockerException as exc: raise HTTPException(status_code=404, detail="Container not found") from exc


@router.get("/projects/{project_id}/vault", response_model=list[VaultItem], tags=["vault"])
def list_vault(project_id: str, store: ProjectStore = Depends(get_project_store), vault: VaultService = Depends(get_vault_service)) -> list[VaultItem]:
    return vault.list(store.project_dir(project_id))


@router.post("/projects/{project_id}/vault", response_model=VaultItem, status_code=201, tags=["vault"])
def create_vault_item(project_id: str, payload: VaultItemInput, store: ProjectStore = Depends(get_project_store), vault: VaultService = Depends(get_vault_service)) -> VaultItem:
    return vault.create(store.project_dir(project_id), payload)


@router.delete("/projects/{project_id}/vault/{item_id}", status_code=204, tags=["vault"])
def delete_vault_item(project_id: str, item_id: str, store: ProjectStore = Depends(get_project_store), vault: VaultService = Depends(get_vault_service)) -> None:
    if not vault.delete(store.project_dir(project_id), item_id): raise HTTPException(status_code=404, detail="Vault item not found")


@router.get("/vault/categories", response_model=list[VaultCategory], tags=["vault"])
def list_vault_categories(vault: VaultService = Depends(get_vault_service)) -> list[VaultCategory]:
    return [VaultCategory.model_validate(item) for item in vault.categories()]


@router.post("/vault/categories", response_model=VaultCategory, status_code=201, tags=["vault"])
def create_vault_category(payload: VaultCategoryInput, vault: VaultService = Depends(get_vault_service)) -> VaultCategory:
    return VaultCategory.model_validate(vault.add_category(payload.name, payload.accent))


@router.patch("/vault/categories/{category_id}", response_model=VaultCategory, tags=["vault"])
def update_vault_category(category_id: str, payload: VaultCategoryInput, vault: VaultService = Depends(get_vault_service)) -> VaultCategory:
    category = vault.update_category(category_id, payload.name, payload.accent)
    if category is None: raise HTTPException(status_code=404, detail="Vault category not found")
    return VaultCategory.model_validate(category)


@router.delete("/vault/categories/{category_id}", status_code=204, tags=["vault"])
def delete_vault_category(category_id: str, vault: VaultService = Depends(get_vault_service)) -> None:
    if not any(item["id"] == category_id for item in vault.categories()): raise HTTPException(status_code=404, detail="Vault category not found")
    vault.delete_category(category_id)


@router.get("/vault/categories/{category_id}/items", response_model=list[VaultItemRecord], tags=["vault"])
def list_vault_items(category_id: str, vault: VaultService = Depends(get_vault_service)) -> list[VaultItemRecord]:
    return [VaultItemRecord.model_validate(item) for item in vault.items(category_id)]


@router.post("/vault/categories/{category_id}/items", response_model=VaultItemRecord, status_code=201, tags=["vault"])
def create_vault_item_record(category_id: str, payload: VaultItemRecordInput, vault: VaultService = Depends(get_vault_service)) -> VaultItemRecord:
    if payload.type == "link" and not payload.url: raise HTTPException(status_code=422, detail="Link URL is required")
    if payload.type == "note" and payload.text is None: raise HTTPException(status_code=422, detail="Note text is required")
    values = {"url": payload.url} if payload.type == "link" else {"text": payload.text, "lang": payload.lang}
    return VaultItemRecord.model_validate(vault.add_item(category_id, payload.type, payload.title or payload.url or "Note", **values))


@router.post("/vault/categories/{category_id}/files", response_model=VaultItemRecord, status_code=201, tags=["vault"])
async def upload_vault_file(category_id: str, upload: UploadFile = File(...), vault: VaultService = Depends(get_vault_service)) -> VaultItemRecord:
    content = await upload.read()
    if len(content) > 25_000_000: raise HTTPException(status_code=413, detail="Vault files are limited to 25 MB")
    return VaultItemRecord.model_validate(vault.add_file(category_id, upload.filename or "file", content))


@router.patch("/vault/items/{item_id}", response_model=VaultItemRecord, tags=["vault"])
def update_vault_item_record(item_id: str, payload: VaultItemRecordInput, vault: VaultService = Depends(get_vault_service)) -> VaultItemRecord:
    item = vault.update_item(item_id, title=payload.title, url=payload.url, text=payload.text, lang=payload.lang)
    if item is None: raise HTTPException(status_code=404, detail="Vault item not found")
    return VaultItemRecord.model_validate(item)


@router.delete("/vault/items/{item_id}", status_code=204, tags=["vault"])
def delete_vault_item_record(item_id: str, vault: VaultService = Depends(get_vault_service)) -> None:
    if not vault.delete_item(item_id): raise HTTPException(status_code=404, detail="Vault item not found")


@router.post("/projects/{project_id}/intruder/runs", response_model=list[IntruderResult], tags=["testing"])
async def run_intruder(
    project_id: str,
    payload: IntruderRequest,
    store: ProjectStore = Depends(get_project_store),
    service: IntruderService = Depends(get_intruder_service),
) -> list[IntruderResult]:
    try:
        project = store.get(project_id)
        scope = store.get_scope(project_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc
    urls = [payload.url.replace(payload.placeholder, value) for value in payload.payloads]
    if not all(_host_in_project_scope(url, project.target, scope) for url in urls):
        raise HTTPException(status_code=403, detail="Every generated URL must be inside the project scope")
    try:
        return await service.run(payload)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


def _websocket_connection(doc: dict) -> WebSocketConnection:
    return WebSocketConnection.model_validate({**doc, "id": str(doc["_id"])})


def _websocket_frame(doc: dict) -> WebSocketFrame:
    return WebSocketFrame.model_validate({**doc, "id": str(doc["_id"])})


@router.get("/projects/{project_id}/websockets", response_model=list[WebSocketConnection], tags=["websockets"])
def list_websocket_connections(project_id: str, limit: int = 200, store: ProjectStore = Depends(get_project_store), repositories: LegacyRepositoryFactory = Depends(get_repository_factory)) -> list[WebSocketConnection]:
    try:
        store.project_dir(project_id)
        docs = repositories.websocket_db().ws_connections.find({}).sort("opened_at", -1).limit(max(1, min(limit, 1000)))
        return [_websocket_connection(doc) for doc in docs]
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc
    except PyMongoError as exc:
        raise HTTPException(status_code=503, detail="Database unavailable") from exc


@router.get("/projects/{project_id}/websockets/{connection_id}/frames", response_model=list[WebSocketFrame], tags=["websockets"])
def list_websocket_frames(project_id: str, connection_id: str, store: ProjectStore = Depends(get_project_store), repositories: LegacyRepositoryFactory = Depends(get_repository_factory)) -> list[WebSocketFrame]:
    try:
        store.project_dir(project_id)
        docs = repositories.websocket_db().ws_frames.find({"conn_id": connection_id}).sort("timestamp", 1).limit(2000)
        return [_websocket_frame(doc) for doc in docs]
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc
    except PyMongoError as exc:
        raise HTTPException(status_code=503, detail="Database unavailable") from exc


@router.post("/projects/{project_id}/websockets/send", response_model=WebSocketSendResponse, tags=["websockets"])
async def send_websocket_message(project_id: str, payload: WebSocketSendRequest, store: ProjectStore = Depends(get_project_store), service: WebSocketClientService = Depends(get_websocket_client)) -> WebSocketSendResponse:
    try:
        project = store.get(project_id)
        scope = store.get_scope(project_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc
    http_url = payload.url.replace("wss://", "https://", 1).replace("ws://", "http://", 1)
    if not _host_in_project_scope(http_url, project.target, scope):
        raise HTTPException(status_code=403, detail="WebSocket URL is outside the project scope")
    try:
        return WebSocketSendResponse(reply=await service.send(payload.url, payload.message))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"WebSocket connection failed: {exc}") from exc


@router.put("/projects/{project_id}/intercept", status_code=204, tags=["proxy"])
def configure_intercept(project_id: str, payload: InterceptConfig, store: ProjectStore = Depends(get_project_store), control: ProxyControlService = Depends(get_proxy_control)) -> None:
    try:
        store.project_dir(project_id)
        control.set_intercept(payload.enabled, payload.patterns)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc
    except ConnectionError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.get("/projects/{project_id}/intercept/pending", response_model=list[InterceptRequest], tags=["proxy"])
def list_pending_intercepts(project_id: str, store: ProjectStore = Depends(get_project_store), control: ProxyControlService = Depends(get_proxy_control)) -> list[InterceptRequest]:
    try:
        store.project_dir(project_id)
        return [InterceptRequest.model_validate(item) for item in control.pending()]
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc


@router.post("/projects/{project_id}/intercept/{request_id}/resolve", status_code=204, tags=["proxy"])
def resolve_intercept(project_id: str, request_id: str, payload: InterceptDecision, store: ProjectStore = Depends(get_project_store), control: ProxyControlService = Depends(get_proxy_control)) -> None:
    try:
        store.project_dir(project_id)
        control.resolve(request_id, payload.decision, payload.headers, payload.body_b64)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc
    except ConnectionError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


def _browser_model(state) -> BrowserSession:
    return BrowserSession.model_validate(state.__dict__)


def _browser_project(project_id: str, store: ProjectStore):
    try:
        return store.get(project_id), store.get_scope(project_id), store.get_settings(project_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc


@router.get("/projects/{project_id}/browser/sessions", response_model=list[BrowserSession], tags=["browser"])
def list_browser_sessions(project_id: str, store: ProjectStore = Depends(get_project_store), manager: BrowserSessionManager = Depends(get_browser_manager)) -> list[BrowserSession]:
    store.project_dir(project_id)
    return [_browser_model(item) for item in manager.list(project_id)]


@router.post("/projects/{project_id}/browser/sessions", response_model=BrowserSession, status_code=201, tags=["browser"])
async def create_browser_session(project_id: str, payload: BrowserViewport = BrowserViewport(), store: ProjectStore = Depends(get_project_store), manager: BrowserSessionManager = Depends(get_browser_manager)) -> BrowserSession:
    _browser_project(project_id, store)
    settings = store.get_settings(project_id)
    try:
        state = await manager.create(project_id, settings.get("proxy_port", 8080), payload.width, payload.height)
        return _browser_model(state)
    except BrowserUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.get("/projects/{project_id}/browser/sessions/{session_id}/screenshot", tags=["browser"])
async def browser_screenshot(project_id: str, session_id: str, store: ProjectStore = Depends(get_project_store), manager: BrowserSessionManager = Depends(get_browser_manager)) -> Response:
    store.project_dir(project_id)
    try:
        state, image = await manager.screenshot(session_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Browser session not found") from exc
    if state.project_id != project_id:
        raise HTTPException(status_code=404, detail="Browser session not found")
    return Response(content=image, media_type="image/png", headers={"X-AWE-Browser-Url": state.url})


@router.post("/projects/{project_id}/browser/sessions/{session_id}/navigate", response_model=BrowserSession, tags=["browser"])
async def navigate_browser(project_id: str, session_id: str, payload: BrowserNavigate, store: ProjectStore = Depends(get_project_store), manager: BrowserSessionManager = Depends(get_browser_manager)) -> BrowserSession:
    project, scope, _ = _browser_project(project_id, store)
    if not _host_in_project_scope(payload.url, project.target, scope):
        raise HTTPException(status_code=403, detail="URL is outside the project scope")
    try:
        state = manager.get(session_id).state
        if state.project_id != project_id:
            raise KeyError(session_id)
        return _browser_model(await manager.navigate(session_id, payload.url))
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Browser session not found") from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Browser navigation failed: {exc}") from exc


@router.delete("/projects/{project_id}/browser/sessions/{session_id}", status_code=204, tags=["browser"])
async def close_browser(project_id: str, session_id: str, store: ProjectStore = Depends(get_project_store), manager: BrowserSessionManager = Depends(get_browser_manager)) -> None:
    store.project_dir(project_id)
    try:
        if manager.get(session_id).state.project_id != project_id:
            raise KeyError(session_id)
        await manager.close(session_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Browser session not found") from exc


@router.websocket("/projects/{project_id}/browser/sessions/{session_id}/stream")
async def browser_stream(project_id: str, session_id: str, websocket: WebSocket, store: ProjectStore = Depends(get_project_store), manager: BrowserSessionManager = Depends(get_browser_manager)) -> None:
    try:
        store.project_dir(project_id)
        if manager.get(session_id).state.project_id != project_id:
            raise KeyError(session_id)
    except (ProjectNotFoundError, KeyError):
        await websocket.close(code=4404, reason="Browser session not found")
        return
    await websocket.accept()
    try:
        while True:
            receive_task = asyncio.create_task(websocket.receive_json())
            tick_task = asyncio.create_task(asyncio.sleep(0.25))
            done, pending = await asyncio.wait({receive_task, tick_task}, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            if tick_task in done:
                state, image = await manager.screenshot(session_id)
                await websocket.send_json({"type": "frame", "session": _browser_model(state).model_dump(mode="json"), "image": base64.b64encode(image).decode()})
                continue
            action = receive_task.result()
            if action.get("type") == "close":
                break
            try:
                await manager.interact(session_id, action)
            except (KeyError, ValueError) as exc:
                await websocket.send_json({"type": "error", "message": str(exc)})
    except (WebSocketDisconnect, KeyError):
        pass
