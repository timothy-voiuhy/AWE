import asyncio
import base64
import fnmatch
import re
import docker.errors
from pathlib import Path
from functools import lru_cache
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request, Response, UploadFile, File, WebSocket, WebSocketDisconnect, status
from fastapi.responses import FileResponse
from pymongo import MongoClient
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
from .docker_operations import DockerOperationManager, DockerOperationNotFound
from .vault import VaultService
from .browser import BrowserSessionManager, BrowserUnavailable
from .ai_service import AIService
from .terminal import TerminalManager
from .terminal_profiles import TerminalProfileStore
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
    ProjectNotes,
    AuthSessionInput,
    AuthSessionEntry,
    MethodologyStateInput,
    MethodologyCategory,
    MethodologyDetail,
    PipelineTemplate,
    PipelineJob,
    PipelineRunCreate,
    ScanSession,
    PipelineToolRun,
    StoredResult,
    TrafficEntry,
    DatabaseOverview,
    DatabaseStats,
    DatabaseCollectionStats,
    DatabaseCleanupResult,
    NetworkGraph, NetworkNode, NetworkEdge, NetworkManualNode,
    RepeaterRequest,
    RepeaterResponse,
    ProjectSettings,
    DockerContainer,
    DockerImage, DockerTool, DockerImagePull, DockerImageBuild, DockerToolCreate, DockerToolRun, DockerOperation,
    VaultItem,
    VaultItemInput,
    VaultCategory, VaultCategoryInput, VaultItemRecord, VaultItemRecordInput,
    JwtScanRequest,
    IntruderRequest,
    IntruderResult,
    IntruderJob,
    WebSocketConnection,
    WebSocketFrame,
    WebSocketSendRequest,
    WebSocketSendResponse,
    InterceptConfig,
    InterceptRequest,
    InterceptDecision,
    BrowserSession, BrowserNavigate, BrowserViewport,
    AIConversation, AIConversationDetail, AIChatRequest, AISettings,
    AIApproval, AIApprovalDecision,
    TerminalConnectRequest, TerminalSessionInfo,
    TerminalProfile, TerminalProfileInput,
)

router = APIRouter()

@router.post("/jwt/scan", tags=["jwt"])
def scan_jwt(payload: JwtScanRequest) -> dict:
    """Run jwt_tool in an isolated Docker container, matching the Qt workbench."""
    args = [payload.token]
    if payload.url and payload.mode != "decode":
        args += ["-t", payload.url]
        if payload.cookie:
            args += ["-rc", f"{payload.cookie}={payload.token}"]
        elif payload.header:
            args += ["-rh", f"{payload.header} {payload.token}"]
        args += ["-M", payload.mode]
    try:
        client = docker.from_env()
        output = client.containers.run("ticarpi/jwt_tool", args=args, remove=True, stdout=True, stderr=True)
    except docker.errors.ImageNotFound:
        try:
            client.images.pull("ticarpi/jwt_tool")
            output = client.containers.run("ticarpi/jwt_tool", args=args, remove=True, stdout=True, stderr=True)
        except Exception as exc:
            raise HTTPException(status_code=503, detail=f"jwt_tool unavailable: {exc}") from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"jwt_tool failed: {exc}") from exc
    return {"output": output.decode("utf-8", errors="replace") if isinstance(output, bytes) else str(output)}

@router.get("/proxy/info", tags=["proxy"])
def proxy_info(settings: Settings = Depends(get_settings)) -> dict:
    return {
        "host": settings.proxy_advertise_host,
        "port": settings.proxy_public_port,
        "certificate_url": "/api/v1/proxy/certificate",
        "scheme": "http",
    }

@router.get("/proxy/certificate", tags=["proxy"])
def download_proxy_certificate(settings: Settings = Depends(get_settings)) -> FileResponse:
    certificate = settings.proxy_certificate_path
    if not certificate.is_file():
        raise HTTPException(status_code=503, detail="Proxy certificate is not available yet")
    return FileResponse(certificate, media_type="application/x-x509-ca-cert", filename="awe-proxy-ca.crt")


def _mongo_collection_stats(database, collection_name: str) -> DatabaseCollectionStats:
    """Return lightweight Mongo collection statistics for the admin page."""
    stats = database.command("collStats", collection_name)
    return DatabaseCollectionStats(
        name=collection_name,
        documents=int(stats.get("count", 0)),
        storage_bytes=int(stats.get("storageSize", 0)),
        index_bytes=int(stats.get("totalIndexSize", 0)),
    )


@router.get("/database/overview", response_model=DatabaseOverview, tags=["database"])
def database_overview(settings: Settings = Depends(get_settings)) -> DatabaseOverview:
    """Return database and collection sizes without exposing stored contents."""
    try:
        with MongoClient(settings.mongo_uri, serverSelectionTimeoutMS=3000) as client:
            databases: list[DatabaseStats] = []
            for database_name in sorted(client.list_database_names()):
                if database_name in {"admin", "config", "local"}:
                    continue
                database = client[database_name]
                collections: list[DatabaseCollectionStats] = []
                for collection_name in sorted(database.list_collection_names()):
                    if collection_name.startswith("system."):
                        continue
                    try:
                        collections.append(_mongo_collection_stats(database, collection_name))
                    except PyMongoError:
                        # A collection can disappear while a cleanup operation
                        # is running. It should not make the whole dashboard fail.
                        continue
                if collections:
                    databases.append(DatabaseStats(
                        name=database_name,
                        documents=sum(item.documents for item in collections),
                        storage_bytes=sum(item.storage_bytes for item in collections),
                        index_bytes=sum(item.index_bytes for item in collections),
                        collections=collections,
                    ))
            return DatabaseOverview(databases=databases)
    except PyMongoError as exc:
        raise HTTPException(status_code=503, detail="Database unavailable") from exc


@router.delete("/database/traffic", response_model=DatabaseCleanupResult, tags=["database"])
def clear_all_proxy_traffic(settings: Settings = Depends(get_settings)) -> DatabaseCleanupResult:
    """Drop every captured proxy transaction and recreate its indexes.

    This is intentionally global: proxy traffic is shared by projects and can
    include captures from external devices. The UI must therefore require an
    explicit confirmation before calling this endpoint.
    """
    database_name = "awe_proxy_traffic"
    collection_name = "traffic"
    try:
        with MongoClient(settings.mongo_uri, serverSelectionTimeoutMS=3000) as client:
            database = client[database_name]
            try:
                stats = database.command("collStats", collection_name)
            except PyMongoError:
                stats = {}
            deleted_documents = int(stats.get("count", 0))
            released_storage = int(stats.get("storageSize", 0)) + int(stats.get("totalIndexSize", 0))
            database.drop_collection(collection_name)

            # Keep the proxy collection ready for new captures immediately;
            # dropping the collection also removes its old indexes.
            traffic = database[collection_name]
            traffic.create_index("host")
            traffic.create_index("project_id")
            traffic.create_index([("host", 1), ("timestamp", -1)])
            traffic.create_index([("host", 1), ("method", 1), ("path", 1)])
            return DatabaseCleanupResult(
                database=database_name,
                collection=collection_name,
                deleted_documents=deleted_documents,
                reclaimed_storage_bytes=released_storage,
            )
    except PyMongoError as exc:
        raise HTTPException(status_code=503, detail="Database unavailable") from exc
from .intruder_jobs import IntruderJobManager, IntruderJobNotFound


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


@lru_cache
def get_docker_operation_manager() -> DockerOperationManager: return DockerOperationManager()


def get_vault_service(settings: Settings = Depends(get_settings)) -> VaultService:
    return VaultService(settings.secret_key)


@lru_cache
def get_browser_manager() -> BrowserSessionManager:
    return BrowserSessionManager()


def get_ai_service(project_id: str, store: ProjectStore = Depends(get_project_store), settings: Settings = Depends(get_settings)) -> AIService:
    return AIService(store.project_dir(project_id), settings.secret_key)


@lru_cache
def get_terminal_manager() -> TerminalManager:
    return TerminalManager()


@lru_cache
def get_intruder_service() -> IntruderService:
    return IntruderService()

@lru_cache
def _intruder_manager(workspace: str, mongo_uri: str) -> IntruderJobManager:
    return IntruderJobManager(get_intruder_service(), Path(workspace), mongo_uri)

def get_intruder_job_manager(settings: Settings = Depends(get_settings)) -> IntruderJobManager:
    return _intruder_manager(str(settings.workspace_dir.resolve()), settings.mongo_uri)


def get_proxy_control(settings: Settings = Depends(get_settings)) -> ProxyControlService:
    try:
        return ProxyControlService(settings.legacy_src_dir, settings.proxy_control_host, settings.proxy_control_port)
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


def _methodology_registry(settings: Settings) -> list[dict]:
    import json

    path = settings.legacy_src_dir.resolve().parent / "resources" / "methodology" / "registry.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data.get("categories", [])
    except (OSError, ValueError):
        return []


def _methodology_description(settings: Settings, description_file: str) -> str:
    path = settings.legacy_src_dir.resolve().parent / "resources" / "methodology" / "descriptions" / description_file
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, ValueError):
        return ""


def _methodology_item(settings: Settings, vuln_id: str, states: dict) -> tuple[dict, dict] | None:
    for category in _methodology_registry(settings):
        for vuln in category.get("vulnerabilities", []):
            if vuln.get("id") == vuln_id:
                state = states.get(vuln_id, {"status": "not_tested", "notes": ""})
                return {**vuln, "category_id": category["id"], "category_name": category["name"]}, state
    return None


@router.get(
    "/projects/{project_id}/methodology",
    response_model=list[MethodologyCategory],
    tags=["methodology"],
)
def list_methodology(
    project_id: str,
    store: ProjectStore = Depends(get_project_store),
    repositories: LegacyRepositoryFactory = Depends(get_repository_factory),
    settings: Settings = Depends(get_settings),
) -> list[MethodologyCategory]:
    try:
        repository = repositories(store.project_dir(project_id))
        states = repository.load_methodology_states()
        categories = []
        for category in _methodology_registry(settings):
            vulnerabilities = [
                {**vuln, **states.get(vuln["id"], {"status": "not_tested", "notes": ""})}
                for vuln in category.get("vulnerabilities", [])
            ]
            categories.append({**category, "vulnerabilities": vulnerabilities})
        return [MethodologyCategory.model_validate(category) for category in categories]
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc
    except PyMongoError as exc:
        raise HTTPException(status_code=503, detail="Database unavailable") from exc


@router.get(
    "/projects/{project_id}/methodology/{vuln_id}",
    response_model=MethodologyDetail,
    tags=["methodology"],
)
def get_methodology_detail(
    project_id: str,
    vuln_id: str,
    store: ProjectStore = Depends(get_project_store),
    repositories: LegacyRepositoryFactory = Depends(get_repository_factory),
    settings: Settings = Depends(get_settings),
) -> MethodologyDetail:
    try:
        repository = repositories(store.project_dir(project_id))
        item = _methodology_item(settings, vuln_id, repository.load_methodology_states())
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc
    except PyMongoError as exc:
        raise HTTPException(status_code=503, detail="Database unavailable") from exc
    if not item:
        raise HTTPException(status_code=404, detail="Methodology check not found")
    vuln, state = item
    return MethodologyDetail.model_validate({**vuln, **state, "description": _methodology_description(settings, vuln.get("description_file", ""))})


@router.put(
    "/projects/{project_id}/methodology/{vuln_id}",
    response_model=MethodologyDetail,
    tags=["methodology"],
)
def update_methodology_status(
    project_id: str,
    vuln_id: str,
    payload: MethodologyStateInput,
    store: ProjectStore = Depends(get_project_store),
    repositories: LegacyRepositoryFactory = Depends(get_repository_factory),
    settings: Settings = Depends(get_settings),
) -> MethodologyDetail:
    try:
        repository = repositories(store.project_dir(project_id))
        states = repository.load_methodology_states()
        item = _methodology_item(settings, vuln_id, states)
        if not item:
            raise HTTPException(status_code=404, detail="Methodology check not found")
        states[vuln_id] = payload.model_dump()
        repository.save_methodology_state(states)
        vuln, state = item
        return MethodologyDetail.model_validate({**vuln, **payload.model_dump(), "description": _methodology_description(settings, vuln.get("description_file", ""))})
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc
    except PyMongoError as exc:
        raise HTTPException(status_code=503, detail="Database unavailable") from exc


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
    repositories: LegacyRepositoryFactory = Depends(get_repository_factory),
) -> PipelineJob:
    try:
        project = store.get(project_id)
        project_dir = store.project_dir(project_id)
        scope = store.get_scope(project_id)
        repository = repositories(store.project_dir(project_id))
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc
    except PyMongoError as exc:
        raise HTTPException(status_code=503, detail="Database unavailable") from exc
    session = repository.get_session(payload.session_id) if payload.session_id else None
    if payload.session_id and (not session or session.get("pipeline_key") != payload.pipeline_key):
        raise HTTPException(status_code=404, detail="Pipeline session not found")
    target = session.get("target", "") if session else project.target
    if not target:
        raise HTTPException(status_code=409, detail="Configure a target before running a pipeline")
    try:
        return jobs.start(
            project_id=project_id,
            project_dir=project_dir,
            pipeline_key=payload.pipeline_key,
            target=target,
            params=payload.params,
            in_scope=session.get("in_scope", []) if session else [entry.value for entry in scope.entries if entry.in_scope],
            out_of_scope=session.get("out_of_scope", []) if session else [entry.value for entry in scope.entries if not entry.in_scope],
            session_id=payload.session_id,
            tool_keys=payload.tool_keys,
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
    "/projects/{project_id}/sessions/{session_id}/tool-runs",
    response_model=list[PipelineToolRun],
    tags=["pipeline runs"],
)
def list_session_tool_runs(
    project_id: str,
    session_id: str,
    store: ProjectStore = Depends(get_project_store),
    repositories: LegacyRepositoryFactory = Depends(get_repository_factory),
) -> list[PipelineToolRun]:
    try:
        repository = repositories(store.project_dir(project_id))
        session = repository.get_session(session_id)
        rows = repository.get_tool_runs(session_id) if session else []
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc
    except PyMongoError as exc:
        raise HTTPException(status_code=503, detail="Database unavailable") from exc
    if not session:
        raise HTTPException(status_code=404, detail="Pipeline session not found")
    return [PipelineToolRun.model_validate(row) for row in rows]


@router.delete(
    "/projects/{project_id}/sessions/{session_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["pipeline runs"],
)
def delete_scan_session(
    project_id: str,
    session_id: str,
    store: ProjectStore = Depends(get_project_store),
    repositories: LegacyRepositoryFactory = Depends(get_repository_factory),
) -> Response:
    try:
        repository = repositories(store.project_dir(project_id))
        if not repository.get_session(session_id):
            raise HTTPException(status_code=404, detail="Pipeline session not found")
        repository.delete_session(session_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc
    except PyMongoError as exc:
        raise HTTPException(status_code=503, detail="Database unavailable") from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/projects/{project_id}/results",
    response_model=list[StoredResult],
    tags=["results"],
)
def list_project_results(
    project_id: str,
    category: str | None = None,
    limit: int = 5000,
    store: ProjectStore = Depends(get_project_store),
    repositories: LegacyRepositoryFactory = Depends(get_repository_factory),
) -> list[StoredResult]:
    """Return de-duplicated results from every project session, including proxy traffic."""
    limit = max(1, min(limit, 10000))
    try:
        repository = repositories(store.project_dir(project_id))
        docs = repository.get_results_project(category=category)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc
    except PyMongoError as exc:
        raise HTTPException(status_code=503, detail="Database unavailable") from exc

    merged: dict[tuple[str, str], dict] = {}
    for item in docs:
        key = (item.get("category", ""), item.get("result_key", ""))
        if key not in merged:
            merged[key] = dict(item)
            merged[key]["sources"] = list(item.get("sources", []))
        else:
            merged[key]["sources"] = sorted(set(merged[key]["sources"]) | set(item.get("sources", [])))
    return [StoredResult.model_validate(item) for item in list(merged.values())[:limit]]


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


def _traffic_summary(doc: dict) -> TrafficEntry:
    """Build the list representation without transferring captured bodies.

    Traffic bodies can be hundreds of kilobytes each.  The list view only
    needs request/response metadata; the full document is still available
    through GET /traffic/{traffic_id} when the user selects an entry.
    """
    value = {**doc, "id": str(doc["_id"])}
    for field in ("request", "response"):
        message = dict(value.get(field) or {})
        body = message.pop("body", "")
        if isinstance(body, str):
            message["body_length"] = len(body.encode("utf-8"))
        message.pop("body_encoding", None)
        message.pop("body_truncated", None)
        if field == "request":
            message.pop("headers", None)
        else:
            headers = message.get("headers")
            if isinstance(headers, dict):
                message["headers"] = {
                    key: header_value
                    for key, header_value in headers.items()
                    if key.lower() in {"content-type", "content-length"}
                }
        value[field] = message
    return TrafficEntry.model_validate(value)


def _traffic_scope_host_patterns(target: str, scope: ScopeConfig) -> list[str]:
    """Build Mongo host regexes for unassigned external-device captures.

    External clients cannot always send the AWE project marker.  Restricting
    the Mongo query to scope candidates before sorting/limiting prevents a
    busy shared proxy from hiding the current project's traffic behind a
    global newest-record limit.  Final URL/path matching still happens in
    ``_traffic_belongs_to_project``.
    """
    patterns: list[str] = []

    def add_domain(value: str, subdomains: bool = True) -> None:
        host = value.strip().lower().lstrip("*.")
        if not host:
            return
        suffix = rf"(?:^|\.){re.escape(host)}$" if subdomains else rf"^{re.escape(host)}$"
        if suffix not in patterns:
            patterns.append(suffix)

    target_host = (urlsplit(target if "://" in target else f"https://{target}").hostname or "").lower()
    included = [entry for entry in scope.entries if entry.in_scope]
    if not included:
        add_domain(target_host, scope.include_subdomains)
        return patterns

    for entry in included:
        value = entry.value.strip()
        if entry.entry_type == "regex":
            try:
                re.compile(value, re.IGNORECASE)
            except re.error:
                continue
            patterns.append(value)
            continue
        if entry.entry_type == "url":
            host = (urlsplit(value if "://" in value else f"https://{value}").hostname or "").lower()
            add_domain(host, False)
            continue
        add_domain(value, entry.entry_type == "wildcard" or scope.include_subdomains)
    return patterns


def _traffic_project_query(
    project_id: str,
    target: str | None = None,
    scope: ScopeConfig | None = None,
) -> dict:
    """Match tagged traffic and scoped captures from unmarked devices."""
    unassigned: dict = {
        "$or": [
            {"project_id": None},
            {"project_id": {"$exists": False}},
        ]
    }
    if target and scope:
        patterns = _traffic_scope_host_patterns(target, scope)
        if patterns:
            unassigned["host"] = {"$regex": "|".join(f"(?:{pattern})" for pattern in patterns), "$options": "i"}
    return {"$or": [{"project_id": project_id}, unassigned]}


def _traffic_belongs_to_project(
    doc: dict,
    project_id: str,
    target: str,
    scope: ScopeConfig,
) -> bool:
    """Apply project isolation to a captured traffic document.

    A proxy-authenticated/embedded-browser capture has an explicit project
    marker and is accepted only for that exact project.  An unmarked capture
    can be shown as a convenience for external devices, but only if its URL
    is within the current project's scope.
    """
    marker = doc.get("project_id")
    if marker:
        return marker == project_id
    request = doc.get("request") or {}
    url = request.get("url") or f"https://{doc.get('host', '')}{doc.get('path', '/') or '/'}"
    return _host_in_project_scope(str(url), target, scope)


def _network_graph(project_dir: Path, target: str, repositories: LegacyRepositoryFactory) -> NetworkGraph:
    """Build the same typed attack-surface graph used by the Qt client."""
    repo = repositories(project_dir); nodes: dict[str, NetworkNode] = {}; edges: dict[tuple[str,str,str], NetworkEdge] = {}
    def node(nid: str, kind: str, label: str, data: dict | None = None):
        if nid not in nodes: nodes[nid] = NetworkNode(id=nid, kind=kind, label=label, data=data or {})
        elif data:
            nodes[nid].data.update({k:v for k,v in data.items() if v not in (None, "", [], {})})
    def edge(src: str, dst: str, kind: str, label: str = ""):
        if src in nodes and dst in nodes: edges[(src,dst,kind)] = NetworkEdge(source_id=src,target_id=dst,kind=kind,label=label)
    root=f"target:{target}"; node(root,"target",target,{"domain":target})
    default=f"subdomain:{target}"; node(default,"subdomain",target,{"domain":target}); edge(root,default,"has_subdomain")
    for session in sorted(repo.list_sessions(limit=0), key=lambda x:x.get("started_at", "")):
        sid=session["id"]
        for category in ("subdomain","portscan","http","cdn","vuln","osint","crawl","params","info","custom"):
            for result in repo.get_results(sid, category):
                d=result.get("data",{}); sources=result.get("sources",[])
                if category=="subdomain" and d.get("domain"):
                    dom=d["domain"]; sid2=f"subdomain:{dom}"; node(sid2,"subdomain",dom,{"domain":dom,"ips":d.get("ip_addresses",[]),"sources":sources}); edge(root,sid2,"has_subdomain")
                    for ip in d.get("ip_addresses",[]): node(f"ip:{ip}","ip",ip,{"ip":ip}); edge(sid2,f"ip:{ip}","resolves_to")
                elif category=="portscan" and d.get("host") and d.get("port"):
                    host=str(d["host"]); ip=f"ip:{host}"; node(ip,"ip",host,{"ip":host}); pid=f"port:{host}:{d['port']}"; node(pid,"port",f"{d['port']}/{d.get('protocol','tcp')} {d.get('service','')}",d); edge(ip,pid,"has_port")
                elif category=="http" and d.get("url"):
                    parsed=urlsplit(d["url"]); host=parsed.hostname or ""; sub=f"subdomain:{host}"; node(sub,"subdomain",host,{"domain":host,"live":True,"status":d.get("status_code"),"title":d.get("title","")}); edge(root,sub,"has_subdomain")
                    for tech in d.get("technologies",[]): tid=f"tech:{tech}"; node(tid,"tech",tech,{"tech":tech}); edge(sub,tid,"uses_tech")
                    port=int(d.get("port") or (443 if parsed.scheme=="https" else 80)); pid=f"port:{host}:{port}"; node(pid,"port",f"{port}/tcp",{"host":host,"port":port,"url":d["url"],"status":d.get("status_code")}); edge(sub,pid,"has_port")
                elif category=="cdn" and d.get("provider"):
                    sub=f"subdomain:{d.get('subdomain',target)}"; node(sub,"subdomain",d.get("subdomain",target),{"domain":d.get("subdomain",target)}); cid=f"cdn:{d['provider']}:{d.get('subdomain',target)}"; node(cid,"cdn",d["provider"],d); edge(sub,cid,"proxied_by")
                elif category=="vuln" and d.get("name"):
                    host=urlsplit(d.get("url","")).hostname or target; sub=f"subdomain:{host}"; node(sub,"subdomain",host,{"domain":host}); vid=f"vuln:{d.get('template_id',d['name'])}:{host}"; node(vid,"vuln",d["name"],d); edge(sub,vid,"has_vuln")
                elif category=="osint" and d.get("value"):
                    oid=f"osint:{d.get('result_type','hit')}:{d['value']}"; node(oid,"osint",str(d['value'])[:80],d); edge(default,oid,"is_osint")
                elif category=="crawl" and d.get("url"):
                    parsed=urlsplit(d["url"]); host=parsed.hostname or target; sub=f"subdomain:{host}"; node(sub,"subdomain",host,{"domain":host}); eid=f"endpoint:{d.get('method','GET')}:{d['url']}"; node(eid,"endpoint",f"{d.get('method','GET')} {parsed.path or '/'}",d); edge(sub,eid,"has_endpoint")
                elif category=="params" and d.get("name"):
                    eid=f"endpoint:{d.get('method','GET')}:{d.get('endpoint','')}"; pid=f"param:{eid}:{d['name']}"; node(pid,"param",str(d['name']),d); edge(eid,pid,"has_param")
                elif category=="info" and d.get("content"):
                    parent=d.get("parent_node_id",""); iid=f"info:{parent}"; node(iid,"info",str(d["content"]).splitlines()[0][:80],d); edge(parent,iid,"annotates")
                elif category=="custom" and d.get("label"):
                    parent=d.get("parent_node_id",""); cid=f"custom:{result.get('result_key',d['label'])}"; node(cid,"custom",d["label"],d); edge(parent,cid,"linked_to")
    for item in repo._db.results.find({"session_id":{"$exists":False},"project_id":project_dir.name,"category":"network_manual"}):
        d=item.get("data",{}); node(item.get("result_key",d.get("label","manual")),d.get("kind","custom"),d.get("label","manual"),d); edge(d.get("parent_id",""),item.get("result_key",""),"linked_to")
    return NetworkGraph(nodes=list(nodes.values()), edges=list(edges.values()))


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
        if entry.entry_type == "regex":
            try:
                if re.search(value, host, re.IGNORECASE): return True
            except re.error:
                continue
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


@router.post("/docker/containers/{container_id}/start", status_code=204, tags=["docker"])
def start_docker_container(container_id: str, service: DockerService = Depends(get_docker_service)) -> None:
    try: service.start(container_id)
    except PermissionError as exc: raise HTTPException(status_code=403, detail=str(exc)) from exc
    except docker.errors.DockerException as exc: raise HTTPException(status_code=404, detail="Container not found") from exc


@router.delete("/docker/containers/{container_id}", status_code=204, tags=["docker"])
def remove_docker_container(container_id: str, service: DockerService = Depends(get_docker_service)) -> None:
    try: service.remove(container_id)
    except PermissionError as exc: raise HTTPException(status_code=403, detail=str(exc)) from exc
    except docker.errors.DockerException as exc: raise HTTPException(status_code=404, detail="Container not found") from exc


@router.get("/docker/images", response_model=list[DockerImage], tags=["docker"])
def list_docker_images(service: DockerService = Depends(get_docker_service)) -> list[DockerImage]:
    try:
        import sys
        source = str(get_settings().legacy_src_dir.resolve())
        if source not in sys.path: sys.path.insert(0, source)
        from containers.tool_registry import TOOL_REGISTRY
        return [DockerImage.model_validate(item) for item in service.images({tool.image for tool in TOOL_REGISTRY.values()})]
    except docker.errors.DockerException as exc: raise HTTPException(status_code=503, detail="Docker is unavailable") from exc


@router.delete("/docker/images/{image}", status_code=204, tags=["docker"])
def remove_docker_image(image: str, service: DockerService = Depends(get_docker_service)) -> None:
    try: service.remove_image(image)
    except docker.errors.DockerException as exc: raise HTTPException(status_code=404, detail="Image not found") from exc


@router.post("/docker/images/pull", response_model=dict, tags=["docker"])
def pull_docker_image(payload: DockerImagePull, service: DockerService = Depends(get_docker_service)) -> dict:
    try: return service.pull_image(payload.image)
    except docker.errors.DockerException as exc: raise HTTPException(status_code=400, detail=str(exc)) from exc

@router.post("/docker/images/build", response_model=dict, tags=["docker"])
def build_docker_image(payload: DockerImageBuild, service: DockerService = Depends(get_docker_service)) -> dict:
    try: return service.build_image(payload.dockerfile, payload.tag)
    except docker.errors.DockerException as exc: raise HTTPException(status_code=400, detail=str(exc)) from exc

@router.post("/docker/tools/images/{operation}", response_model=dict, tags=["docker"])
def operate_tool_images(operation: str, service: DockerService = Depends(get_docker_service), manager: DockerOperationManager = Depends(get_docker_operation_manager)) -> dict:
    if operation not in {"build", "pull", "setup"}: raise HTTPException(status_code=422, detail="Operation must be build, pull, or setup")
    try: return manager.start_images(operation, service).model_dump()
    except Exception as exc: raise HTTPException(status_code=400, detail=str(exc)) from exc

@router.post("/docker/tools/{key}/image/{operation}", response_model=DockerOperation, tags=["docker"])
def operate_one_tool_image(key: str, operation: str, service: DockerService = Depends(get_docker_service), manager: DockerOperationManager = Depends(get_docker_operation_manager)) -> DockerOperation:
    if operation not in {"build", "pull"}: raise HTTPException(status_code=422, detail="Operation must be build or pull")
    try: return manager.start_one_image(key, operation, service)
    except KeyError: raise HTTPException(status_code=404, detail="Tool not found")
    except Exception as exc: raise HTTPException(status_code=400, detail=str(exc)) from exc

@router.post("/docker/tools", response_model=DockerTool, status_code=201, tags=["docker"])
def create_docker_tool(payload: DockerToolCreate, settings: Settings = Depends(get_settings)) -> DockerTool:
    import json, sys
    source = str(settings.legacy_src_dir.resolve())
    if source not in sys.path: sys.path.insert(0, source)
    try:
        from config.config import CUSTOM_TOOLS_DIR
        from containers.custom_tools import register_custom_tool
        from containers.tool_registry import TOOL_REGISTRY
        if payload.key in TOOL_REGISTRY: raise ValueError(f"Tool key '{payload.key}' already exists")
        tool_dir = Path(CUSTOM_TOOLS_DIR) / payload.key
        tool_dir.mkdir(parents=True, exist_ok=True)
        (tool_dir / "tool.json").write_text(json.dumps(payload.model_dump(exclude={"dockerfile", "parser"}), indent=2))
        if payload.dockerfile: (tool_dir / "Dockerfile").write_text(payload.dockerfile)
        if payload.parser: (tool_dir / "parser.py").write_text(payload.parser)
        register_custom_tool(str(tool_dir))
        return _docker_tool_detail(payload.key)
    except Exception as exc: raise HTTPException(status_code=400, detail=str(exc)) from exc


def _docker_tool_detail(key: str) -> DockerTool:
    from containers.custom_tools import CustomToolConfig
    from containers.tool_registry import TOOL_REGISTRY
    from containers.parsers import PARSERS
    tool = TOOL_REGISTRY[key]
    is_custom = isinstance(tool, CustomToolConfig)
    return DockerTool(key=key, display_name=tool.display_name, category=tool.category, image=tool.image, description=tool.description, param_specs=tool.param_spec(), source="build" if tool.dockerfile else "hub", is_custom=is_custom, status="ok" if key in PARSERS else "no parser", command_template=getattr(tool, "command_template", ""), dockerfile=Path(tool.dockerfile).read_text(errors="replace") if is_custom and tool.dockerfile and Path(tool.dockerfile).exists() else "", parser=Path(tool.parser_path).read_text(errors="replace") if is_custom and tool.parser_path and Path(tool.parser_path).exists() else "")


@router.put("/docker/tools/{key}", response_model=DockerTool, tags=["docker"])
def update_docker_tool(key: str, payload: DockerToolCreate, settings: Settings = Depends(get_settings)) -> DockerTool:
    import json, sys
    source = str(settings.legacy_src_dir.resolve())
    if source not in sys.path: sys.path.insert(0, source)
    try:
        from containers.custom_tools import CustomToolConfig, register_custom_tool
        from containers.tool_registry import TOOL_REGISTRY
        if payload.key != key: raise ValueError("Tool key cannot be changed")
        if not isinstance(TOOL_REGISTRY.get(key), CustomToolConfig): raise KeyError(key)
        tool_dir = Path(TOOL_REGISTRY[key].tool_dir)
        (tool_dir / "tool.json").write_text(json.dumps(payload.model_dump(exclude={"dockerfile", "parser"}), indent=2))
        (tool_dir / "Dockerfile").write_text(payload.dockerfile)
        (tool_dir / "parser.py").write_text(payload.parser)
        register_custom_tool(str(tool_dir))
        return _docker_tool_detail(key)
    except KeyError as exc: raise HTTPException(status_code=404, detail="Custom tool not found") from exc
    except Exception as exc: raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.delete("/docker/tools/{key}", status_code=204, tags=["docker"])
def delete_docker_tool(key: str, settings: Settings = Depends(get_settings)) -> None:
    import sys
    source = str(settings.legacy_src_dir.resolve())
    if source not in sys.path: sys.path.insert(0, source)
    try:
        from containers.custom_tools import remove_custom_tool
        remove_custom_tool(key)
    except ValueError as exc: raise HTTPException(status_code=404, detail="Custom tool not found") from exc


@router.post("/docker/prune", response_model=dict, tags=["docker"])
def prune_docker(service: DockerService = Depends(get_docker_service)) -> dict:
    try: return {"removed": service.prune()}
    except docker.errors.DockerException as exc: raise HTTPException(status_code=503, detail="Docker is unavailable") from exc


@router.get("/docker/containers/{container_id}/logs", response_model=list[str], tags=["docker"])
def docker_logs(container_id: str, service: DockerService = Depends(get_docker_service)) -> list[str]:
    try: return service.logs(container_id)
    except PermissionError as exc: raise HTTPException(status_code=403, detail=str(exc)) from exc
    except docker.errors.DockerException as exc: raise HTTPException(status_code=404, detail="Container not found") from exc


@router.get("/docker/tools", response_model=list[DockerTool], tags=["docker"])
def list_docker_tools(settings: Settings = Depends(get_settings), service: DockerService = Depends(get_docker_service)) -> list[DockerTool]:
    import sys
    source=str(settings.legacy_src_dir.resolve())
    if source not in sys.path: sys.path.insert(0,source)
    try:
        from containers.tool_registry import TOOL_REGISTRY
        local = {tag for item in service.images() for tag in item["tags"]}
        result = []
        for key, tool in TOOL_REGISTRY.items():
            item = _docker_tool_detail(key)
            item.image_present = tool.image in local or any(tag.split(":")[0] == tool.image.split(":")[0] for tag in local)
            result.append(item)
        return result
    except Exception as exc: raise HTTPException(status_code=503, detail=f"Tool registry unavailable: {exc}") from exc


@router.get("/docker/status", response_model=dict, tags=["docker"])
def docker_status(service: DockerService = Depends(get_docker_service)) -> dict:
    try: return service.status()
    except docker.errors.DockerException as exc: return {"available": False, "version": "", "message": str(exc)}


@router.get("/docker/operations/{operation_id}", response_model=DockerOperation, tags=["docker"])
def get_docker_operation(operation_id: str, manager: DockerOperationManager = Depends(get_docker_operation_manager)) -> DockerOperation:
    try: return manager.get(operation_id)
    except DockerOperationNotFound as exc: raise HTTPException(status_code=404, detail="Operation not found") from exc


@router.post("/docker/operations/{operation_id}/cancel", response_model=DockerOperation, tags=["docker"])
def cancel_docker_operation(operation_id: str, manager: DockerOperationManager = Depends(get_docker_operation_manager)) -> DockerOperation:
    try: return manager.cancel(operation_id)
    except DockerOperationNotFound as exc: raise HTTPException(status_code=404, detail="Operation not found") from exc


@router.post("/projects/{project_id}/docker/tools/{key}/runs", response_model=DockerOperation, status_code=202, tags=["docker"])
def run_docker_tool(project_id: str, key: str, payload: DockerToolRun, store: ProjectStore = Depends(get_project_store), service: DockerService = Depends(get_docker_service), manager: DockerOperationManager = Depends(get_docker_operation_manager)) -> DockerOperation:
    project_dir = store.project_dir(project_id).resolve()
    relative = Path(payload.output_subdir)
    if relative.is_absolute() or ".." in relative.parts: raise HTTPException(status_code=422, detail="Output directory must be relative to the project")
    return manager.start_tool(key, payload.params, project_dir / relative, service)


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


@router.get("/vault/items/{item_id}/file", tags=["vault"])
def download_vault_file(item_id: str, vault: VaultService = Depends(get_vault_service)) -> FileResponse:
    item = vault.get_item(item_id)
    if not item or item.get("type") not in {"image", "pdf", "file"}:
        raise HTTPException(status_code=404, detail="Vault file not found")
    path = vault.file_path(item)
    if path is None or not path.is_file():
        raise HTTPException(status_code=404, detail="Vault file not found")
    return FileResponse(path, filename=item.get("title") or "download")


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
    urls = [url for _, url, _ in service.generate_requests(payload)]
    if not all(_host_in_project_scope(url, project.target, scope) for url in urls):
        raise HTTPException(status_code=403, detail="Every generated URL must be inside the project scope")
    try:
        return await service.run(payload)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

@router.post("/projects/{project_id}/intruder/jobs",response_model=IntruderJob,status_code=202,tags=["testing"])
def start_intruder_job(project_id:str,payload:IntruderRequest,store:ProjectStore=Depends(get_project_store),manager:IntruderJobManager=Depends(get_intruder_job_manager),service:IntruderService=Depends(get_intruder_service))->IntruderJob:
    try:project=store.get(project_id);scope=store.get_scope(project_id)
    except ProjectNotFoundError as exc:raise HTTPException(status_code=404,detail="Project not found") from exc
    if not all(_host_in_project_scope(url,project.target,scope) for _,url,_ in service.generate_requests(payload)):raise HTTPException(status_code=403,detail="Every generated URL must be inside the project scope")
    return manager.start(project_id,payload)

@router.get("/projects/{project_id}/intruder/jobs",response_model=list[IntruderJob],tags=["testing"])
def list_intruder_jobs(project_id:str,manager:IntruderJobManager=Depends(get_intruder_job_manager))->list[IntruderJob]:return manager.list(project_id)

@router.get("/projects/{project_id}/intruder/jobs/{job_id}",response_model=IntruderJob,tags=["testing"])
def get_intruder_job(project_id:str,job_id:str,manager:IntruderJobManager=Depends(get_intruder_job_manager))->IntruderJob:
    try:job=manager.get(project_id, job_id)
    except IntruderJobNotFound as exc:raise HTTPException(status_code=404,detail="Intruder job not found") from exc
    if job.project_id!=project_id:raise HTTPException(status_code=404,detail="Intruder job not found")
    return job

@router.post("/projects/{project_id}/intruder/jobs/{job_id}/cancel",response_model=IntruderJob,tags=["testing"])
def cancel_intruder_job(project_id:str,job_id:str,manager:IntruderJobManager=Depends(get_intruder_job_manager))->IntruderJob:
    get_intruder_job(project_id,job_id,manager);return manager.cancel(project_id, job_id)


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
async def create_browser_session(project_id: str, payload: BrowserViewport = BrowserViewport(), store: ProjectStore = Depends(get_project_store), manager: BrowserSessionManager = Depends(get_browser_manager), app_settings: Settings = Depends(get_settings)) -> BrowserSession:
    _browser_project(project_id, store)
    settings = store.get_settings(project_id)
    try:
        state = await manager.create(project_id, app_settings.browser_proxy_host, app_settings.browser_proxy_port, payload.width, payload.height, app_settings.browser_proxy_enabled)
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
                try:
                    state, image = await manager.screenshot(session_id)
                    await websocket.send_json({"type": "frame", "session": _browser_model(state).model_dump(mode="json"), "image": base64.b64encode(image).decode()})
                except Exception as exc:
                    # A page can be between commits while Chromium is still
                    # painting. Keep the stream alive so the next frame can
                    # expose the partially loaded page instead of disconnecting.
                    await websocket.send_json({"type": "error", "message": f"Browser frame delayed: {exc}"})
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


@router.get("/projects/{project_id}/ai/settings", response_model=AISettings, tags=["ai"])
def get_ai_settings(project_id: str, service: AIService = Depends(get_ai_service)) -> AISettings:
    return AISettings.model_validate(service.settings())


@router.put("/projects/{project_id}/ai/settings", response_model=AISettings, tags=["ai"])
def put_ai_settings(project_id: str, payload: AISettings, service: AIService = Depends(get_ai_service)) -> AISettings:
    return AISettings.model_validate(service.save_settings(payload.model_dump()))


@router.get("/projects/{project_id}/ai/conversations", response_model=list[AIConversation], tags=["ai"])
def list_ai_conversations(project_id: str, service: AIService = Depends(get_ai_service)) -> list[AIConversation]:
    return [AIConversation.model_validate(item) for item in service.list_conversations()]


@router.post("/projects/{project_id}/ai/conversations", response_model=AIConversationDetail, status_code=201, tags=["ai"])
def create_ai_conversation(project_id: str, service: AIService = Depends(get_ai_service)) -> AIConversationDetail:
    return AIConversationDetail.model_validate(service.create())


@router.get("/projects/{project_id}/ai/conversations/{conversation_id}", response_model=AIConversationDetail, tags=["ai"])
def get_ai_conversation(project_id: str, conversation_id: str, service: AIService = Depends(get_ai_service)) -> AIConversationDetail:
    try: return AIConversationDetail.model_validate(service.get(conversation_id))
    except KeyError as exc: raise HTTPException(status_code=404, detail="Conversation not found") from exc


@router.post("/projects/{project_id}/ai/conversations/{conversation_id}/messages", response_model=AIConversationDetail, tags=["ai"])
async def send_ai_message(project_id: str, conversation_id: str, payload: AIChatRequest, service: AIService = Depends(get_ai_service)) -> AIConversationDetail:
    try:
        await service.reply(conversation_id, payload.content)
        return AIConversationDetail.model_validate(service.get(conversation_id))
    except KeyError as exc: raise HTTPException(status_code=404, detail="Conversation not found") from exc
    except httpx.HTTPError as exc: raise HTTPException(status_code=502, detail=f"AI provider request failed: {exc}") from exc
    except RuntimeError as exc: raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.websocket("/projects/{project_id}/ai/conversations/{conversation_id}/stream")
async def stream_ai_message(project_id: str, conversation_id: str, websocket: WebSocket, store: ProjectStore = Depends(get_project_store), settings: Settings = Depends(get_settings)) -> None:
    try: store.project_dir(project_id)
    except ProjectNotFoundError:
        await websocket.close(code=4404, reason="Project not found"); return
    await websocket.accept(); service=AIService(store.project_dir(project_id), settings.secret_key)
    try:
        request=await websocket.receive_json(); prompt=str(request.get("content", "")).strip()
        if not prompt: await websocket.send_json({"type":"error","message":"Message cannot be empty"}); return
        async for event in service.stream_reply(conversation_id,prompt): await websocket.send_json(event)
    except WebSocketDisconnect: return
    except KeyError: await websocket.send_json({"type":"error","message":"Conversation not found"})
    except Exception as exc: await websocket.send_json({"type":"error","message":str(exc)})


@router.get("/projects/{project_id}/ai/approvals", response_model=list[AIApproval], tags=["ai"])
def list_ai_approvals(project_id: str, service: AIService = Depends(get_ai_service)) -> list[AIApproval]:
    return [AIApproval.model_validate(item) for item in service.approvals() if item.get("status") == "pending"]


@router.post("/projects/{project_id}/ai/approvals/{approval_id}", response_model=AIApproval, tags=["ai"])
def resolve_ai_approval(project_id: str, approval_id: str, payload: AIApprovalDecision, service: AIService = Depends(get_ai_service), store: ProjectStore = Depends(get_project_store), jobs: PipelineJobManager = Depends(get_job_manager)) -> AIApproval:
    item=service.resolve_approval(approval_id,payload.decision)
    if item is None: raise HTTPException(status_code=404, detail="Approval request not found")
    if payload.decision == "approve" and item["tool_name"] == "start_pipeline":
        try:
            project=store.get(project_id); scope=store.get_scope(project_id); project_dir=store.project_dir(project_id)
            jobs.start(project_id, project_dir, str(item["arguments"].get("pipeline_key","")), project.target, {}, [e.value for e in scope.entries if e.in_scope], [e.value for e in scope.entries if not e.in_scope])
            item["execution"]="started"
        except (ProjectNotFoundError, ValueError) as exc:
            item["execution_error"]=str(exc)
    return AIApproval.model_validate(item)


@router.post("/projects/{project_id}/terminal/sessions", response_model=TerminalSessionInfo, status_code=201, tags=["terminal"])
async def create_terminal_session(project_id: str, payload: TerminalConnectRequest, store: ProjectStore = Depends(get_project_store), manager: TerminalManager = Depends(get_terminal_manager)) -> TerminalSessionInfo:
    store.project_dir(project_id)
    try:
        session=await manager.create(project_id,payload.host,payload.port,payload.username,payload.password,payload.private_key,payload.key_passphrase,payload.trust_host_key)
        return TerminalSessionInfo(id=session.id,project_id=project_id,host=session.host,port=session.port,username=session.username)
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.get("/projects/{project_id}/terminal/profiles", response_model=list[TerminalProfile], tags=["terminal"])
def list_terminal_profiles(project_id: str, store: ProjectStore = Depends(get_project_store)) -> list[TerminalProfile]:
    return [TerminalProfile.model_validate(item) for item in TerminalProfileStore(store.project_dir(project_id)).list()]


@router.post("/projects/{project_id}/terminal/profiles", response_model=TerminalProfile, status_code=201, tags=["terminal"])
def create_terminal_profile(project_id: str, payload: TerminalProfileInput, store: ProjectStore = Depends(get_project_store)) -> TerminalProfile:
    return TerminalProfile.model_validate(TerminalProfileStore(store.project_dir(project_id)).create(payload.name,payload.host,payload.port,payload.username))


@router.put("/projects/{project_id}/terminal/profiles/{profile_id}", response_model=TerminalProfile, tags=["terminal"])
def update_terminal_profile(project_id: str, profile_id: str, payload: TerminalProfileInput, store: ProjectStore = Depends(get_project_store)) -> TerminalProfile:
    item=TerminalProfileStore(store.project_dir(project_id)).update(profile_id,payload.name,payload.host,payload.port,payload.username)
    if item is None: raise HTTPException(status_code=404, detail="Terminal profile not found")
    return TerminalProfile.model_validate(item)


@router.delete("/projects/{project_id}/terminal/profiles/{profile_id}", status_code=204, tags=["terminal"])
def delete_terminal_profile(project_id: str, profile_id: str, store: ProjectStore = Depends(get_project_store)) -> None:
    if not TerminalProfileStore(store.project_dir(project_id)).delete(profile_id): raise HTTPException(status_code=404, detail="Terminal profile not found")


@router.websocket("/projects/{project_id}/terminal/sessions/{session_id}/stream")
async def terminal_stream(project_id: str, session_id: str, websocket: WebSocket, store: ProjectStore = Depends(get_project_store), manager: TerminalManager = Depends(get_terminal_manager)) -> None:
    try:
        store.project_dir(project_id); session=manager.get(session_id)
        if session.project_id != project_id: raise KeyError(session_id)
    except (ProjectNotFoundError, KeyError):
        await websocket.close(code=4404, reason="Terminal session not found"); return
    await websocket.accept()
    async def read_output():
        while chunk := await session.process.stdout.read(4096):
            await websocket.send_text(chunk)
        await websocket.close(code=1000, reason="SSH shell exited")
    output_task=asyncio.create_task(read_output())
    try:
        while True:
            message=await websocket.receive_json(); kind=message.get("type")
            if kind == "input": manager.touch(session_id); session.process.stdin.write(str(message.get("data",""))[:10000])
            elif kind == "resize": await manager.resize(session_id,int(message.get("cols",120)),int(message.get("rows",32)))
            elif kind == "close": break
    except (WebSocketDisconnect, KeyError): pass
    except Exception as exc:
        try: await websocket.close(code=1011, reason=f"Terminal stream failed: {str(exc)[:80]}")
        except Exception: pass
    finally:
        output_task.cancel(); await manager.close(session_id)
