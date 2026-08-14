import asyncio
import base64
import fnmatch
import re
import json
import secrets
import sys
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
import docker.errors
from pathlib import Path
from functools import lru_cache
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, UploadFile, File, WebSocket, WebSocketDisconnect, status
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
from .graph_store import GraphRevisionError, InvestigationNotFoundError, InvestigationStore
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
    GraphBundle, GraphEntity, GraphRelationship, GraphInvestigation,
    InvestigationCreate, GraphEntityInput, GraphRelationshipInput,
    GraphPreferencesInput, TransformManifest, TransformStart, TransformJob, GraphIdentityInput, GraphMergeInput, GraphMergeResult,
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

_GRAPH_TRANSFORM_JOBS: dict[str, TransformJob] = {}
_GRAPH_TRANSFORM_SECRETS: dict[str, dict] = {}


def _graph_store(project_dir: Path) -> InvestigationStore:
    return InvestigationStore(project_dir)


def _transform_seed(entity: GraphEntity, parameter: str) -> str:
    """Turn graph values into the input shape expected by legacy tools."""
    raw = entity.value or entity.label
    if parameter in {"domain", "host"}:
        candidate = str(raw).strip()
        parsed = urlsplit(candidate if "://" in candidate else f"https://{candidate}")
        return parsed.hostname or candidate.split("/", 1)[0]
    if parameter in {"url", "endpoint"}:
        candidate = str(raw).strip()
        return candidate if "://" in candidate else f"https://{candidate}"
    return str(raw)


def _graph_transforms(settings: Settings) -> list[TransformManifest]:
    """Expose safe graph adapters over the existing Docker tool registry."""
    source = str(settings.legacy_src_dir)
    if source not in sys.path:
        sys.path.insert(0, source)
    try:
        from containers.tool_registry import TOOL_REGISTRY
    except Exception:
        TOOL_REGISTRY = {}
    builtin = {
        "subfinder": ("Enumerate subdomains", ["target", "domain", "subdomain"], ["subdomain"], "passive"),
        "amass": ("Map related domains", ["target", "domain", "subdomain"], ["subdomain"], "passive"),
        "dnsx": ("Resolve DNS records", ["domain", "subdomain"], ["dns_record", "ip"], "passive"),
        "httpx": ("Probe HTTP services", ["domain", "subdomain", "ip"], ["url", "tech", "port"], "safe_active"),
        "naabu": ("Discover open ports", ["ip", "domain", "subdomain"], ["port"], "active"),
        "nmap": ("Fingerprint services", ["ip", "port"], ["port", "technology"], "active"),
        "katana": ("Crawl endpoints", ["url", "domain", "subdomain"], ["endpoint"], "safe_active"),
        "gospider": ("Discover linked endpoints", ["url", "domain", "subdomain"], ["endpoint"], "safe_active"),
        "arjun": ("Discover URL parameters", ["url", "endpoint"], ["param"], "active"),
        "nuclei": ("Scan for vulnerabilities", ["url", "endpoint", "subdomain"], ["vuln"], "active"),
        "wafw00f": ("Detect WAF and CDN", ["url", "domain", "subdomain"], ["cdn", "tech"], "safe_active"),
        "gowitness": ("Capture a screenshot", ["url", "endpoint"], ["screenshot"], "safe_active"),
        "github_recon": ("Search GitHub intelligence", ["target", "domain", "organization"], ["repository", "osint"], "passive"),
        "cloud_enum": ("Enumerate cloud assets", ["target", "domain"], ["cloud_asset", "osint"], "passive"),
        "asnmap": ("Map ASN ownership and network ranges", ["target", "domain", "organization", "asn", "ip"], ["asn", "netblock"], "passive"),
        "tlsx": ("Collect TLS certificates and fingerprints", ["domain", "subdomain", "ip", "url"], ["certificate", "tls_finding"], "safe_active"),
        "testssl": ("Assess TLS protocols and cryptographic weaknesses", ["domain", "subdomain", "ip", "url"], ["tls_finding"], "safe_active"),
        "theharvester": ("Collect email, name, IP, URL, and subdomain OSINT", ["target", "domain", "organization"], ["email", "person", "ip", "url", "subdomain"], "passive"),
        "gitleaks": ("Find redacted secrets in repository history", ["repository", "file"], ["secret", "repository"], "passive"),
        "whatweb": ("Fingerprint web technologies and versions", ["url", "endpoint", "domain", "subdomain"], ["url", "technology"], "safe_active"),
        "s3scanner": ("Check cloud bucket permissions", ["target", "organization", "cloud_asset"], ["cloud_asset", "cloud_finding"], "safe_active"),
        "wpscan": ("Enumerate WordPress components and findings", ["url", "domain", "subdomain", "technology"], ["platform", "component", "identity", "vuln"], "safe_active"),
        "droopescan": ("Enumerate Drupal components and findings", ["url", "domain", "subdomain", "technology"], ["platform", "component", "endpoint", "misconfiguration"], "safe_active"),
        "prowler": ("Audit cloud, Kubernetes, GitHub, and identity posture", ["cloud_asset", "cluster", "repository", "identity_provider"], ["cloud_asset", "component", "misconfiguration", "vuln"], "active"),
        "kubescape": ("Scan Kubernetes clusters, manifests, and images", ["cluster", "workload", "container_image", "file"], ["cluster", "workload", "container_image", "misconfiguration", "vulnerability"], "active"),
        "trivy": ("Scan container images, repositories, filesystems, and IaC", ["container_image", "repository", "file"], ["container_image", "component", "misconfiguration", "vulnerability", "secret"], "safe_active"),
        "cloudflare_audit": ("Inventory Cloudflare zones and DNS", ["domain", "cloud_asset"], ["cloudflare_zone", "dns_record", "cloud_asset"], "active"),
        "oidc_probe": ("Discover OpenID Connect issuer metadata", ["url", "identity_provider", "domain"], ["identity_provider", "oidc_endpoint", "component"], "safe_active"),
    }
    manifests: list[TransformManifest] = []
    for key, (label, inputs, outputs, mode) in builtin.items():
        tool = TOOL_REGISTRY.get(key)
        if not tool:
            continue
        manifests.append(TransformManifest(
            id=f"docker:{key}", tool_key=key, display_name=label,
            description=getattr(tool, "description", ""), input_types=inputs,
            output_types=outputs,
            relationship_types=list(getattr(tool, "relationship_types", ())) or ["discovered_by"],
            mode=mode,
            requires_approval=mode in {"active", "high_risk"},
            parameters=tool.param_spec(),
        ))
        transform_path = getattr(tool, "tool_dir", "")
        if transform_path:
            manifest_file = Path(transform_path) / "transform.json"
            if manifest_file.is_file():
                try:
                    raw = json.loads(manifest_file.read_text(encoding="utf-8"))
                    manifests[-1] = TransformManifest.model_validate({**manifests[-1].model_dump(), **raw, "id": raw.get("id", f"docker:{key}"), "tool_key": key})
                except (OSError, ValueError):
                    pass
    # Custom tools opt into graph transforms by declaring graph contracts in
    # tool.json. They remain invisible to the graph until both input and
    # output types are present, which prevents an arbitrary Docker helper from
    # being mistaken for a typed transform.
    existing = {item.tool_key for item in manifests}
    for key, tool in TOOL_REGISTRY.items():
        if key in existing or not getattr(tool, "input_types", ()) or not getattr(tool, "output_types", ()):
            continue
        manifests.append(TransformManifest(
            id=f"docker:{key}", tool_key=key, display_name=tool.display_name,
            description=getattr(tool, "description", ""),
            input_types=list(tool.input_types), output_types=list(tool.output_types),
            relationship_types=list(getattr(tool, "relationship_types", ())) or ["discovered_by"],
            mode=getattr(tool, "execution_mode", "passive"),
            requires_approval=getattr(tool, "execution_mode", "passive") in {"active", "high_risk"},
            parameters=tool.param_spec(),
        ))
    return manifests


def _graph_result_kind(data: dict, manifest: TransformManifest) -> str:
    """Resolve a parser result to the graph vocabulary advertised by a manifest."""
    raw = str(data.get("result_type") or data.get("kind") or "").strip()
    aliases = {"vulnerability": "vuln", "technology": "tech", "parameter": "param"}
    candidate = aliases.get(raw, raw)
    if candidate in manifest.output_types:
        return candidate
    if raw in manifest.output_types:
        return raw
    if len(manifest.output_types) == 1:
        return manifest.output_types[0]
    for option in manifest.output_types:
        if option in data or option.rstrip("s") in data:
            return option
    return manifest.output_types[0] if manifest.output_types else "custom"


def _graph_result_value(data: dict) -> str:
    return str(data.get("value") or data.get("domain") or data.get("url") or data.get("name") or data.get("host") or data.get("label") or "")


def _graph_result_edge(kind: str) -> str:
    return {
        "platform": "runs", "component": "has_component", "vuln": "has_finding",
        "vulnerability": "has_finding", "misconfiguration": "has_finding",
        "cloud_asset": "has_cloud_asset", "cloudflare_zone": "contains", "dns_record": "has_dns",
        "cluster": "contains", "workload": "contains", "container_image": "uses_image",
        "identity_provider": "uses_identity_provider", "oidc_endpoint": "exposes",
        "endpoint": "exposes", "secret": "contains_secret", "repository": "has_repository",
    }.get(kind, "discovered_by")


def _redact_transform_params(manifest: TransformManifest, params: dict) -> tuple[dict, dict]:
    secret_keys = {str(item.get("key")) for item in manifest.parameters if item.get("type") == "secret" or item.get("default") == "secret"}
    return (
        {key: ("[redacted]" if key in secret_keys else value) for key, value in params.items()},
        {key: value for key, value in params.items() if key in secret_keys and value not in (None, "", "[redacted]")},
    )


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
    created_relationships: list[str] = []
    for index, result in enumerate(parsed[:1000]):
        data = asdict(result) if is_dataclass(result) else (result if isinstance(result, dict) else {"value": str(result)})
        value = _graph_result_value(data)
        if not value:
            continue
        kind = _graph_result_kind(data, manifest)
        entity_id = f"transform:{provenance_id or secrets.token_hex(8)}:{index}"
        entity = GraphEntity(
            id=entity_id, kind=kind, label=value[:500], value=value[:4096], data=data,
            source="transform", provenance=[{"transform_job_id": provenance_id, "tool_key": manifest.tool_key}],
        )
        graph_store.add_entity(investigation, entity)
        relationship = GraphRelationship(
            id=f"{entity_id}:edge", source_id=parent_id, target_id=entity_id,
            kind=_graph_result_edge(kind), source="transform",
            provenance=[{"transform_job_id": provenance_id, "tool_key": manifest.tool_key}],
        )
        graph_store.add_relationship(investigation, relationship)
        created_entities.append(entity_id)
        created_relationships.append(relationship.id)
    if created_entities or created_relationships:
        graph_store.save(investigation.model_copy(update={
            "entity_ids": [*investigation.entity_ids, *created_entities],
            "relationship_ids": [*investigation.relationship_ids, *created_relationships],
        }), investigation.revision)
    return len(created_entities)

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
        "username": settings.proxy_username,
        "password_configured": bool(settings.proxy_password),
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
    source = str(get_settings().legacy_src_dir.resolve())
    if source not in sys.path: sys.path.insert(0, source)
    try:
        from containers.tool_registry import TOOL_REGISTRY
        template = PipelineCatalog(get_settings().legacy_src_dir).get_legacy_template(payload.pipeline_key)
        requested = set(payload.tool_keys or [step.tool_key for step in (template.steps if template else [])])
        active_tools = sorted(key for key in requested if getattr(TOOL_REGISTRY.get(key), "execution_mode", "passive") in {"active", "high_risk"})
        if active_tools and not payload.approved:
            raise HTTPException(status_code=409, detail=f"Explicit approval required for active tools: {', '.join(active_tools)}")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Could not validate pipeline tools: {exc}") from exc
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
    sessions = sorted(repo.list_sessions(limit=0), key=lambda x: x.get("started_at", ""))
    live_hosts: set[str] = set()

    def hostname(value: str) -> str:
        parsed = urlsplit(value if "://" in value else f"https://{value}")
        return (parsed.hostname or "").rstrip(".").lower()

    for session in sessions:
        for result in repo.get_results(session["id"], "http"):
            url = str(result.get("data", {}).get("url") or "")
            if url and hostname(url):
                live_hosts.add(hostname(url))

    def is_live(value: str) -> bool:
        return hostname(value) in live_hosts

    def architecture_kind(result_type: str) -> str:
        return {
            "vulnerability": "vuln", "technology": "tech", "parameter": "param",
            "cloud_account": "cloud_asset", "cloud_resource": "cloud_asset",
            "cloud_bucket": "cloud_asset", "cloud_asset": "cloud_asset",
        }.get(result_type, result_type)

    def architecture_edge(result_type: str) -> str:
        return {
            "platform": "runs", "component": "has_component", "vulnerability": "has_finding",
            "vuln": "has_finding", "misconfiguration": "has_finding", "cloud_account": "contains",
            "cloud_resource": "has_resource", "cloud_asset": "has_cloud_asset", "cloudflare_zone": "contains",
            "dns_record": "has_dns", "cluster": "contains", "workload": "contains",
            "container_image": "uses_image", "identity_provider": "uses_identity_provider",
            "oidc_endpoint": "exposes", "endpoint": "exposes", "secret": "contains_secret",
            "repository": "has_repository", "email": "has_email", "person": "mentions",
        }.get(result_type, "is_architecture")

    def node(nid: str, kind: str, label: str, data: dict | None = None):
        if nid not in nodes: nodes[nid] = NetworkNode(id=nid, kind=kind, label=label, data=data or {})
        elif data:
            nodes[nid].data.update({k:v for k,v in data.items() if v not in (None, "", [], {})})
    def edge(src: str, dst: str, kind: str, label: str = ""):
        if src in nodes and dst in nodes: edges[(src,dst,kind)] = NetworkEdge(source_id=src,target_id=dst,kind=kind,label=label)
    root=f"target:{target}"; node(root,"target",target,{"domain":target})
    default = f"subdomain:{target}"
    if is_live(target):
        node(default, "subdomain", target, {"domain": target, "live": True})
        edge(root, default, "has_subdomain")
    for session in sessions:
        sid=session["id"]
        for category in ("subdomain","portscan","http","cdn","vuln","osint","architecture","crawl","params","info","custom"):
            for result in repo.get_results(sid, category):
                d=result.get("data",{}); sources=result.get("sources",[])
                if category=="subdomain" and d.get("domain"):
                    dom=str(d["domain"])
                    if not is_live(dom):
                        continue
                    sid2=f"subdomain:{hostname(dom)}"; node(sid2,"subdomain",dom,{"domain":dom,"live":True,"ips":d.get("ip_addresses",[]),"sources":sources}); edge(root,sid2,"has_subdomain")
                    for ip in d.get("ip_addresses",[]): node(f"ip:{ip}","ip",ip,{"ip":ip}); edge(sid2,f"ip:{ip}","resolves_to")
                elif category=="portscan" and d.get("host") and d.get("port"):
                    host=str(d["host"]); ip=f"ip:{host}"; node(ip,"ip",host,{"ip":host}); pid=f"port:{host}:{d['port']}"; node(pid,"port",f"{d['port']}/{d.get('protocol','tcp')} {d.get('service','')}",d); edge(ip,pid,"has_port")
                elif category=="http" and d.get("url"):
                    parsed=urlsplit(d["url"]); host=hostname(d["url"])
                    if not host:
                        continue
                    sub=f"subdomain:{host}"; node(sub,"subdomain",host,{"domain":host,"live":True,"status":d.get("status_code"),"title":d.get("title","")}); edge(root,sub,"has_subdomain")
                    for tech in d.get("technologies",[]): tid=f"tech:{tech}"; node(tid,"tech",tech,{"tech":tech}); edge(sub,tid,"uses_tech")
                    port=int(d.get("port") or (443 if parsed.scheme=="https" else 80)); pid=f"port:{host}:{port}"; node(pid,"port",f"{port}/tcp",{"host":host,"port":port,"url":d["url"],"status":d.get("status_code")}); edge(sub,pid,"has_port")
                elif category=="cdn" and d.get("provider"):
                    subdomain=str(d.get("subdomain", target))
                    if not is_live(subdomain):
                        continue
                    sub=f"subdomain:{hostname(subdomain)}"; node(sub,"subdomain",subdomain,{"domain":subdomain,"live":True}); cid=f"cdn:{d['provider']}:{hostname(subdomain)}"; node(cid,"cdn",d["provider"],d); edge(sub,cid,"proxied_by")
                elif category=="vuln" and d.get("name"):
                    host=hostname(d.get("url", "")) or hostname(target)
                    if not is_live(host):
                        continue
                    sub=f"subdomain:{host}"; node(sub,"subdomain",host,{"domain":host,"live":True}); vid=f"vuln:{d.get('template_id',d['name'])}:{host}"; node(vid,"vuln",d["name"],d); edge(sub,vid,"has_vuln")
                elif category=="osint" and d.get("value"):
                    oid=f"osint:{d.get('result_type','hit')}:{d['value']}"; node(oid,"osint",str(d['value'])[:80],d); edge(root,oid,"is_osint")
                elif category=="architecture" and d.get("value"):
                    result_type = str(d.get("result_type") or d.get("kind") or "architecture")
                    value = str(d.get("value"))
                    kind = architecture_kind(result_type)
                    related = hostname(str(d.get("related_host") or d.get("metadata", {}).get("input") or ""))
                    parent = root
                    if related and is_live(related):
                        parent = f"subdomain:{related}"
                        node(parent, "subdomain", related, {"domain": related, "live": True})
                        edge(root, parent, "has_subdomain")
                    node_id = f"{kind}:{value}"
                    node(node_id, kind, value[:80], {**d, "architecture_type": result_type})
                    edge(parent, node_id, architecture_edge(result_type))
                elif category=="crawl" and d.get("url"):
                    parsed=urlsplit(d["url"]); host=hostname(d["url"])
                    if not is_live(host):
                        continue
                    sub=f"subdomain:{host}"; node(sub,"subdomain",host,{"domain":host,"live":True}); eid=f"endpoint:{d.get('method','GET')}:{d['url']}"; node(eid,"endpoint",f"{d.get('method','GET')} {parsed.path or '/'}",d); edge(sub,eid,"has_endpoint")
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
    manual_entities = [
        item for item in graph_store.entities(investigation)
        if not (item.source == "transform" and item.kind == "subdomain" and item.data.get("live") is not True)
    ]
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
        store.project_dir(project_id)
        return _graph_transforms(settings)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc


@router.post("/projects/{project_id}/transforms", response_model=TransformJob, status_code=202, tags=["network"])
def start_graph_transform(project_id: str, payload: TransformStart, store: ProjectStore = Depends(get_project_store), settings: Settings = Depends(get_settings), docker_operations: DockerOperationManager = Depends(get_docker_operation_manager), docker_service: DockerService = Depends(get_docker_service), repositories: LegacyRepositoryFactory = Depends(get_repository_factory)) -> TransformJob:
    try:
        project = store.get(project_id); project_dir = store.project_dir(project_id); graph_store = _graph_store(project_dir)
        investigation = _ensure_investigation(project_id, project_dir, project.target, repositories) if not payload.investigation_id else graph_store.get(project_id, payload.investigation_id)
        bundle = _graph_bundle(project_id, project_dir, project.target, repositories, investigation.id)
        entities = {entity.id: entity for entity in bundle.entities}
        manifests = {item.id: item for item in _graph_transforms(settings)}
        transform = manifests.get(payload.transform_id)
        if not transform:
            raise HTTPException(status_code=404, detail="Transform not found")
        selected = [entities[item] for item in payload.entity_ids if item in entities]
        if not selected or any(entity.kind not in transform.input_types for entity in selected):
            raise HTTPException(status_code=422, detail="Transform input types do not match the selected entities")
        if transform.requires_approval and not payload.approved:
            raise HTTPException(status_code=409, detail="This transform requires explicit approval")
        job_id = secrets.token_hex(12)
        params = dict(payload.parameters)
        if payload.source_job_id:
            params = {**_GRAPH_TRANSFORM_SECRETS.get(payload.source_job_id, {}), **params}
        for parameter in ("domain", "host", "url", "endpoint"):
            params.setdefault(parameter, _transform_seed(selected[0], parameter))
        output_dir = project_dir / ".awe-transform-runs" / job_id
        operation = docker_operations.start_tool(transform.tool_key, params, output_dir, docker_service)
        safe_params, secret_params = _redact_transform_params(transform, params)
        _GRAPH_TRANSFORM_SECRETS[job_id] = secret_params
        job = TransformJob(id=job_id, project_id=project_id, investigation_id=investigation.id, transform_id=transform.id, status="queued", entity_ids=payload.entity_ids, operation_id=operation.id, parameters=safe_params, created_at=datetime.now(timezone.utc))
        _GRAPH_TRANSFORM_JOBS[job.id] = job
        return job
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc
    except InvestigationNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Investigation not found") from exc


@router.get("/projects/{project_id}/transforms/{job_id}", response_model=TransformJob, tags=["network"])
def get_graph_transform(project_id: str, job_id: str, docker_operations: DockerOperationManager = Depends(get_docker_operation_manager)) -> TransformJob:
    job = _GRAPH_TRANSFORM_JOBS.get(job_id)
    if not job or job.project_id != project_id:
        raise HTTPException(status_code=404, detail="Transform job not found")
    if job.operation_id:
        try:
            operation = docker_operations.get(job.operation_id)
            status_map = {"queued": "queued", "running": "running", "completed": "completed", "failed": "failed", "cancelled": "cancelled", "cancelling": "running"}
            if operation.status != "queued" or job.status == "queued":
                job = job.model_copy(update={"status": status_map.get(operation.status, "failed"), "message": operation.message or job.message, "completed_at": datetime.now(timezone.utc) if operation.status in {"completed", "failed", "cancelled"} else None, "progress_completed": operation.progress_completed, "progress_total": operation.progress_total, "logs": operation.logs[-100:]})
                if operation.status == "completed" and not job.outputs_ingested:
                    try:
                        from containers.parsers import PARSERS
                        from containers.tool_registry import TOOL_REGISTRY
                        from .config import get_settings
                        from .projects import ProjectStore
                        settings = get_settings(); project_store = ProjectStore(settings.workspace_dir)
                        project = project_store.get(project_id); project_dir = project_store.project_dir(project_id)
                        manifest = next((item for item in _graph_transforms(settings) if item.id == job.transform_id), None)
                        parser = PARSERS.get(manifest.tool_key) if manifest else None
                        if parser and operation.result.get("output_dir"):
                            parsed = parser(operation.result["output_dir"]) or []
                            ingested = _ingest_graph_results(project_id, project_dir, job.investigation_id, project.target, repositories, manifest, parsed, job.entity_ids[0] if job.entity_ids else "", job.id)
                            job = job.model_copy(update={"outputs_ingested": True, "message": f"Completed and ingested {ingested} typed outputs"})
                    except Exception as exc:
                        job = job.model_copy(update={"message": f"Completed; output ingestion skipped: {exc}"})
                _GRAPH_TRANSFORM_JOBS[job_id] = job
        except DockerOperationNotFound:
            pass
    return job


@router.post("/projects/{project_id}/transforms/{job_id}/cancel", response_model=TransformJob, tags=["network"])
def cancel_graph_transform(project_id: str, job_id: str, docker_operations: DockerOperationManager = Depends(get_docker_operation_manager)) -> TransformJob:
    job = _GRAPH_TRANSFORM_JOBS.get(job_id)
    if not job or job.project_id != project_id:
        raise HTTPException(status_code=404, detail="Transform job not found")
    if job.operation_id:
        try: docker_operations.cancel(job.operation_id)
        except DockerOperationNotFound: pass
    job = job.model_copy(update={"status": "cancelled", "message": "Cancellation requested"})
    _GRAPH_TRANSFORM_JOBS[job_id] = job
    return job


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
    input_types = list(getattr(tool, "input_types", ()) or ())
    output_types = list(getattr(tool, "output_types", ()) or ())
    relationship_types = list(getattr(tool, "relationship_types", ()) or ())
    return DockerTool(key=key, display_name=tool.display_name, category=tool.category, image=tool.image, description=tool.description, param_specs=tool.param_spec(), source="build" if tool.dockerfile else "hub", is_custom=is_custom, status="ok" if key in PARSERS else "no parser", command_template=getattr(tool, "command_template", ""), dockerfile=Path(tool.dockerfile).read_text(errors="replace") if is_custom and tool.dockerfile and Path(tool.dockerfile).exists() else "", parser=Path(tool.parser_path).read_text(errors="replace") if is_custom and tool.parser_path and Path(tool.parser_path).exists() else "", input_types=input_types, output_types=output_types, relationship_types=relationship_types, execution_mode=getattr(tool, "execution_mode", "passive"), credential_fields=list(getattr(tool, "credential_fields", ()) or ()), graph_enabled=bool(input_types and output_types and key in PARSERS))


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
def run_docker_tool(project_id: str, key: str, payload: DockerToolRun, store: ProjectStore = Depends(get_project_store), service: DockerService = Depends(get_docker_service), manager: DockerOperationManager = Depends(get_docker_operation_manager), repositories: LegacyRepositoryFactory = Depends(get_repository_factory), settings: Settings = Depends(get_settings)) -> DockerOperation:
    project = store.get(project_id)
    project_dir = store.project_dir(project_id).resolve()
    source = str(settings.legacy_src_dir.resolve())
    if source not in sys.path: sys.path.insert(0, source)
    from containers.tool_registry import TOOL_REGISTRY
    tool = TOOL_REGISTRY.get(key)
    if not tool:
        raise HTTPException(status_code=404, detail="Tool not found")
    if getattr(tool, "execution_mode", "passive") in {"active", "high_risk"} and not payload.approved:
        raise HTTPException(status_code=409, detail="This tool requires explicit approval before execution")
    callback = None
    if payload.ingest_to_graph:
        investigation_id = payload.investigation_id
        if not investigation_id:
            investigation_id = _ensure_investigation(project_id, project_dir, project.target, repositories).id
        manifests = {item.tool_key: item for item in _graph_transforms(settings)}
        manifest = manifests.get(key)
        if not manifest:
            raise HTTPException(status_code=422, detail="This tool has no graph contract and cannot be ingested")
        def on_complete(parsed: list, _output_dir: Path) -> dict:
            count = _ingest_graph_results(project_id, project_dir, investigation_id, project.target, repositories, manifest, parsed, "", f"docker-{key}-{secrets.token_hex(6)}")
            return {"ingested_count": count, "investigation_id": investigation_id}
        callback = on_complete
    relative = Path(payload.output_subdir)
    if relative.is_absolute() or ".." in relative.parts: raise HTTPException(status_code=422, detail="Output directory must be relative to the project")
    return manager.start_tool(key, payload.params, project_dir / relative, service, callback)


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
        state = await manager.create(project_id, app_settings.browser_proxy_host, app_settings.browser_proxy_port, payload.width, payload.height, app_settings.proxy_username, app_settings.proxy_password, app_settings.browser_proxy_enabled)
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
