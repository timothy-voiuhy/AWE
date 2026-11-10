"""Testing API handlers and helpers."""

from ..intruder_jobs import IntruderJobManager
from ..intruder_jobs import IntruderJobNotFound
from ..projects import ProjectNotFoundError
from ..projects import ProjectStore
from ..replay import HttpReplayService
from ..repositories import LegacyRepositoryFactory
from ..schemas import InterceptConfig
from ..schemas import InterceptDecision
from ..schemas import InterceptRequest
from ..schemas import IntruderJob
from ..schemas import IntruderRequest
from ..schemas import IntruderResult
from ..schemas import ProjectSettings
from ..schemas import RepeaterRequest
from ..schemas import RepeaterResponse
from ..schemas import WebSocketConnection
from ..schemas import WebSocketFrame
from ..schemas import WebSocketSendRequest
from ..schemas import WebSocketSendResponse
from ..testing_services import IntruderService
from ..testing_services import ProxyControlService
from ..testing_services import WebSocketClientService
from fastapi import Depends
from fastapi import HTTPException
from pymongo.errors import PyMongoError
from .dependencies import get_intruder_job_manager, get_intruder_service, get_project_store, get_proxy_control, get_replay_service, get_repository_factory, get_websocket_client
from .traffic_helpers import _host_in_project_scope
from fastapi import APIRouter

router = APIRouter()


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
