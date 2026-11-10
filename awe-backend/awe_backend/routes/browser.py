"""Browser API handlers and helpers."""

from ..browser import BrowserSessionManager
from ..browser import BrowserUnavailable
from ..config import Settings
from ..config import get_settings
from ..projects import ProjectNotFoundError
from ..projects import ProjectStore
from ..schemas import BrowserNavigate
from ..schemas import BrowserSession
from ..schemas import BrowserViewport
from fastapi import Depends
from fastapi import HTTPException
from fastapi import WebSocket
from fastapi import WebSocketDisconnect
import asyncio
from .dependencies import get_browser_manager, get_project_store
from .traffic_helpers import _host_in_project_scope
from fastapi import APIRouter

router = APIRouter()


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
        state = await manager.create(project_id, app_settings.browser_proxy_host, app_settings.browser_proxy_port, payload.width, payload.height, app_settings.proxy_username, app_settings.proxy_password, app_settings.browser_proxy_enabled, app_settings.proxy_certificate_path)
        return _browser_model(state)
    except BrowserUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


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


@router.websocket("/projects/{project_id}/browser/sessions/{session_id}/vnc")
async def browser_vnc(project_id: str, session_id: str, websocket: WebSocket, store: ProjectStore = Depends(get_project_store), manager: BrowserSessionManager = Depends(get_browser_manager)) -> None:
    """Bridge an authenticated noVNC WebSocket to the private session VNC port."""
    try:
        store.project_dir(project_id)
        session = manager.get(session_id)
        if session.state.project_id != project_id:
            raise KeyError(session_id)
    except (ProjectNotFoundError, KeyError):
        await websocket.close(code=4404, reason="Browser session not found")
        return
    await websocket.accept()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", session.vnc_port)
    except OSError:
        await websocket.close(code=1011, reason="Browser VNC server is unavailable")
        return

    async def from_client() -> None:
        while True:
            message = await websocket.receive()
            if message.get("type") == "websocket.disconnect":
                return
            payload = message.get("bytes")
            if payload:
                writer.write(payload)
                await writer.drain()

    async def to_client() -> None:
        while True:
            payload = await reader.read(65536)
            if not payload:
                return
            await websocket.send_bytes(payload)

    client_task = asyncio.create_task(from_client())
    server_task = asyncio.create_task(to_client())
    try:
        done, pending = await asyncio.wait(
            {client_task, server_task}, return_when=asyncio.FIRST_COMPLETED
        )
        for task in done:
            task.result()
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
    except (WebSocketDisconnect, KeyError, ConnectionError):
        client_task.cancel()
        server_task.cancel()
        await asyncio.gather(client_task, server_task, return_exceptions=True)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
