"""Terminal API handlers and helpers."""

from ..projects import ProjectNotFoundError
from ..projects import ProjectStore
from ..schemas import TerminalConnectRequest
from ..schemas import TerminalProfile
from ..schemas import TerminalProfileInput
from ..schemas import TerminalSessionInfo
from ..terminal import TerminalManager
from ..terminal_profiles import TerminalProfileStore
from fastapi import Depends
from fastapi import HTTPException
from fastapi import WebSocket
from fastapi import WebSocketDisconnect
import asyncio
from .dependencies import get_project_store, get_terminal_manager
from fastapi import APIRouter

router = APIRouter()


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
