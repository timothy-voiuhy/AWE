"""Project session connection, attachment, and termination API."""
import asyncio
import secrets
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field, model_validator

from ..projects import ProjectStore
from ..run_outputs import RunOutputs
from ..session_service import SessionService, check_origin, session_service
from .dependencies import get_project_store

router = APIRouter()


class SessionCreate(BaseModel):
    kind: Literal["ssh", "tcp", "listener"]
    host: str = ""
    port: int = Field(default=0, ge=0, le=65535)
    username: str = ""
    password: str = ""
    private_key: str = ""
    key_passphrase: str = ""
    trust_host_key: bool = False
    label: str = Field(default="", max_length=200)
    expected_peer: str = ""
    run_id: str = ""

    @model_validator(mode="after")
    def connection_fields(self):
        if self.kind in {"tcp", "ssh"} and not self.host:
            raise ValueError("Host is required")
        if self.kind == "tcp" and not self.port:
            raise ValueError("Port is required")
        return self


@router.get("/projects/{project_id}/sessions/interactive", tags=["sessions"])
async def list_sessions(project_id: str, store: ProjectStore = Depends(get_project_store), manager: SessionService = Depends(session_service)):
    store.project_dir(project_id)
    await manager.start()
    return [manager.public(r) for r in manager.rows.values() if r["project_id"] == project_id]


@router.post("/projects/{project_id}/sessions/interactive", tags=["sessions"], status_code=201)
async def create_session(project_id: str, payload: SessionCreate, store: ProjectStore = Depends(get_project_store), manager: SessionService = Depends(session_service)):
    try:
        return await manager.create(project_id, store.project_dir(project_id), payload)
    except KeyError as exc:
        raise HTTPException(404, "Associated run not found") from exc
    except (OSError, ValueError, TimeoutError) as exc:
        raise HTTPException(422, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(502, f"Session connection failed: {exc}") from exc


@router.get("/projects/{project_id}/sessions/interactive/{sid}", tags=["sessions"])
async def get_session(project_id: str, sid: str, manager: SessionService = Depends(session_service)):
    await manager.start()
    try:
        return manager.public(manager.get(project_id, sid))
    except KeyError:
        raise HTTPException(404, "Session not found")


@router.delete("/projects/{project_id}/sessions/interactive/{sid}", tags=["sessions"])
async def terminate_session(project_id: str, sid: str, manager: SessionService = Depends(session_service)):
    try:
        return await manager.terminate(project_id, sid)
    except KeyError:
        raise HTTPException(404, "Session not found")


@router.websocket("/projects/{project_id}/sessions/interactive/{sid}/stream")
async def attach(project_id: str, sid: str, websocket: WebSocket, manager: SessionService = Depends(session_service)):
    if not check_origin(websocket):
        await websocket.close(code=4403); return
    await manager.start()
    try:
        row = manager.get(project_id, sid)
    except KeyError:
        await websocket.close(code=4404); return
    await websocket.accept()
    owner = secrets.token_hex(12)
    if sid not in manager.writers:
        manager.writers[sid] = owner
    from pathlib import Path
    record = RunOutputs(Path(row["project_dir"]), row["run_id"])
    async def read():
        cursor = max(0, int(websocket.query_params.get("after", "0")))
        while True:
            page = await asyncio.to_thread(record.events, cursor)
            cursor = page["cursor"]
            await websocket.send_json({"type": "output", **page, "session": manager.public(row), "writable": manager.writers.get(sid) == owner})
            await asyncio.sleep(.3)
    task = asyncio.create_task(read())
    try:
        while True:
            message = await websocket.receive_json()
            if message.get("type") == "detach":
                break
            try:
                await manager.control(project_id, sid, owner, message)
            except (ValueError, PermissionError, KeyError) as exc:
                await websocket.send_json({"type": "error", "message": str(exc)})
    except WebSocketDisconnect:
        pass
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        if manager.writers.get(sid) == owner:
            manager.writers.pop(sid, None)
