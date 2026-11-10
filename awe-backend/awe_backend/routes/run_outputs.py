"""Durable tool output, artifacts, and evidence routes."""
import asyncio
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel, Field

from ..projects import ProjectStore
from ..run_outputs import RunOutputs, project_runs
from ..schemas import EvidenceInput
from .dependencies import get_project_store
from .stores import _evidence_store

router = APIRouter()


def output(project_id: str, run_id: str, store: ProjectStore) -> RunOutputs:
    try:
        result = RunOutputs(store.project_dir(project_id), run_id)
        result.metadata()
    except (KeyError, ValueError):
        raise HTTPException(404, "Run not found")
    return result


@router.get("/projects/{project_id}/runs", tags=["runs"])
def list_runs(project_id: str, store: ProjectStore = Depends(get_project_store)):
    return project_runs(store.project_dir(project_id))


@router.get("/projects/{project_id}/runs/{run_id}", tags=["runs"])
def get_run(project_id: str, run_id: str, store: ProjectStore = Depends(get_project_store)):
    return output(project_id, run_id, store).metadata()


@router.get("/projects/{project_id}/runs/{run_id}/events", tags=["runs"])
def events(project_id: str, run_id: str, after: int = Query(0, ge=0), limit: int = Query(200, ge=1, le=1000), search: str = "", store: ProjectStore = Depends(get_project_store)):
    return output(project_id, run_id, store).events(after, limit, search)


@router.get("/projects/{project_id}/runs/{run_id}/transcript", tags=["runs"])
def transcript(project_id: str, run_id: str, store: ProjectStore = Depends(get_project_store)):
    record = output(project_id, run_id, store)
    def chunks():
        path = record.root / "events.jsonl"
        if path.exists():
            import json
            with path.open() as file:
                for line in file:
                    event = json.loads(line)
                    yield f"[{event['timestamp']}] [{event['stream']}] {event['data']}\n"
    return StreamingResponse(chunks(), media_type="text/plain", headers={"Content-Disposition": f'attachment; filename="{run_id}.txt"'})


@router.get("/projects/{project_id}/runs/{run_id}/artifacts", tags=["runs"])
def artifacts(project_id: str, run_id: str, store: ProjectStore = Depends(get_project_store)):
    return output(project_id, run_id, store).metadata().get("artifacts", [])


@router.post("/projects/{project_id}/runs/{run_id}/artifacts/refresh", tags=["runs"])
def refresh_artifacts(project_id: str, run_id: str, store: ProjectStore = Depends(get_project_store)):
    record = output(project_id, run_id, store)
    return record.collect(record.metadata().get("artifact_paths"))


@router.get("/projects/{project_id}/runs/{run_id}/artifacts/{artifact_id}", tags=["runs"])
def download_artifact(project_id: str, run_id: str, artifact_id: str, preview: bool = False, store: ProjectStore = Depends(get_project_store)):
    try:
        path, item = output(project_id, run_id, store).artifact(artifact_id)
    except KeyError:
        raise HTTPException(404, "Artifact not found")
    safe_image = item["mime_type"] in {"image/png", "image/jpeg", "image/gif", "image/webp"}
    mime = item["mime_type"] if safe_image else "text/plain" if preview else item["mime_type"]
    return FileResponse(path, filename=Path(item["name"]).name, media_type=mime, content_disposition_type="inline" if preview else "attachment", headers={"X-Content-Type-Options": "nosniff", "Content-Security-Policy": "default-src 'none'; sandbox"})


class OutputEvidence(BaseModel):
    title: str = Field(min_length=1, max_length=300)
    interpretation: str = Field(default="", max_length=20000)
    start_sequence: int = Field(default=1, ge=1)
    end_sequence: int = Field(default=1000, ge=1)
    artifact_id: str = ""
    investigation_id: str = ""
    entity_ids: list[str] = Field(default_factory=list, max_length=500)


@router.post("/projects/{project_id}/runs/{run_id}/evidence", tags=["runs"], status_code=201)
def promote_evidence(project_id: str, run_id: str, payload: OutputEvidence, store: ProjectStore = Depends(get_project_store)):
    record = output(project_id, run_id, store)
    data = {"run_id": run_id, "interpretation": payload.interpretation}
    artifact_path = None
    if payload.artifact_id:
        try:
            artifact_path, artifact = record.artifact(payload.artifact_id)
        except KeyError:
            raise HTTPException(404, "Artifact not found")
        data["artifact"] = artifact
    else:
        if payload.end_sequence < payload.start_sequence or payload.end_sequence - payload.start_sequence >= 1000:
            raise HTTPException(422, "Select at most 1000 events in ascending order")
        data["events"] = [e for e in record.events(payload.start_sequence - 1, 1000)["events"] if e["sequence"] <= payload.end_sequence]
    evidence = _evidence_store(record.project_dir).create(project_id, EvidenceInput(title=payload.title, summary=payload.interpretation, source_type="run_output", source_id=run_id, kind="file" if payload.artifact_id else "tool_output", investigation_id=payload.investigation_id, entity_ids=payload.entity_ids, data=data))
    if artifact_path:
        import shutil
        import hashlib
        folder = record.project_dir / ".awe-evidence-files"
        folder.mkdir(exist_ok=True)
        destination = folder / evidence.id
        shutil.copyfile(artifact_path, destination)
        digest = hashlib.sha256()
        with destination.open("rb") as file:
            for chunk in iter(lambda: file.read(1024 * 1024), b""):
                digest.update(chunk)
        if digest.hexdigest() != data["artifact"]["sha256"]:
            destination.unlink()
            _evidence_store(record.project_dir).delete(project_id, evidence.id)
            raise HTTPException(409, "Artifact changed during capture; refresh artifacts before saving evidence")
    return evidence


@router.get("/projects/{project_id}/evidence/{evidence_id}/file", tags=["evidence"])
def download_evidence_snapshot(project_id: str, evidence_id: str, store: ProjectStore = Depends(get_project_store)):
    import re
    from ..evidence_store import EvidenceNotFoundError
    project_dir = store.project_dir(project_id)
    try:
        evidence = _evidence_store(project_dir).get(project_id, evidence_id)
    except EvidenceNotFoundError:
        raise HTTPException(404, "Evidence not found")
    if not re.fullmatch(r"[a-f0-9]{24}", evidence_id):
        raise HTTPException(404, "Evidence file not found")
    path = project_dir / ".awe-evidence-files" / evidence_id
    if path.is_symlink() or not path.is_file():
        raise HTTPException(404, "Evidence file not found")
    return FileResponse(path, filename=Path(evidence.data.get("artifact", {}).get("name", "evidence.bin")).name, media_type="application/octet-stream")


@router.websocket("/projects/{project_id}/runs/{run_id}/events/stream")
async def stream_events(project_id: str, run_id: str, websocket: WebSocket, store: ProjectStore = Depends(get_project_store)):
    from ..session_service import check_origin
    if not check_origin(websocket):
        await websocket.close(code=4403)
        return
    record = output(project_id, run_id, store)
    await websocket.accept()
    cursor = max(0, int(websocket.query_params.get("after", "0")))
    try:
        while True:
            page = await asyncio.to_thread(record.events, cursor)
            cursor = page["cursor"]
            if page["events"]:
                await websocket.send_json(page)
            await asyncio.sleep(.3)
    except WebSocketDisconnect:
        pass
