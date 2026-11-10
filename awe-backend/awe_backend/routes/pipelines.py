"""Pipelines API handlers and helpers."""

from ..config import get_settings
from ..jobs import JobNotFoundError
from ..jobs import PipelineJobManager
from ..pipelines import PipelineCatalog
from ..projects import ProjectNotFoundError
from ..projects import ProjectStore
from ..repositories import LegacyRepositoryFactory
from ..schemas import PipelineJob
from ..schemas import PipelineRunCreate
from ..schemas import PipelineToolRun
from ..schemas import ScanSession
from fastapi import Depends
from fastapi import HTTPException
from fastapi import Response
from fastapi import WebSocket
from fastapi import WebSocketDisconnect
from fastapi import status
from pymongo.errors import PyMongoError
import asyncio
import sys
from .dependencies import get_job_manager, get_project_store, get_repository_factory
from fastapi import APIRouter

router = APIRouter()


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
