"""Ai API handlers and helpers."""

from ..ai_service import AIService
from ..config import Settings
from ..config import get_settings
from ..jobs import PipelineJobManager
from ..projects import ProjectNotFoundError
from ..projects import ProjectStore
from ..schemas import AIApproval
from ..schemas import AIApprovalDecision
from ..schemas import AIChatRequest
from ..schemas import AIConversation
from ..schemas import AIConversationDetail
from ..schemas import AISettings
from fastapi import Depends
from fastapi import HTTPException
from fastapi import WebSocket
from fastapi import WebSocketDisconnect
from .dependencies import get_ai_service, get_job_manager, get_project_store
from fastapi import APIRouter

router = APIRouter()


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
