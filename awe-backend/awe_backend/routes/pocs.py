"""PoC source registration and tracked builds."""
import secrets
from typing import Literal
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from pydantic import ValidationError
from ..config import Settings, get_settings
from ..projects import ProjectStore
from ..schemas import DockerToolCreate
from ..poc_sources import start_build
from .dependencies import get_project_store

router = APIRouter()


class PocCreate(DockerToolCreate):
    repository: str = ""
    revision: str = ""
    image: str = "awe/poc"
    dockerfile: str = ""
    category: str = "vuln"
    output_channels: list[Literal["structured", "logs", "artifacts", "session"]] = ["logs", "artifacts"]


@router.post("/projects/{project_id}/pocs", status_code=202, tags=["pocs"])
async def create_poc(project_id: str, definition: str = Form(...), archive: UploadFile | None = File(None), store: ProjectStore = Depends(get_project_store), settings: Settings = Depends(get_settings)):
    try:
        payload = PocCreate.model_validate_json(definition)
    except ValidationError as exc:
        raise HTTPException(422, str(exc))
    if not payload.repository and archive is None:
        raise HTTPException(422, "Provide a Git repository or archive")
    raw = await archive.read(50 * 1024 * 1024 + 1) if archive else None
    if raw and len(raw) > 50 * 1024 * 1024:
        raise HTTPException(413, "Archive exceeds 50 MiB")
    return start_build(store.project_dir(project_id), secrets.token_hex(12), payload, raw, settings)
