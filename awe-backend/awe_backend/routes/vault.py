"""Vault API handlers and helpers."""

from ..projects import ProjectStore
from ..schemas import VaultCategory
from ..schemas import VaultCategoryInput
from ..schemas import VaultItem
from ..schemas import VaultItemInput
from ..schemas import VaultItemRecord
from ..schemas import VaultItemRecordInput
from ..vault import VaultService
from fastapi import Depends
from fastapi import File
from fastapi import HTTPException
from fastapi import UploadFile
from fastapi.responses import FileResponse
from .dependencies import get_project_store, get_vault_service
from fastapi import APIRouter

router = APIRouter()


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
