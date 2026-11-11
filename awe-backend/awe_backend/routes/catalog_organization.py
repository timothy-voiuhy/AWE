"""Category hierarchy and placement APIs for all catalog tools/transforms."""
import sys
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from ..catalog_organization import CatalogOrganization
from ..config import Settings, get_settings
from ..projects import ProjectNotFoundError, ProjectStore
from .dependencies import get_project_store
from .transform_catalog import _graph_transforms

router = APIRouter(prefix="/projects/{project_id}/catalog", tags=["catalog"])


class CategoryInput(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    parent_id: str | None = Field(default=None, max_length=80)


class AssignmentInput(BaseModel):
    item_keys: list[str] = Field(min_length=1, max_length=1000)
    category_id: str = Field(min_length=1, max_length=80)


def context(project_id: str, store: ProjectStore = Depends(get_project_store), settings: Settings = Depends(get_settings)):
    try:
        project_dir = store.project_dir(project_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(404, "Project not found") from exc
    source = str(settings.legacy_src_dir)
    if source not in sys.path:
        sys.path.insert(0, source)
    from containers.tool_registry import TOOL_REGISTRY
    items = {f"tool:{key}": "Exploits" if getattr(tool, "source_metadata", {}).get("kind") in {"git", "archive"} else (tool.category or "Other") for key, tool in TOOL_REGISTRY.items()}
    for manifest in _graph_transforms(settings, project_dir):
        key = f"tool:{manifest.tool_key}" if manifest.tool_key in TOOL_REGISTRY else f"transform:{project_id}:{manifest.id}"
        items.setdefault(key, manifest.category or "Other")
    return CatalogOrganization(settings.workspace_dir), items


def perform(operation):
    try:
        return operation()
    except KeyError as exc:
        raise HTTPException(404, "Category not found") from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


@router.get("/organization")
def organization(ctx=Depends(context)):
    service, items = ctx
    return perform(lambda: service.snapshot(items))


@router.post("/categories", status_code=201)
def create_category(payload: CategoryInput, ctx=Depends(context)):
    service, items = ctx
    return perform(lambda: service.save_category(items, payload.name, payload.parent_id))


@router.patch("/categories/{category_id}")
def update_category(category_id: str, payload: CategoryInput, ctx=Depends(context)):
    service, items = ctx
    return perform(lambda: service.save_category(items, payload.name, payload.parent_id, category_id))


@router.delete("/categories/{category_id}")
def delete_category(category_id: str, ctx=Depends(context)):
    service, items = ctx
    return perform(lambda: service.delete_category(items, category_id))


@router.put("/assignments")
def assign_items(payload: AssignmentInput, ctx=Depends(context)):
    service, items = ctx
    return perform(lambda: service.assign(items, payload.item_keys, payload.category_id))
