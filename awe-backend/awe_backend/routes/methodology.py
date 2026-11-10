"""Methodology API handlers and helpers."""

from ..config import Settings
from ..config import get_settings
from ..projects import ProjectNotFoundError
from ..projects import ProjectStore
from ..repositories import LegacyRepositoryFactory
from ..schemas import MethodologyCategory
from ..schemas import MethodologyDetail
from ..schemas import MethodologyStateInput
from fastapi import Depends
from fastapi import HTTPException
from pathlib import Path
from pymongo.errors import PyMongoError
import json
from .dependencies import get_project_store, get_repository_factory
from fastapi import APIRouter

router = APIRouter()


def _methodology_registry(settings: Settings) -> list[dict]:
    import json

    path = settings.legacy_src_dir.resolve().parent / "resources" / "methodology" / "registry.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data.get("categories", [])
    except (OSError, ValueError):
        return []


def _methodology_description(settings: Settings, description_file: str) -> str:
    relative = Path(description_file)
    if relative.is_absolute() or ".." in relative.parts:
        return ""
    roots = [
        settings.legacy_src_dir.resolve().parent,
        Path(__file__).resolve().parents[2],
        Path.cwd(),
    ]
    for root in roots:
        path = root / "resources" / "methodology" / "descriptions" / relative
        try:
            if path.is_file():
                return path.read_text(encoding="utf-8")
        except (OSError, ValueError):
            continue
    return ""


def _methodology_item(settings: Settings, vuln_id: str, states: dict) -> tuple[dict, dict] | None:
    for category in _methodology_registry(settings):
        for vuln in category.get("vulnerabilities", []):
            if vuln.get("id") == vuln_id:
                state = states.get(vuln_id, {"status": "not_tested", "notes": ""})
                return {**vuln, "category_id": category["id"], "category_name": category["name"]}, state
    return None


@router.get(
    "/projects/{project_id}/methodology",
    response_model=list[MethodologyCategory],
    tags=["methodology"],
)
def list_methodology(
    project_id: str,
    store: ProjectStore = Depends(get_project_store),
    repositories: LegacyRepositoryFactory = Depends(get_repository_factory),
    settings: Settings = Depends(get_settings),
) -> list[MethodologyCategory]:
    try:
        repository = repositories(store.project_dir(project_id))
        states = repository.load_methodology_states()
        categories = []
        for category in _methodology_registry(settings):
            vulnerabilities = [
                {**vuln, **states.get(vuln["id"], {"status": "not_tested", "notes": ""})}
                for vuln in category.get("vulnerabilities", [])
            ]
            categories.append({**category, "vulnerabilities": vulnerabilities})
        return [MethodologyCategory.model_validate(category) for category in categories]
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc
    except PyMongoError as exc:
        raise HTTPException(status_code=503, detail="Database unavailable") from exc


@router.get(
    "/projects/{project_id}/methodology/{vuln_id}",
    response_model=MethodologyDetail,
    tags=["methodology"],
)
def get_methodology_detail(
    project_id: str,
    vuln_id: str,
    store: ProjectStore = Depends(get_project_store),
    repositories: LegacyRepositoryFactory = Depends(get_repository_factory),
    settings: Settings = Depends(get_settings),
) -> MethodologyDetail:
    try:
        repository = repositories(store.project_dir(project_id))
        item = _methodology_item(settings, vuln_id, repository.load_methodology_states())
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc
    except PyMongoError as exc:
        raise HTTPException(status_code=503, detail="Database unavailable") from exc
    if not item:
        raise HTTPException(status_code=404, detail="Methodology check not found")
    vuln, state = item
    return MethodologyDetail.model_validate({**vuln, **state, "description": _methodology_description(settings, vuln.get("description_file", ""))})


@router.put(
    "/projects/{project_id}/methodology/{vuln_id}",
    response_model=MethodologyDetail,
    tags=["methodology"],
)
def update_methodology_status(
    project_id: str,
    vuln_id: str,
    payload: MethodologyStateInput,
    store: ProjectStore = Depends(get_project_store),
    repositories: LegacyRepositoryFactory = Depends(get_repository_factory),
    settings: Settings = Depends(get_settings),
) -> MethodologyDetail:
    try:
        repository = repositories(store.project_dir(project_id))
        states = repository.load_methodology_states()
        item = _methodology_item(settings, vuln_id, states)
        if not item:
            raise HTTPException(status_code=404, detail="Methodology check not found")
        states[vuln_id] = payload.model_dump()
        repository.save_methodology_state(states)
        vuln, state = item
        return MethodologyDetail.model_validate({**vuln, **payload.model_dump(), "description": _methodology_description(settings, vuln.get("description_file", ""))})
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc
    except PyMongoError as exc:
        raise HTTPException(status_code=503, detail="Database unavailable") from exc
