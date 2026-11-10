"""Results API handlers and helpers."""

from ..projects import ProjectNotFoundError
from ..projects import ProjectStore
from ..repositories import LegacyRepositoryFactory
from ..schemas import ResultActionInput
from ..schemas import StoredResult
from fastapi import Depends
from fastapi import HTTPException
from pymongo.errors import PyMongoError
from .dependencies import get_project_store, get_repository_factory
from fastapi import APIRouter

router = APIRouter()


def _merged_project_results(repository, category: str | None = None, limit: int = 5000) -> list[StoredResult]:
    docs = repository.get_results_project(category=category)
    merged: dict[tuple[str, str], dict] = {}
    for item in docs:
        key = (item.get("category", ""), item.get("result_key", ""))
        if key not in merged:
            merged[key] = dict(item)
            merged[key]["sources"] = list(item.get("sources", []))
        else:
            merged[key]["sources"] = sorted(set(merged[key]["sources"]) | set(item.get("sources", [])))
    return _results_with_review_state(repository, list(merged.values())[:limit])


def _results_with_review_state(repository, results: list[dict]) -> list[StoredResult]:
    reviewed_by_category = {
        category: repository.get_reviewed_keys(category)
        for category in {str(item.get("category", "")) for item in results}
    }
    return [
        StoredResult.model_validate({
            **item,
            "reviewed": item.get("result_key", "") in reviewed_by_category.get(str(item.get("category", "")), set()),
        })
        for item in results
    ]


@router.get(
    "/projects/{project_id}/results",
    response_model=list[StoredResult],
    tags=["results"],
)
def list_project_results(
    project_id: str,
    category: str | None = None,
    limit: int = 5000,
    store: ProjectStore = Depends(get_project_store),
    repositories: LegacyRepositoryFactory = Depends(get_repository_factory),
) -> list[StoredResult]:
    """Return de-duplicated results from every project session, including proxy traffic."""
    limit = max(1, min(limit, 10000))
    try:
        repository = repositories(store.project_dir(project_id))
        return _merged_project_results(repository, category=category, limit=limit)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc
    except PyMongoError as exc:
        raise HTTPException(status_code=503, detail="Database unavailable") from exc


@router.get(
    "/projects/{project_id}/sessions/{session_id}/results",
    response_model=list[StoredResult],
    tags=["results"],
)
def list_session_results(
    project_id: str,
    session_id: str,
    category: str | None = None,
    limit: int = 1000,
    store: ProjectStore = Depends(get_project_store),
    repositories: LegacyRepositoryFactory = Depends(get_repository_factory),
) -> list[StoredResult]:
    limit = max(1, min(limit, 5000))
    try:
        repository = repositories(store.project_dir(project_id))
        session = repository.get_session(session_id)
        results = repository.get_results(session_id, category=category, limit=limit) if session else []
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc
    except PyMongoError as exc:
        raise HTTPException(status_code=503, detail="Database unavailable") from exc
    if session is None:
        raise HTTPException(status_code=404, detail="Scan session not found")
    return _results_with_review_state(repository, results)


@router.put(
    "/projects/{project_id}/results/reviewed",
    tags=["results"],
)
def set_result_reviewed(
    project_id: str,
    payload: ResultActionInput,
    store: ProjectStore = Depends(get_project_store),
    repositories: LegacyRepositoryFactory = Depends(get_repository_factory),
) -> dict:
    try:
        repository = repositories(store.project_dir(project_id))
        repository.mark_result_reviewed(payload.category, payload.result_key, payload.reviewed)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc
    except PyMongoError as exc:
        raise HTTPException(status_code=503, detail="Database unavailable") from exc
    return {"category": payload.category, "result_key": payload.result_key, "reviewed": payload.reviewed}


@router.delete(
    "/projects/{project_id}/results",
    tags=["results"],
)
def delete_stored_result(
    project_id: str,
    payload: ResultActionInput,
    store: ProjectStore = Depends(get_project_store),
    repositories: LegacyRepositoryFactory = Depends(get_repository_factory),
) -> dict:
    try:
        repository = repositories(store.project_dir(project_id))
        deleted = repository.delete_results(payload.category, [payload.result_key], session_id=payload.session_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc
    except PyMongoError as exc:
        raise HTTPException(status_code=503, detail="Database unavailable") from exc
    if not deleted:
        raise HTTPException(status_code=404, detail="Result not found")
    return {"category": payload.category, "result_key": payload.result_key, "deleted_count": deleted}
