"""Docker API handlers and helpers."""

from ..config import Settings
from ..config import get_settings
from ..docker_operations import DockerOperationManager
from ..docker_operations import DockerOperationNotFound
from ..docker_service import DockerService
from ..projects import ProjectStore
from ..repositories import LegacyRepositoryFactory
from ..schemas import DockerContainer
from ..schemas import DockerImage
from ..schemas import DockerImageBuild
from ..schemas import DockerImagePull
from ..schemas import DockerOperation
from ..schemas import DockerTool
from ..schemas import DockerToolCreate
from ..schemas import DockerToolRun
from ..schemas import EvidenceInput
from fastapi import Depends
from fastapi import HTTPException
from pathlib import Path
import docker
import json
import secrets
import sys
from .dependencies import get_docker_operation_manager, get_docker_service, get_project_store, get_repository_factory
from .graph import _ensure_investigation, _ingest_graph_results
from .stores import _create_evidence_record
from .transform_catalog import _graph_transforms
from fastapi import APIRouter

router = APIRouter()


@router.get("/docker/containers", response_model=list[DockerContainer], tags=["docker"])
def list_docker_containers(service: DockerService = Depends(get_docker_service)) -> list[DockerContainer]:
    try: return service.list()
    except docker.errors.DockerException as exc: raise HTTPException(status_code=503, detail="Docker is unavailable") from exc


@router.post("/docker/containers/{container_id}/stop", status_code=204, tags=["docker"])
def stop_docker_container(container_id: str, service: DockerService = Depends(get_docker_service)) -> None:
    try: service.stop(container_id)
    except PermissionError as exc: raise HTTPException(status_code=403, detail=str(exc)) from exc
    except docker.errors.DockerException as exc: raise HTTPException(status_code=404, detail="Container not found") from exc


@router.post("/docker/containers/{container_id}/start", status_code=204, tags=["docker"])
def start_docker_container(container_id: str, service: DockerService = Depends(get_docker_service)) -> None:
    try: service.start(container_id)
    except PermissionError as exc: raise HTTPException(status_code=403, detail=str(exc)) from exc
    except docker.errors.DockerException as exc: raise HTTPException(status_code=404, detail="Container not found") from exc


@router.delete("/docker/containers/{container_id}", status_code=204, tags=["docker"])
def remove_docker_container(container_id: str, service: DockerService = Depends(get_docker_service)) -> None:
    try: service.remove(container_id)
    except PermissionError as exc: raise HTTPException(status_code=403, detail=str(exc)) from exc
    except docker.errors.DockerException as exc: raise HTTPException(status_code=404, detail="Container not found") from exc


@router.get("/docker/images", response_model=list[DockerImage], tags=["docker"])
def list_docker_images(service: DockerService = Depends(get_docker_service)) -> list[DockerImage]:
    try:
        import sys
        source = str(get_settings().legacy_src_dir.resolve())
        if source not in sys.path: sys.path.insert(0, source)
        from containers.tool_registry import TOOL_REGISTRY
        return [DockerImage.model_validate(item) for item in service.images({tool.image for tool in TOOL_REGISTRY.values()})]
    except docker.errors.DockerException as exc: raise HTTPException(status_code=503, detail="Docker is unavailable") from exc


@router.delete("/docker/images/{image}", status_code=204, tags=["docker"])
def remove_docker_image(image: str, service: DockerService = Depends(get_docker_service)) -> None:
    try: service.remove_image(image)
    except docker.errors.DockerException as exc: raise HTTPException(status_code=404, detail="Image not found") from exc


@router.post("/docker/images/pull", response_model=dict, tags=["docker"])
def pull_docker_image(payload: DockerImagePull, service: DockerService = Depends(get_docker_service)) -> dict:
    try: return service.pull_image(payload.image)
    except docker.errors.DockerException as exc: raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/docker/images/build", response_model=dict, tags=["docker"])
def build_docker_image(payload: DockerImageBuild, service: DockerService = Depends(get_docker_service)) -> dict:
    try: return service.build_image(payload.dockerfile, payload.tag)
    except docker.errors.DockerException as exc: raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/docker/tools/images/{operation}", response_model=dict, tags=["docker"])
def operate_tool_images(operation: str, service: DockerService = Depends(get_docker_service), manager: DockerOperationManager = Depends(get_docker_operation_manager)) -> dict:
    if operation not in {"build", "pull", "setup"}: raise HTTPException(status_code=422, detail="Operation must be build, pull, or setup")
    try: return manager.start_images(operation, service).model_dump()
    except Exception as exc: raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/docker/tools/{key}/image/{operation}", response_model=DockerOperation, tags=["docker"])
def operate_one_tool_image(key: str, operation: str, service: DockerService = Depends(get_docker_service), manager: DockerOperationManager = Depends(get_docker_operation_manager)) -> DockerOperation:
    if operation not in {"build", "pull"}: raise HTTPException(status_code=422, detail="Operation must be build or pull")
    try: return manager.start_one_image(key, operation, service)
    except KeyError: raise HTTPException(status_code=404, detail="Tool not found")
    except Exception as exc: raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/docker/tools", response_model=DockerTool, status_code=201, tags=["docker"])
def create_docker_tool(payload: DockerToolCreate, settings: Settings = Depends(get_settings)) -> DockerTool:
    import json, sys
    source = str(settings.legacy_src_dir.resolve())
    if source not in sys.path: sys.path.insert(0, source)
    try:
        from config.config import CUSTOM_TOOLS_DIR
        from containers.custom_tools import register_custom_tool
        from containers.tool_registry import TOOL_REGISTRY
        if payload.key in TOOL_REGISTRY: raise ValueError(f"Tool key '{payload.key}' already exists")
        tool_dir = Path(CUSTOM_TOOLS_DIR) / payload.key
        tool_dir.mkdir(parents=True, exist_ok=True)
        (tool_dir / "tool.json").write_text(json.dumps(payload.model_dump(exclude={"dockerfile", "parser"}), indent=2))
        if payload.dockerfile: (tool_dir / "Dockerfile").write_text(payload.dockerfile)
        if payload.parser: (tool_dir / "parser.py").write_text(payload.parser)
        register_custom_tool(str(tool_dir))
        return _docker_tool_detail(payload.key)
    except Exception as exc: raise HTTPException(status_code=400, detail=str(exc)) from exc


def _docker_tool_detail(key: str) -> DockerTool:
    from containers.custom_tools import CustomToolConfig
    from containers.tool_registry import TOOL_REGISTRY
    from containers.parsers import PARSERS
    tool = TOOL_REGISTRY[key]
    is_custom = isinstance(tool, CustomToolConfig)
    input_types = list(getattr(tool, "input_types", ()) or ())
    output_types = list(getattr(tool, "output_types", ()) or ())
    relationship_types = list(getattr(tool, "relationship_types", ()) or ())
    return DockerTool(key=key, display_name=tool.display_name, category=tool.category, image=tool.image, description=tool.description, param_specs=tool.param_spec(), source="build" if tool.dockerfile else "hub", is_custom=is_custom, status="ok" if key in PARSERS else "no parser", command_template=getattr(tool, "command_template", ""), dockerfile=Path(tool.dockerfile).read_text(errors="replace") if is_custom and tool.dockerfile and Path(tool.dockerfile).exists() else "", parser=Path(tool.parser_path).read_text(errors="replace") if is_custom and tool.parser_path and Path(tool.parser_path).exists() else "", input_types=input_types, output_types=output_types, relationship_types=relationship_types, execution_mode=getattr(tool, "execution_mode", "passive"), credential_fields=list(getattr(tool, "credential_fields", ()) or ()), graph_enabled=bool(input_types and output_types and key in PARSERS))


@router.put("/docker/tools/{key}", response_model=DockerTool, tags=["docker"])
def update_docker_tool(key: str, payload: DockerToolCreate, settings: Settings = Depends(get_settings)) -> DockerTool:
    import json, sys
    source = str(settings.legacy_src_dir.resolve())
    if source not in sys.path: sys.path.insert(0, source)
    try:
        from containers.custom_tools import CustomToolConfig, register_custom_tool
        from containers.tool_registry import TOOL_REGISTRY
        if payload.key != key: raise ValueError("Tool key cannot be changed")
        if not isinstance(TOOL_REGISTRY.get(key), CustomToolConfig): raise KeyError(key)
        tool_dir = Path(TOOL_REGISTRY[key].tool_dir)
        (tool_dir / "tool.json").write_text(json.dumps(payload.model_dump(exclude={"dockerfile", "parser"}), indent=2))
        (tool_dir / "Dockerfile").write_text(payload.dockerfile)
        (tool_dir / "parser.py").write_text(payload.parser)
        register_custom_tool(str(tool_dir))
        return _docker_tool_detail(key)
    except KeyError as exc: raise HTTPException(status_code=404, detail="Custom tool not found") from exc
    except Exception as exc: raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.delete("/docker/tools/{key}", status_code=204, tags=["docker"])
def delete_docker_tool(key: str, settings: Settings = Depends(get_settings)) -> None:
    import sys
    source = str(settings.legacy_src_dir.resolve())
    if source not in sys.path: sys.path.insert(0, source)
    try:
        from containers.custom_tools import remove_custom_tool
        remove_custom_tool(key)
    except ValueError as exc: raise HTTPException(status_code=404, detail="Custom tool not found") from exc


@router.post("/docker/prune", response_model=dict, tags=["docker"])
def prune_docker(service: DockerService = Depends(get_docker_service)) -> dict:
    try: return {"removed": service.prune()}
    except docker.errors.DockerException as exc: raise HTTPException(status_code=503, detail="Docker is unavailable") from exc


@router.get("/docker/containers/{container_id}/logs", response_model=list[str], tags=["docker"])
def docker_logs(container_id: str, service: DockerService = Depends(get_docker_service)) -> list[str]:
    try: return service.logs(container_id)
    except PermissionError as exc: raise HTTPException(status_code=403, detail=str(exc)) from exc
    except docker.errors.DockerException as exc: raise HTTPException(status_code=404, detail="Container not found") from exc


@router.get("/docker/tools", response_model=list[DockerTool], tags=["docker"])
def list_docker_tools(settings: Settings = Depends(get_settings), service: DockerService = Depends(get_docker_service)) -> list[DockerTool]:
    import sys
    source=str(settings.legacy_src_dir.resolve())
    if source not in sys.path: sys.path.insert(0,source)
    try:
        from containers.tool_registry import TOOL_REGISTRY
        local = {tag for item in service.images() for tag in item["tags"]}
        result = []
        for key, tool in TOOL_REGISTRY.items():
            item = _docker_tool_detail(key)
            item.image_present = tool.image in local or any(tag.split(":")[0] == tool.image.split(":")[0] for tag in local)
            result.append(item)
        return result
    except Exception as exc: raise HTTPException(status_code=503, detail=f"Tool registry unavailable: {exc}") from exc


@router.get("/docker/status", response_model=dict, tags=["docker"])
def docker_status(service: DockerService = Depends(get_docker_service)) -> dict:
    try: return service.status()
    except docker.errors.DockerException as exc: return {"available": False, "version": "", "message": str(exc)}


@router.get("/docker/operations/{operation_id}", response_model=DockerOperation, tags=["docker"])
def get_docker_operation(operation_id: str, manager: DockerOperationManager = Depends(get_docker_operation_manager)) -> DockerOperation:
    try: return manager.get(operation_id)
    except DockerOperationNotFound as exc: raise HTTPException(status_code=404, detail="Operation not found") from exc


@router.get("/docker/operations", response_model=list[DockerOperation], tags=["docker"])
def list_recent_docker_tool_runs(manager: DockerOperationManager = Depends(get_docker_operation_manager)) -> list[DockerOperation]:
    return manager.recent_tool_runs()


@router.post("/docker/operations/{operation_id}/cancel", response_model=DockerOperation, tags=["docker"])
def cancel_docker_operation(operation_id: str, manager: DockerOperationManager = Depends(get_docker_operation_manager)) -> DockerOperation:
    try: return manager.cancel(operation_id)
    except DockerOperationNotFound as exc: raise HTTPException(status_code=404, detail="Operation not found") from exc


@router.post("/projects/{project_id}/docker/tools/{key}/runs", response_model=DockerOperation, status_code=202, tags=["docker"])
def run_docker_tool(project_id: str, key: str, payload: DockerToolRun, store: ProjectStore = Depends(get_project_store), service: DockerService = Depends(get_docker_service), manager: DockerOperationManager = Depends(get_docker_operation_manager), repositories: LegacyRepositoryFactory = Depends(get_repository_factory), settings: Settings = Depends(get_settings)) -> DockerOperation:
    project = store.get(project_id)
    project_dir = store.project_dir(project_id).resolve()
    source = str(settings.legacy_src_dir.resolve())
    if source not in sys.path: sys.path.insert(0, source)
    from containers.tool_registry import TOOL_REGISTRY
    tool = TOOL_REGISTRY.get(key)
    if not tool:
        raise HTTPException(status_code=404, detail="Tool not found")
    if getattr(tool, "execution_mode", "passive") in {"active", "high_risk"} and not payload.approved:
        raise HTTPException(status_code=409, detail="This tool requires explicit approval before execution")
    callback = None
    if payload.ingest_to_graph:
        investigation_id = payload.investigation_id
        if not investigation_id:
            investigation_id = _ensure_investigation(project_id, project_dir, project.target, repositories).id
        manifests = {item.tool_key: item for item in _graph_transforms(settings, project_dir)}
        manifest = manifests.get(key)
        if not manifest:
            raise HTTPException(status_code=422, detail="This tool has no graph contract and cannot be ingested")
        run_id = f"docker-{key}-{secrets.token_hex(6)}"
        def on_complete(parsed: list, _output_dir: Path) -> dict:
            count = _ingest_graph_results(project_id, project_dir, investigation_id, project.target, repositories, manifest, parsed, "", run_id)
            evidence = _create_evidence_record(project_id, project_dir, EvidenceInput(
                investigation_id=investigation_id,
                title=f"{manifest.display_name} Docker output",
                summary=f"Parsed {len(parsed)} result(s) and ingested {count} graph output(s).",
                kind="tool_output",
                source_type="docker_tool",
                source_id=run_id,
                tags=["docker", key, *manifest.output_types[:5]],
                data={
                    "tool_key": key,
                    "output_dir": str(_output_dir),
                    "parsed_count": len(parsed),
                    "ingested_count": count,
                    "parameters": payload.params,
                },
            ))
            return {"ingested_count": count, "investigation_id": investigation_id, "evidence_id": evidence.id if evidence else ""}
        callback = on_complete
    relative = Path(payload.output_subdir)
    if relative.is_absolute() or ".." in relative.parts: raise HTTPException(status_code=422, detail="Output directory must be relative to the project")
    return manager.start_tool(key, payload.params, project_dir / relative, service, callback)
