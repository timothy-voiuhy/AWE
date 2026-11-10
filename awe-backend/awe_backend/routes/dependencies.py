"""Dependencies API handlers and helpers."""

from ..ai_service import AIService
from ..auth import AuthService
from ..browser import BrowserSessionManager
from ..config import Settings
from ..config import get_settings
from ..docker_operations import DockerOperationManager
from ..docker_service import DockerService
from ..intruder_jobs import IntruderJobManager
from ..jobs import PipelineJobManager
from ..pipelines import PipelineCatalog
from ..projects import ProjectStore
from ..replay import HttpReplayService
from ..repositories import LegacyRepositoryFactory
from ..terminal import TerminalManager
from ..testing_services import IntruderService
from ..testing_services import ProxyControlService
from ..testing_services import WebSocketClientService
from ..vault import VaultService
from fastapi import Depends
from fastapi import HTTPException
from functools import lru_cache
from pathlib import Path


@lru_cache
def _store_for_workspace(workspace: str) -> ProjectStore:
    from pathlib import Path

    return ProjectStore(Path(workspace))


def get_project_store(settings: Settings = Depends(get_settings)) -> ProjectStore:
    return _store_for_workspace(str(settings.workspace_dir.resolve()))


def get_pipeline_catalog(settings: Settings = Depends(get_settings)) -> PipelineCatalog:
    return PipelineCatalog(settings.legacy_src_dir)


@lru_cache
def _job_manager(legacy_src: str, mongo_uri: str) -> PipelineJobManager:
    from pathlib import Path

    return PipelineJobManager(Path(legacy_src), mongo_uri)


def get_job_manager(settings: Settings = Depends(get_settings)) -> PipelineJobManager:
    return _job_manager(str(settings.legacy_src_dir.resolve()), settings.mongo_uri)


def get_repository_factory(
    settings: Settings = Depends(get_settings),
) -> LegacyRepositoryFactory:
    return LegacyRepositoryFactory(settings.legacy_src_dir, settings.mongo_uri)


def get_replay_service() -> HttpReplayService:
    return HttpReplayService()


def get_docker_service() -> DockerService: return DockerService()


@lru_cache
def _docker_operation_manager(workspace: str, docker_workspace: str) -> DockerOperationManager:
    return DockerOperationManager(Path(workspace) / ".awe-docker-operations.json", workspace_dir=Path(workspace), docker_workspace_dir=Path(docker_workspace))


def get_docker_operation_manager(settings: Settings = Depends(get_settings)) -> DockerOperationManager:
    return _docker_operation_manager(str(settings.workspace_dir.resolve()), str(settings.docker_workspace_dir))


def get_vault_service(settings: Settings = Depends(get_settings)) -> VaultService:
    return VaultService(settings.secret_key)


@lru_cache
def get_browser_manager() -> BrowserSessionManager:
    return BrowserSessionManager()


def get_ai_service(project_id: str, store: ProjectStore = Depends(get_project_store), settings: Settings = Depends(get_settings)) -> AIService:
    return AIService(store.project_dir(project_id), settings.secret_key)


@lru_cache
def get_terminal_manager() -> TerminalManager:
    return TerminalManager()


@lru_cache
def get_intruder_service() -> IntruderService:
    return IntruderService()


@lru_cache
def _intruder_manager(workspace: str, mongo_uri: str) -> IntruderJobManager:
    return IntruderJobManager(get_intruder_service(), Path(workspace), mongo_uri)


def get_intruder_job_manager(settings: Settings = Depends(get_settings)) -> IntruderJobManager:
    return _intruder_manager(str(settings.workspace_dir.resolve()), settings.mongo_uri)


def get_proxy_control(settings: Settings = Depends(get_settings)) -> ProxyControlService:
    try:
        return ProxyControlService(settings.legacy_src_dir, settings.proxy_control_host, settings.proxy_control_port)
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=503, detail="AWE proxy is unavailable") from exc


def get_websocket_client() -> WebSocketClientService:
    return WebSocketClientService()


@lru_cache
def _auth_service(settings_json: str) -> AuthService:
    return AuthService(Settings.model_validate_json(settings_json))


def get_auth_service(settings: Settings = Depends(get_settings)) -> AuthService:
    return _auth_service(settings.model_dump_json())
