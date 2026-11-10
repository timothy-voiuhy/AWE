"""Compose feature routers and retain public dependency imports."""

from fastapi import APIRouter

from .routes import graph
from .routes import system
from .routes.dependencies import (
    get_ai_service,
    get_auth_service,
    get_browser_manager,
    get_docker_operation_manager,
    get_docker_service,
    get_intruder_job_manager,
    get_intruder_service,
    get_job_manager,
    get_pipeline_catalog,
    get_project_store,
    get_proxy_control,
    get_replay_service,
    get_repository_factory,
    get_terminal_manager,
    get_vault_service,
    get_websocket_client,
)  # noqa: F401
from .routes import authentication
from .routes import projects
from .routes import methodology
from .routes import pipelines
from .routes import results
from .routes import reports
from .routes import imports
from .routes import evidence
from .routes import traffic
from .routes import testing
from .routes import docker
from .routes import vault
from .routes import browser
from .routes import ai
from .routes import terminal
from .routes import run_outputs
from .routes import sessions
from .routes import pocs

router = APIRouter()

router.include_router(graph.router)
router.include_router(system.router)
router.include_router(authentication.router)
router.include_router(projects.router)
router.include_router(methodology.router)
router.include_router(pipelines.router)
router.include_router(results.router)
router.include_router(reports.router)
router.include_router(imports.router)
router.include_router(evidence.router)
router.include_router(traffic.router)
router.include_router(testing.router)
router.include_router(docker.router)
router.include_router(vault.router)
router.include_router(browser.router)
router.include_router(ai.router)
router.include_router(terminal.router)
router.include_router(run_outputs.router)
router.include_router(sessions.router)
router.include_router(pocs.router)
