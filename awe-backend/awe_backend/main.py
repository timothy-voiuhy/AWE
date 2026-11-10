from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api import get_browser_manager, router
from .auth import AuthService
from .auth_middleware import AuthenticationMiddleware
from .config import Settings, get_settings


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    app = FastAPI(
        title=settings.app_name,
        version="0.1.0",
        docs_url=f"{settings.api_prefix}/docs",
        openapi_url=f"{settings.api_prefix}/openapi.json",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE"],
        allow_headers=["Content-Type", "Authorization", "X-AWE-CSRF"],
    )
    app.add_middleware(
        AuthenticationMiddleware,
        auth=AuthService(settings),
        enabled=settings.auth_enabled,
    )
    app.include_router(router, prefix=settings.api_prefix)
    app.dependency_overrides[get_settings] = lambda: settings

    @app.on_event("shutdown")
    async def shutdown_browser_sessions() -> None:
        await get_browser_manager().shutdown()
        from .session_service import session_service
        await session_service().shutdown()

    @app.on_event("startup")
    async def start_sessions() -> None:
        import sys
        source = str(settings.legacy_src_dir)
        if source not in sys.path:
            sys.path.insert(0, source)
        from containers.custom_tools import load_custom_tools
        load_custom_tools()
        from .routes.dependencies import get_docker_operation_manager
        get_docker_operation_manager(settings)
        from .run_outputs import project_runs, RunOutputs
        for project_dir in settings.workspace_dir.iterdir() if settings.workspace_dir.is_dir() else []:
            if project_dir.is_dir():
                for run in project_runs(project_dir):
                    if run.get("kind", "").startswith("poc.build.") and run.get("status") == "running":
                        RunOutputs(project_dir, run["id"]).update(status="failed", message="PoC build interrupted by backend restart; register the source again to retry")
        from .session_service import session_service
        await session_service().start()

    return app


app = create_app()
