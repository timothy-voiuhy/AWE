from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api import router
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
    return app


app = create_app()
