"""Authentication API handlers and helpers."""

from ..auth import AuthService
from ..auth import AuthenticationError
from ..auth import CSRF_COOKIE
from ..auth import SESSION_COOKIE
from ..config import Settings
from ..config import get_settings
from ..schemas import AuthSession
from ..schemas import HealthResponse
from ..schemas import LoginRequest
from ..schemas import SetupRequest
from ..schemas import SetupStatus
from fastapi import Depends
from fastapi import HTTPException
from fastapi import Request
from fastapi import Response
from fastapi import status
from .dependencies import get_auth_service
from fastapi import APIRouter

router = APIRouter()


@router.get("/health", response_model=HealthResponse, tags=["system"])
def health(settings: Settings = Depends(get_settings)) -> HealthResponse:
    return HealthResponse(status="ok", service=settings.app_name, version="0.1.0")


@router.post("/auth/login", response_model=AuthSession, tags=["authentication"])
def login(
    payload: LoginRequest,
    response: Response,
    auth: AuthService = Depends(get_auth_service),
) -> AuthSession:
    try:
        token, session = auth.login(payload.username, payload.password)
    except AuthenticationError as exc:
        raise HTTPException(status_code=401, detail="Invalid credentials") from exc
    _set_auth_cookies(response, auth, token, session.csrf)
    return AuthSession(username=session.username, csrf_token=session.csrf)


def _set_auth_cookies(response: Response, auth: AuthService, token: str, csrf: str) -> None:
    cookie_options = {
        "secure": auth.settings.secure_cookies,
        "samesite": "strict",
        "max_age": auth.settings.session_ttl_seconds,
        "path": "/",
    }
    response.set_cookie(SESSION_COOKIE, token, httponly=True, **cookie_options)
    response.set_cookie(CSRF_COOKIE, csrf, httponly=False, **cookie_options)


@router.get("/auth/setup-status", response_model=SetupStatus, tags=["authentication"])
def setup_status(auth: AuthService = Depends(get_auth_service)) -> SetupStatus:
    return SetupStatus(configured=auth.is_configured())


@router.post(
    "/auth/setup",
    response_model=AuthSession,
    status_code=status.HTTP_201_CREATED,
    tags=["authentication"],
)
def setup_account(
    payload: SetupRequest,
    response: Response,
    auth: AuthService = Depends(get_auth_service),
) -> AuthSession:
    try:
        token, session = auth.setup(payload.username, payload.password)
    except AuthenticationError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    _set_auth_cookies(response, auth, token, session.csrf)
    return AuthSession(username=session.username, csrf_token=session.csrf)


@router.get("/auth/session", response_model=AuthSession, tags=["authentication"])
def auth_session(
    request: Request,
    auth: AuthService = Depends(get_auth_service),
) -> AuthSession:
    session = auth.verify(request.cookies.get(SESSION_COOKIE, ""))
    return AuthSession(username=session.username, csrf_token=session.csrf)


@router.post("/auth/logout", status_code=status.HTTP_204_NO_CONTENT, tags=["authentication"])
def logout(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")
