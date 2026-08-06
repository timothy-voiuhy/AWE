from __future__ import annotations

import secrets
from http.cookies import SimpleCookie

from starlette.responses import JSONResponse

from .auth import CSRF_COOKIE, CSRF_HEADER, SESSION_COOKIE, AuthService, AuthenticationError

_PUBLIC_PATHS = {
    "/api/v1/health",
    "/api/v1/auth/login",
    "/api/v1/auth/setup",
    "/api/v1/auth/setup-status",
}
_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


class AuthenticationMiddleware:
    """ASGI middleware protecting both HTTP and WebSocket connections."""

    def __init__(self, app, auth: AuthService, enabled: bool = True):
        self.app = app
        self.auth = auth
        self.enabled = enabled

    async def __call__(self, scope, receive, send):
        if not self.enabled or scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        if scope["type"] == "http" and (path in _PUBLIC_PATHS or path.startswith("/api/v1/docs") or path == "/api/v1/openapi.json"):
            await self.app(scope, receive, send)
            return

        headers = {key.decode().lower(): value.decode() for key, value in scope.get("headers", [])}
        cookies = SimpleCookie()
        cookies.load(headers.get("cookie", ""))
        token = cookies.get(SESSION_COOKIE)
        try:
            session = self.auth.verify(token.value if token else "")
        except AuthenticationError:
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 4401, "reason": "Authentication required"})
            else:
                await JSONResponse({"detail": "Authentication required"}, status_code=401)(scope, receive, send)
            return

        if scope["type"] == "http" and scope.get("method") not in _SAFE_METHODS and path != "/api/v1/auth/logout":
            csrf_cookie = cookies.get(CSRF_COOKIE)
            csrf_header = headers.get(CSRF_HEADER, "")
            if not csrf_cookie or not secrets.compare_digest(csrf_cookie.value, session.csrf) or not secrets.compare_digest(csrf_header, session.csrf):
                await JSONResponse({"detail": "CSRF validation failed"}, status_code=403)(scope, receive, send)
                return

        scope.setdefault("state", {})["user"] = session.username
        await self.app(scope, receive, send)
