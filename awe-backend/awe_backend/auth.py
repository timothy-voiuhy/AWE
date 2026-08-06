from __future__ import annotations

import secrets
from dataclasses import dataclass

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from pwdlib import PasswordHash

from .config import Settings

SESSION_COOKIE = "awe_session"
CSRF_COOKIE = "awe_csrf"
CSRF_HEADER = "x-awe-csrf"


class AuthenticationError(ValueError):
    pass


@dataclass(frozen=True)
class Session:
    username: str
    csrf: str


class AuthService:
    def __init__(self, settings: Settings):
        self.settings = settings
        self._serializer = URLSafeTimedSerializer(settings.secret_key, salt="awe-session-v1")
        self._passwords = PasswordHash.recommended()

    def login(self, username: str, password: str) -> tuple[str, Session]:
        if username != "admin" or not self.settings.admin_password_hash:
            raise AuthenticationError("Invalid credentials")
        try:
            valid = self._passwords.verify(password, self.settings.admin_password_hash)
        except Exception as exc:
            raise AuthenticationError("Invalid credentials") from exc
        if not valid:
            raise AuthenticationError("Invalid credentials")
        session = Session(username="admin", csrf=secrets.token_urlsafe(32))
        token = self._serializer.dumps({"username": session.username, "csrf": session.csrf})
        return token, session

    def verify(self, token: str) -> Session:
        try:
            data = self._serializer.loads(token, max_age=self.settings.session_ttl_seconds)
            return Session(username=data["username"], csrf=data["csrf"])
        except (BadSignature, SignatureExpired, KeyError, TypeError) as exc:
            raise AuthenticationError("Invalid or expired session") from exc


def hash_password(password: str) -> str:
    return PasswordHash.recommended().hash(password)
