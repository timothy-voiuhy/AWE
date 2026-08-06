from __future__ import annotations

import secrets
import json
import os
import threading
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
        self._setup_lock = threading.Lock()

    def account(self) -> tuple[str, str] | None:
        if self.settings.admin_password_hash:
            return "admin", self.settings.admin_password_hash
        try:
            data = json.loads(self.settings.auth_file.read_text(encoding="utf-8"))
            return str(data["username"]), str(data["password_hash"])
        except (FileNotFoundError, OSError, ValueError, KeyError, TypeError):
            return None

    def is_configured(self) -> bool:
        return self.account() is not None

    def setup(self, username: str, password: str) -> tuple[str, Session]:
        username = username.strip()
        if not username:
            raise AuthenticationError("Username cannot be empty")
        with self._setup_lock:
            if self.is_configured():
                raise AuthenticationError("A local account is already configured")
            auth_file = self.settings.auth_file
            auth_file.parent.mkdir(parents=True, exist_ok=True)
            temporary = auth_file.with_suffix(".tmp")
            temporary.write_text(
                json.dumps({"username": username, "password_hash": self._passwords.hash(password)}, indent=2),
                encoding="utf-8",
            )
            os.chmod(temporary, 0o600)
            temporary.replace(auth_file)
        return self.login(username, password)

    def login(self, username: str, password: str) -> tuple[str, Session]:
        account = self.account()
        if account is None or username != account[0]:
            raise AuthenticationError("Invalid credentials")
        try:
            valid = self._passwords.verify(password, account[1])
        except Exception as exc:
            raise AuthenticationError("Invalid credentials") from exc
        if not valid:
            raise AuthenticationError("Invalid credentials")
        session = Session(username=username, csrf=secrets.token_urlsafe(32))
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
