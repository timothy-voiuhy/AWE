import stat

from fastapi.testclient import TestClient

from awe_backend.auth import CSRF_HEADER, hash_password
from awe_backend.config import Settings
from awe_backend.main import create_app


def test_authentication_and_csrf_protect_api(tmp_path):
    settings = Settings(
        auth_enabled=True,
        secret_key="test-secret-key-that-is-not-used-in-production",
        admin_password_hash=hash_password("correct horse battery staple"),
        workspace_dir=tmp_path,
    )
    app = create_app(settings)

    with TestClient(app) as client:
        assert client.get("/api/v1/health").status_code == 200
        assert client.get("/api/v1/projects").status_code == 401

        invalid = client.post(
            "/api/v1/auth/login", json={"username": "admin", "password": "wrong"}
        )
        assert invalid.status_code == 401

        login = client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "correct horse battery staple"},
        )
        assert login.status_code == 200
        csrf = login.json()["csrf_token"]
        assert client.get("/api/v1/auth/session").status_code == 200
        assert client.get("/api/v1/projects").status_code == 200

        blocked = client.post("/api/v1/projects", json={"name": "No CSRF"})
        assert blocked.status_code == 403
        allowed = client.post(
            "/api/v1/projects",
            json={"name": "Authenticated"},
            headers={CSRF_HEADER: csrf},
        )
        assert allowed.status_code == 201

        logout = client.post("/api/v1/auth/logout")
        assert logout.status_code == 204
        assert client.get("/api/v1/projects").status_code == 401


def test_first_run_creates_one_local_account(tmp_path):
    auth_file = tmp_path / "auth" / "account.json"
    settings = Settings(
        auth_enabled=True,
        secret_key="another-test-secret-key-not-for-production",
        admin_password_hash="",
        auth_file=auth_file,
        workspace_dir=tmp_path / "projects",
    )
    app = create_app(settings)

    with TestClient(app) as client:
        assert client.get("/api/v1/auth/setup-status").json() == {"configured": False}

        too_short = client.post(
            "/api/v1/auth/setup", json={"username": "owner", "password": "short"}
        )
        assert too_short.status_code == 422

        setup = client.post(
            "/api/v1/auth/setup",
            json={"username": "owner", "password": "a strong local password"},
        )
        assert setup.status_code == 201
        assert setup.json()["username"] == "owner"
        assert auth_file.is_file()
        assert stat.S_IMODE(auth_file.stat().st_mode) == 0o600
        assert client.get("/api/v1/auth/setup-status").json() == {"configured": True}

        duplicate = client.post(
            "/api/v1/auth/setup",
            json={"username": "other", "password": "another strong password"},
        )
        assert duplicate.status_code == 409

        created = client.post(
            "/api/v1/projects",
            json={"name": "First project"},
            headers={CSRF_HEADER: setup.json()["csrf_token"]},
        )
        assert created.status_code == 201
