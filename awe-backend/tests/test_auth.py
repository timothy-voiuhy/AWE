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
