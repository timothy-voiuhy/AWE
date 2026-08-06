# AWE Backend

The web API and application-service boundary for AWE.

```bash
python -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/python -m awe_backend.password
AWE_SECRET_KEY='a-long-random-secret' \
AWE_ADMIN_PASSWORD_HASH='the-generated-argon2-hash' \
AWE_WORKSPACE_DIR=/path/to/projects \
.venv/bin/uvicorn awe_backend.main:app --reload
```

OpenAPI is available at `http://localhost:8000/api/v1/docs`.

Authentication is enabled by default. Set `AWE_SECURE_COOKIES=true` whenever
the backend is served over HTTPS. `AWE_AUTH_ENABLED=false` is intended only for
isolated development and automated tests.
