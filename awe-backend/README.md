# AWE Backend

The web API and application-service boundary for AWE.

## Run locally

```bash
./run.sh --reload
```

`run.sh` creates an isolated `.venv` when necessary, installs the backend only
when `pyproject.toml` changed or required imports are missing, and starts the
API on `127.0.0.1:8001`. It also checks MongoDB and, for the default local URI,
starts a persistent `awe-mongo-local` Docker container when necessary. Override
its defaults with `AWE_BACKEND_HOST`,
`AWE_BACKEND_PORT`, or `AWE_BACKEND_VENV`. Additional arguments are forwarded
to Uvicorn.

To validate dependencies without starting the server:

```bash
AWE_BACKEND_CHECK_ONLY=1 ./run.sh
```

## Manual setup

```bash
python -m venv .venv
.venv/bin/pip install -e '.[dev]'
AWE_SECRET_KEY='a-long-random-secret' \
AWE_WORKSPACE_DIR=/path/to/projects \
.venv/bin/uvicorn awe_backend.main:app --reload --port 8001
```

For local development the backend uses port `8001`, leaving port `8000` for
the frontend. OpenAPI is available at `http://localhost:8001/api/v1/docs`.

Authentication is enabled by default. Set `AWE_SECURE_COOKIES=true` whenever
the backend is served over HTTPS. `AWE_AUTH_ENABLED=false` is intended only for
isolated development and automated tests.

On first launch, open the frontend and create the local administrator account.
The Argon2 password hash is stored in `~/.config/awe/auth.json`. For automated
deployments, `AWE_ADMIN_PASSWORD_HASH` can still provide a pre-generated hash.
