#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${AWE_BACKEND_VENV:-${SCRIPT_DIR}/.venv}"
PYTHON_BIN="${VENV_DIR}/bin/python"
PIP_BIN="${VENV_DIR}/bin/pip"
STAMP_FILE="${VENV_DIR}/.awe-dependencies.sha256"
HOST="${AWE_BACKEND_HOST:-127.0.0.1}"
PORT="${AWE_BACKEND_PORT:-8001}"
RELOAD="${AWE_BACKEND_RELOAD:-1}"

create_venv() {
    if python3 -m venv "${VENV_DIR}" 2>/dev/null; then
        return
    fi
    if python3 -m virtualenv "${VENV_DIR}" 2>/dev/null; then
        return
    fi
    if command -v virtualenv >/dev/null 2>&1; then
        virtualenv "${VENV_DIR}"
        return
    fi
    echo "Unable to create ${VENV_DIR}. Install python3-venv or virtualenv, then retry." >&2
    exit 1
}

dependency_hash() {
    sha256sum "${SCRIPT_DIR}/pyproject.toml" | awk '{print $1}'
}

dependencies_work() {
    "${PYTHON_BIN}" -c \
        "import awe_backend, docker, fastapi, itsdangerous, pwdlib, pymongo, pydantic_settings, uvicorn" \
        >/dev/null 2>&1
}

mongo_works() {
    AWE_MONGO_URI="${AWE_MONGO_URI:-mongodb://127.0.0.1:27017}" \
        "${PYTHON_BIN}" -c \
        "import os; from pymongo import MongoClient; MongoClient(os.environ['AWE_MONGO_URI'], serverSelectionTimeoutMS=500).admin.command('ping')" \
        >/dev/null 2>&1
}

ensure_mongo() {
    if mongo_works; then
        echo "MongoDB is available"
        return
    fi
    if [[ "${AWE_MONGO_URI:-mongodb://127.0.0.1:27017}" != mongodb://localhost:27017* && \
          "${AWE_MONGO_URI:-mongodb://127.0.0.1:27017}" != mongodb://127.0.0.1:27017* ]]; then
        echo "MongoDB is unavailable at ${AWE_MONGO_URI}. Start it and retry." >&2
        exit 1
    fi
    if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
        echo "MongoDB is unavailable. Start MongoDB on port 27017 or start Docker and retry." >&2
        exit 1
    fi

    if docker container inspect awe-mongo-local >/dev/null 2>&1; then
        echo "Starting existing awe-mongo-local container"
        docker start awe-mongo-local >/dev/null
    else
        echo "Creating local MongoDB container"
        docker run -d \
            --name awe-mongo-local \
            --restart unless-stopped \
            -p 127.0.0.1:27017:27017 \
            -v awe_mongo_local:/data/db \
            mongo:7 >/dev/null
    fi

    for _ in {1..30}; do
        if mongo_works; then
            echo "MongoDB is ready"
            return
        fi
        sleep 1
    done
    echo "MongoDB did not become ready. Check: docker logs awe-mongo-local" >&2
    exit 1
}

if [[ ! -x "${PYTHON_BIN}" || ! -x "${PIP_BIN}" ]]; then
    echo "Creating backend virtual environment at ${VENV_DIR}"
    create_venv
fi

CURRENT_HASH="$(dependency_hash)"
INSTALLED_HASH=""
if [[ -f "${STAMP_FILE}" ]]; then
    INSTALLED_HASH="$(<"${STAMP_FILE}")"
fi

if [[ "${CURRENT_HASH}" != "${INSTALLED_HASH}" ]] || ! dependencies_work; then
    echo "Installing or updating AWE backend dependencies"
    "${PIP_BIN}" install --disable-pip-version-check -e "${SCRIPT_DIR}"
    printf '%s\n' "${CURRENT_HASH}" > "${STAMP_FILE}"
else
    echo "Backend dependencies are up to date"
fi

if [[ "${AWE_BACKEND_CHECK_ONLY:-0}" == "1" ]]; then
    echo "Backend dependency check passed"
    exit 0
fi

if [[ "${AWE_BACKEND_SKIP_MONGO:-0}" != "1" ]]; then
    ensure_mongo
fi

echo "Starting AWE backend at http://${HOST}:${PORT}"
UVICORN_ARGS=(awe_backend.main:app \
    --host "${HOST}" \
    --port "${PORT}")
if [[ "${RELOAD}" == "1" ]]; then
    UVICORN_ARGS+=(--reload --reload-dir "${SCRIPT_DIR}/awe_backend")
fi
exec "${PYTHON_BIN}" -m uvicorn "${UVICORN_ARGS[@]}" "$@"
