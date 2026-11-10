FROM golang:1.24-alpine AS pty-build
WORKDIR /build
COPY awe-backend/pty-runner/main.go ./main.go
RUN CGO_ENABLED=0 go build -o /pty-runner main.go

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends chromium xvfb x11vnc xdotool libnss3-tools \
    && rm -rf /var/lib/apt/lists/*

RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

COPY awe-backend/pyproject.toml /tmp/awe-pyproject.toml
RUN python -c "import subprocess, tomllib; deps = tomllib.load(open('/tmp/awe-pyproject.toml', 'rb'))['project']['dependencies']; subprocess.check_call(['python', '-m', 'pip', 'install', '--no-cache-dir', 'setuptools>=68', *deps])"
COPY awe-backend /app/awe-backend
COPY --from=pty-build /pty-runner /usr/local/lib/awe/pty-runner
RUN python -m pip install --no-deps --no-build-isolation /app/awe-backend

# Shared runtime modules used by the backend's pipeline, repository, container,
# parser, and proxy services.
COPY src /app/src
COPY dockerfiles /app/dockerfiles
COPY resources /app/resources

RUN mkdir -p /data/projects

EXPOSE 8000
CMD ["uvicorn", "awe_backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
