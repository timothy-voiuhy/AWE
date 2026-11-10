FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends chromium xvfb x11vnc xdotool libnss3-tools \
    && rm -rf /var/lib/apt/lists/*

COPY awe-backend /app/awe-backend
RUN python -m pip install --no-cache-dir /app/awe-backend

# Shared runtime modules used by the backend's pipeline, repository, container,
# parser, and proxy services.
COPY src /app/src
COPY dockerfiles /app/dockerfiles
COPY resources /app/resources

RUN mkdir -p /data/projects

EXPOSE 8000
CMD ["uvicorn", "awe_backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
