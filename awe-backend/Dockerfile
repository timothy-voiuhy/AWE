FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY awe-backend /app/awe-backend
RUN python -m pip install --no-cache-dir /app/awe-backend
RUN python -m playwright install --with-deps chromium

# Migration bridge: the backend currently reuses AWE's Qt-free pipeline,
# repository, container registry, and parser modules from the legacy tree.
COPY src /app/src
COPY dockerfiles /app/dockerfiles
COPY resources /app/resources

RUN mkdir -p /data/projects

EXPOSE 8000
CMD ["uvicorn", "awe_backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
