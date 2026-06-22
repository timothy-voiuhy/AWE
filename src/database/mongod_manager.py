"""
MongoDB lifecycle manager — Docker-based.

Runs the official mongo:7 image as a named container "awe_mongodb".
Data persists in ~/.awe/mongodb/data so it survives container restarts.
Port 27017 is bound to 127.0.0.1 only (not exposed on the network).

AWE does not require MongoDB to be installed on the host system; the
container is pulled automatically on first use.

Public API (unchanged from the old subprocess-based version):
  ensure_running() -> (ok: bool, message: str)
  shutdown()
  status() -> dict
"""
import atexit
import logging
import time
from pathlib import Path

from database.mongo import ping

logger = logging.getLogger(__name__)

_CONTAINER_NAME = "awe_mongodb"
_IMAGE          = "mongo:7"
_PORT           = 27017
_DATA_DIR       = Path.home() / ".awe" / "mongodb" / "data"

# True only when this AWE session brought the container up
_started_by_us: bool = False


def ensure_running() -> tuple[bool, str]:
    """Ensure the MongoDB container is running.

    Returns (True, version_string) on success, (False, error_message) on failure.
    Safe to call multiple times — no-ops if MongoDB is already reachable.
    """
    global _started_by_us

    # Already reachable (container running from a previous session, or system mongo)
    ok, msg = ping()
    if ok:
        return True, msg

    # Import here to avoid a circular dependency at module load time
    try:
        from containers.docker_manager import manager as docker
    except Exception as exc:
        return False, f"Docker manager unavailable: {exc}"

    docker_ok, docker_msg = docker.is_available()
    if not docker_ok:
        return False, f"Docker unavailable — cannot start MongoDB: {docker_msg}"

    _DATA_DIR.mkdir(parents=True, exist_ok=True)

    try:
        docker.ensure_service_container(
            name=_CONTAINER_NAME,
            image=_IMAGE,
            ports={"27017/tcp": ("127.0.0.1", _PORT)},
            volumes={str(_DATA_DIR): {"bind": "/data/db", "mode": "rw"}},
        )
        _started_by_us = True
        atexit.register(shutdown)
    except Exception as exc:
        return False, f"Could not start MongoDB container: {exc}"

    # Wait up to 15 s for mongod to be ready inside the container
    for attempt in range(30):
        time.sleep(0.5)
        ok, msg = ping()
        if ok:
            logger.info("MongoDB container ready after %.1fs", (attempt + 1) * 0.5)
            return True, msg

    return False, "MongoDB container did not become ready within 15 seconds"


def shutdown() -> None:
    """Stop the MongoDB container if this AWE session started it."""
    global _started_by_us
    if not _started_by_us:
        return
    logger.info("Stopping MongoDB container (%s)", _CONTAINER_NAME)
    try:
        from containers.docker_manager import manager as docker
        docker.stop_service_container(_CONTAINER_NAME)
    except Exception as exc:
        logger.warning("Error stopping MongoDB container: %s", exc)
    _started_by_us = False


def status() -> dict:
    """Return a status dict suitable for display in the UI."""
    ok, msg = ping()
    container_status = "unknown"
    try:
        from containers.docker_manager import manager as docker
        c = docker.get_container(_CONTAINER_NAME)
        container_status = c.status if c else "not found"
    except Exception:
        pass
    return {
        "connected":      ok,
        "message":        msg,
        "managed":        _started_by_us,
        "container_name": _CONTAINER_NAME,
        "container_up":   container_status == "running",
        "container_status": container_status,
        "data_dir":       str(_DATA_DIR),
    }
