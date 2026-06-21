"""
mongod lifecycle manager.

Responsibilities:
  - Detect whether mongod is already running (ping)
  - If not, find the mongod binary and start it as a background subprocess
  - Wait until it is ready to accept connections
  - Provide a clean shutdown (called via atexit)

Data directory: ~/.awe/mongodb/data/
Log file:       ~/.awe/mongodb/mongod.log
PID file:       ~/.awe/mongodb/mongod.pid

Public API
──────────
  ensure_running() -> (ok: bool, message: str)
      Call once at startup. Safe to call multiple times — no-ops if already up.
  shutdown()
      Gracefully stop the mongod instance AWE started (not one the user started).
"""
import atexit
import logging
import os
import shutil
import subprocess
import time
from pathlib import Path

from database.mongo import ping, _client

logger = logging.getLogger(__name__)

_AWE_HOME = Path.home() / ".awe" / "mongodb"
_DATA_DIR  = _AWE_HOME / "data"
_LOG_FILE  = _AWE_HOME / "mongod.log"
_PID_FILE  = _AWE_HOME / "mongod.pid"
_PORT      = 27017

_started_by_us: subprocess.Popen | None = None


def ensure_running() -> tuple[bool, str]:
    """
    Ensure mongod is up.  Returns (True, version_string) or (False, error).
    """
    global _started_by_us

    # Already running?
    ok, msg = ping()
    if ok:
        return True, msg

    # Find binary
    mongod_bin = _find_mongod()
    if not mongod_bin:
        return False, (
            "mongod not found. Install MongoDB: https://www.mongodb.com/try/download/community"
        )

    # Create dirs
    _DATA_DIR.mkdir(parents=True, exist_ok=True)

    logger.info("Starting mongod from %s", mongod_bin)
    try:
        proc = subprocess.Popen(
            [
                mongod_bin,
                "--dbpath", str(_DATA_DIR),
                "--logpath", str(_LOG_FILE),
                "--port",    str(_PORT),
                "--quiet",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        _started_by_us = proc
        _PID_FILE.write_text(str(proc.pid))
        atexit.register(shutdown)
    except OSError as exc:
        return False, f"Failed to start mongod: {exc}"

    # Wait up to 12 seconds for mongod to be ready
    for attempt in range(24):
        time.sleep(0.5)
        if proc.poll() is not None:
            # Process exited — read last log lines for diagnosis
            tail = ""
            try:
                tail = _LOG_FILE.read_text()[-600:]
            except Exception:
                pass
            return False, f"mongod exited (code {proc.returncode}). Log:\n{tail}"

        ok, msg = ping()
        if ok:
            logger.info("mongod ready after %.1fs", (attempt + 1) * 0.5)
            return True, msg

    return False, "mongod did not become ready within 12 seconds"


def shutdown():
    """Stop the mongod instance AWE started, if we started one."""
    global _started_by_us
    if _started_by_us is None:
        return
    proc = _started_by_us
    if proc.poll() is None:
        logger.info("Stopping mongod (pid %d)", proc.pid)
        try:
            # Prefer clean shutdown via mongo admin command
            try:
                c = _client()
                c.admin.command("shutdown", force=True)
            except Exception:
                pass
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
    _started_by_us = None
    try:
        _PID_FILE.unlink(missing_ok=True)
    except Exception:
        pass


def _find_mongod() -> str | None:
    # 1. PATH
    found = shutil.which("mongod")
    if found:
        return found
    # 2. Common install locations
    candidates = [
        "/usr/bin/mongod",
        "/usr/local/bin/mongod",
        "/opt/mongodb/bin/mongod",
        "/usr/local/mongodb/bin/mongod",
        str(Path.home() / ".local" / "bin" / "mongod"),
    ]
    for c in candidates:
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return None


def status() -> dict:
    """Return a status dict for display in the UI."""
    ok, msg = ping()
    running_by_us = _started_by_us is not None and _started_by_us.poll() is None
    return {
        "connected": ok,
        "message":   msg,
        "managed":   running_by_us,
        "pid":       _started_by_us.pid if running_by_us else None,
        "data_dir":  str(_DATA_DIR),
    }
