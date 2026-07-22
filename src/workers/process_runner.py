from __future__ import annotations

import logging
import subprocess
import sys
import threading
import uuid
from pathlib import Path

from PySide6.QtCore import QThread, Signal

from config.config import RUNDIR
from workers.protocol import WorkerMessage, encode_message

log = logging.getLogger(__name__)


class ProxyExtractorServiceRunner(QThread):
    ready = Signal()
    started_job = Signal(str)
    job_done = Signal(str, dict)
    job_error = Signal(str, str)
    worker_log = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("Proxy Extractor Service")
        self.process: subprocess.Popen | None = None
        self._write_lock = threading.Lock()
        self._stop_requested = False

    def run(self) -> None:
        cmd = [sys.executable, "-m", "workers.proxy_extractor_worker"]
        try:
            self.process = subprocess.Popen(
                cmd,
                cwd=str(Path(RUNDIR) / "src"),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            self.process.process_name = "proxyExtractorService"
            assert self.process.stdout is not None
            for line in self.process.stdout:
                self._handle_line(line.rstrip("\n"))
                if self._stop_requested:
                    break
            self.process.wait()
        except Exception as exc:
            log.exception("Proxy extractor service failed")
            self.job_error.emit("", str(exc))
        finally:
            self.process = None

    def start_extraction(
        self,
        *,
        project_dir: str,
        target: str,
        mongo_uri: str,
        scope: dict,
        batch_size: int = 100,
        batch_pause_ms: int = 15,
        max_request_body_scan_chars: int = 250_000,
        max_secret_scan_chars: int = 250_000,
    ) -> str:
        job_id = uuid.uuid4().hex
        self._send(
            "start_extract",
            job_id,
            project_dir=project_dir,
            target=target,
            mongo_uri=mongo_uri,
            scope=scope,
            batch_size=batch_size,
            batch_pause_ms=batch_pause_ms,
            max_request_body_scan_chars=max_request_body_scan_chars,
            max_secret_scan_chars=max_secret_scan_chars,
        )
        return job_id

    def shutdown(self) -> None:
        self._stop_requested = True
        try:
            self._send("shutdown")
        except Exception:
            self.stop()

    def stop(self) -> None:
        self._stop_requested = True
        proc = self.process
        if proc is not None and proc.poll() is None:
            try:
                proc.terminate()
            except Exception:
                pass

    def _send(self, message_type: str, job_id: str = "", **payload) -> None:
        proc = self.process
        if proc is None or proc.stdin is None or proc.poll() is not None:
            raise RuntimeError("proxy extractor service is not running")
        with self._write_lock:
            proc.stdin.write(encode_message(message_type, job_id, **payload))
            proc.stdin.flush()

    def _handle_line(self, line: str) -> None:
        if not line:
            return
        try:
            msg = WorkerMessage.from_json_line(line)
        except Exception:
            self.worker_log.emit(line)
            return

        if msg.type == "ready":
            self.ready.emit()
        elif msg.type == "started":
            self.started_job.emit(msg.job_id)
        elif msg.type == "done":
            self.job_done.emit(msg.job_id, msg.payload)
        elif msg.type == "error":
            self.job_error.emit(msg.job_id, str(msg.payload.get("error") or "worker error"))
        else:
            self.worker_log.emit(line)
