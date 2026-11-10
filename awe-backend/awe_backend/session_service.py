"""Sessions outlive browser attachments; transport adapters own their lifecycle."""
from __future__ import annotations

import asyncio
import base64
import io
import json
import secrets
import tarfile
import threading
import time
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

from .config import Settings, get_settings
from .run_outputs import RunOutputs


def check_origin(websocket) -> bool:
    origin = websocket.headers.get("origin", "")
    return bool(origin and urlsplit(origin).netloc == websocket.headers.get("host"))


class SessionService:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.rows: dict[str, dict] = {}
        self.transports: dict[str, object] = {}
        self.writers: dict[str, str] = {}
        self.activity: dict[str, float] = {}
        self.tasks: dict[str, asyncio.Task] = {}
        self.lock = threading.RLock()
        self.loop = None
        self._loaded = False

    def _save(self, row):
        project_dir = Path(row["project_dir"])
        with self.lock:
            path = project_dir / ".awe-sessions.json"
            rows = [r for r in self.rows.values() if r["project_dir"] == str(project_dir)]
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(rows))
            tmp.replace(path)

    def public(self, row):
        return {k: v for k, v in row.items() if k not in {"project_dir", "output_dir", "offset"}}

    def get(self, project_id, sid):
        row = self.rows.get(sid)
        if row is None or row["project_id"] != project_id:
            raise KeyError(sid)
        return row

    def _new(self, project_id, project_dir, kind, run_id="", **values):
        with self.lock:
            live = sum(r["project_id"] == project_id and r["status"] in {"starting", "listening", "active"} for r in self.rows.values())
            if live >= self.settings.session_max_per_project:
                raise ValueError("Maximum live sessions reached for this project")
            sid = secrets.token_hex(12)
            row = {"id": sid, "project_id": project_id, "project_dir": str(project_dir), "kind": kind, "run_id": run_id or f"session-{sid}", "status": "starting", "created_at": time.time(), "offset": 0, "capabilities": ["input", "output", "terminate"], **values}
            self.rows[sid] = row
            self.activity[sid] = time.monotonic()
            record = RunOutputs(project_dir, row["run_id"])
            try:
                record.metadata()
            except KeyError:
                record.update(kind=f"session.{kind}", status="running", output_dir=str(record.root / "files"))
            record.update(session_id=sid, session_ids=list(dict.fromkeys([*record.metadata().get("session_ids", []), sid])))
            self._save(row)
            return row

    async def start(self):
        self.loop = asyncio.get_running_loop()
        if self._loaded:
            return
        self._loaded = True
        for path in self.settings.workspace_dir.glob("*/.awe-sessions.json"):
            try:
                rows = json.loads(path.read_text())
            except (OSError, ValueError):
                continue
            for row in rows:
                self.rows[row["id"]] = row
                self.activity[row["id"]] = time.monotonic()
                if row["status"] in {"starting", "listening", "active"}:
                    if row["kind"] == "container":
                        self.tasks[row["id"]] = asyncio.create_task(self._watch_container(row))
                    else:
                        self._ended(row, "disconnected", "Connection interrupted by backend restart")
        self.tasks["idle"] = asyncio.create_task(self._idle())

    def create_container(self, project_dir: Path, run_id: str, container, output_dir: Path, tool) -> dict:
        # Called by a Docker worker thread. The supervisor is the container's
        # main process, so reattachment never launches the command a second time.
        project_id = json.loads((project_dir / ".awe-project.json").read_text())["id"]
        row = self._new(project_id, project_dir, "container", run_id, container_id=container.id, output_dir=str(output_dir), capabilities=["input", "output", "resize", "terminate"], label=tool.display_name)
        binary = self.settings.pty_runner_path.read_bytes()
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w") as tar:
            info = tarfile.TarInfo("awe-pty-runner"); info.mode = 0o755; info.size = len(binary)
            tar.addfile(info, io.BytesIO(binary))
        try:
            container.put_archive("/tmp", archive.getvalue())
            container.start()
            row["status"] = "active"
            self._save(row)
            if self.loop:
                self.loop.call_soon_threadsafe(lambda: self.tasks.update({row["id"]: asyncio.create_task(self._watch_container(row))}))
            return row
        except Exception:
            self._ended(row, "failed", "Interactive container failed to start")
            container.remove(force=True)
            raise

    async def create(self, project_id, project_dir, payload):
        await self.start()
        if payload.run_id:
            RunOutputs(project_dir, payload.run_id).metadata()
        kind = payload.kind
        row = self._new(project_id, project_dir, kind, payload.run_id, host=payload.host, port=payload.port, label=payload.label or kind, expected_peer=payload.expected_peer)
        sid = row["id"]
        try:
            if kind == "ssh":
                import asyncssh
                kwargs = {"host": payload.host, "port": payload.port or 22, "username": payload.username}
                if payload.trust_host_key:
                    kwargs["known_hosts"] = None
                if payload.private_key:
                    kwargs["client_keys"] = [asyncssh.import_private_key(payload.private_key, passphrase=payload.key_passphrase or None)]
                else:
                    kwargs["password"] = payload.password
                connection = await asyncio.wait_for(asyncssh.connect(**kwargs), 30)
                process = await connection.create_process(term_type="xterm-256color", term_size=(120, 32), encoding=None)
                self.transports[sid] = (connection, process)
                row["capabilities"].append("resize")
                row["status"] = "active"
                self.tasks[sid] = asyncio.create_task(self._read_network(row, process.stdout, "ssh"))
            elif kind == "tcp":
                reader, writer = await asyncio.wait_for(asyncio.open_connection(payload.host, payload.port), 30)
                self.transports[sid] = writer
                row["status"] = "active"
                self.tasks[sid] = asyncio.create_task(self._read_network(row, reader, "tcp"))
            elif kind == "listener":
                ports = [payload.port] if payload.port else range(self.settings.callback_port_start, self.settings.callback_port_end + 1)
                server = None
                for port in ports:
                    if not self.settings.callback_port_start <= port <= self.settings.callback_port_end:
                        raise ValueError("Listener port is outside the configured callback range")
                    try:
                        server = await asyncio.start_server(lambda r, w: self._accept(row, r, w), self.settings.callback_bind_host, port)
                        row["port"] = port
                        break
                    except OSError:
                        continue
                if server is None:
                    raise ValueError("No callback port is available")
                self.transports[sid] = server
                row.update(status="listening", host=self.settings.callback_advertise_host)
            self._save(row)
            return self.public(row)
        except Exception as exc:
            self._ended(row, "failed", str(exc))
            raise

    async def _accept(self, row, reader, writer):
        peer = writer.get_extra_info("peername")[0]
        if row["status"] != "listening" or (row.get("expected_peer") and row["expected_peer"] != peer):
            writer.close(); await writer.wait_closed(); return
        server = self.transports[row["id"]]
        row.update(status="active", peer=peer)
        server.close()
        self.transports[row["id"]] = writer
        self._save(row)
        self.tasks[row["id"]] = asyncio.create_task(self._read_network(row, reader, "tcp"))

    async def _read_network(self, row, reader, kind):
        record = RunOutputs(Path(row["project_dir"]), row["run_id"])
        try:
            while chunk := await reader.read(4096):
                self.activity[row["id"]] = time.monotonic()
                record.append(chunk.decode("utf-8", errors="replace") if isinstance(chunk, bytes) else chunk, "terminal")
            self._ended(row, "exited" if kind == "ssh" else "disconnected", "Connection ended")
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self._ended(row, "disconnected", str(exc))
        finally:
            transport = self.transports.pop(row["id"], None)
            if isinstance(transport, tuple):
                transport[1].close(); transport[0].close()
            elif transport:
                transport.close()

    def _ended(self, row, status, message):
        if row["status"] == "terminated":
            return
        row.update(status=status, message=message)
        self._save(row)
        record = RunOutputs(Path(row["project_dir"]), row["run_id"])
        record.update(session_status=status)
        if row["run_id"].startswith("session-"):
            record.update(status="completed" if status == "exited" else status)
        record.append(message, "system")

    async def _watch_container(self, row):
        from .docker_service import DockerService
        try:
            container = await asyncio.to_thread(DockerService()._client().containers.get, row["container_id"])
            if container.labels.get("awe.session") != "true":
                raise ValueError("Container does not belong to session service")
            record = RunOutputs(Path(row["project_dir"]), row["run_id"])
            composite = record.metadata().get("kind", "").startswith("composite.")
            if not composite:
                record.update(status="running")
            while True:
                path = Path(row["output_dir"]) / ".awe-terminal.jsonl"
                if path.exists():
                    with path.open("rb") as file:
                        file.seek(row.get("offset", 0))
                        while line := file.readline():
                            if not line.endswith(b"\n"):
                                break
                            event = json.loads(line)
                            record.append(base64.b64decode(event["data"]).decode("utf-8", errors="replace"), "terminal")
                            row["offset"] = file.tell()
                        self._save(row)
                await asyncio.to_thread(container.reload)
                if container.status not in {"running", "restarting"}:
                    state = Path(row["output_dir"]) / ".awe-terminal-exit.json"
                    info = json.loads(state.read_text()) if state.exists() else {"exit_code": container.attrs.get("State", {}).get("ExitCode")}
                    values = {"exit_code": info.get("exit_code"), "logs_truncated": info.get("transcript_truncated", False)}
                    if not composite:
                        values["status"] = "completed" if info.get("exit_code") == 0 else "failed"
                    record.update(**values)
                    self._ended(row, "exited", "Tool process exited")
                    record.collect()
                    return
                await asyncio.sleep(.3)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self._ended(row, "disconnected", f"Container unavailable: {exc}")

    async def control(self, project_id, sid, owner, message):
        row = self.get(project_id, sid)
        kind = message.get("type")
        if kind == "take_control":
            self.writers[sid] = owner
            return
        if self.writers.get(sid) != owner:
            raise PermissionError("This connection is read-only; take control to send input")
        self.activity[sid] = time.monotonic()
        if row["status"] != "active":
            raise ValueError("Session is not active")
        if kind == "resize" and "resize" not in row["capabilities"]:
            return
        if row["kind"] == "container":
            from .docker_service import DockerService
            data = {"type": kind}
            if kind == "input":
                data["data"] = base64.b64encode(str(message.get("data", ""))[:10000].encode()).decode()
            elif kind == "resize":
                data.update(cols=max(20, min(300, int(message.get("cols", 120)))), rows=max(5, min(100, int(message.get("rows", 32)))))
            container = await asyncio.to_thread(DockerService()._client().containers.get, row["container_id"])
            await asyncio.to_thread(container.exec_run, ["/tmp/awe-pty-runner", "control", json.dumps(data)])
        elif row["kind"] == "ssh":
            _, process = self.transports[sid]
            if kind == "input":
                process.stdin.write(str(message.get("data", ""))[:10000].encode())
            elif kind == "resize":
                process.change_terminal_size(max(20,min(300,int(message.get("cols",120)))), max(5,min(100,int(message.get("rows",32)))))
        elif kind == "input":
            self.transports[sid].write(str(message.get("data", ""))[:10000].encode())
            await self.transports[sid].drain()

    async def terminate(self, project_id, sid):
        row = self.get(project_id, sid)
        if row["status"] == "terminated":
            return self.public(row)
        self._ended(row, "terminated", "Session terminated by researcher")
        if row["kind"] == "container":
            RunOutputs(Path(row["project_dir"]), row["run_id"]).update(status="cancelled")
        task = self.tasks.pop(sid, None)
        if task:
            task.cancel()
        if row["kind"] == "container":
            from .docker_service import DockerService
            try:
                container = await asyncio.to_thread(DockerService()._client().containers.get, row["container_id"])
                await asyncio.to_thread(container.stop, timeout=3)
                await asyncio.to_thread(container.remove, force=True)
            except Exception:
                pass
        transport = self.transports.pop(sid, None)
        if isinstance(transport, tuple):
            transport[1].close(); transport[0].close()
        elif isinstance(transport, asyncio.Server):
            transport.close(); await transport.wait_closed()
        elif transport:
            transport.close()
        self._ended(row, "terminated", "Session terminated by researcher")
        return self.public(row)

    async def _idle(self):
        while True:
            for sid, row in list(self.rows.items()):
                if row["kind"] != "container" and row["status"] in {"active", "listening"} and time.monotonic() - self.activity.get(sid, time.monotonic()) > self.settings.session_idle_seconds:
                    await self.terminate(row["project_id"], sid)
            await asyncio.sleep(5)

    async def shutdown(self):
        for task in self.tasks.values():
            task.cancel()
        await asyncio.gather(*self.tasks.values(), return_exceptions=True)
        for transport in self.transports.values():
            if isinstance(transport, tuple):
                transport[1].close(); transport[0].close()
            else:
                transport.close()
        self.tasks.clear(); self.transports.clear(); self._loaded = False


@lru_cache
def session_service() -> SessionService:
    return SessionService(get_settings())
