from __future__ import annotations

import secrets
import threading
from pathlib import Path
from typing import Callable

from .docker_service import DockerService
from .schemas import DockerOperation


class DockerOperationNotFound(LookupError):
    pass


class DockerOperationManager:
    def __init__(self, max_logs: int = 2000):
        self._max_logs = max_logs
        self._items: dict[str, DockerOperation] = {}
        self._cancelled: set[str] = set()
        self._containers: dict[str, object] = {}
        self._lock = threading.RLock()

    def get(self, operation_id: str) -> DockerOperation:
        with self._lock:
            item = self._items.get(operation_id)
            if not item: raise DockerOperationNotFound(operation_id)
            return item.model_copy(deep=True)

    def cancel(self, operation_id: str) -> DockerOperation:
        with self._lock:
            item = self._items.get(operation_id)
            if not item: raise DockerOperationNotFound(operation_id)
            if item.status in ("queued", "running"):
                item.status = "cancelling"
                self._cancelled.add(operation_id)
                container = self._containers.get(operation_id)
                if container is not None:
                    try: container.stop(timeout=5)
                    except Exception: pass
            return item.model_copy(deep=True)

    def start_images(self, operation: str, service: DockerService) -> DockerOperation:
        item = self._start(f"images.{operation}", lambda oid: self._run_images(oid, operation, service))
        try:
            import sys
            source = str(Path(__file__).resolve().parents[2] / "src")
            if source not in sys.path: sys.path.insert(0, source)
            from containers.tool_registry import TOOL_REGISTRY
            total = sum(1 for tool in TOOL_REGISTRY.values() if (operation == "setup" or (operation == "build") == bool(tool.dockerfile)))
            with self._lock: self._items[item.id].progress_total = total
        except Exception: pass
        return self.get(item.id)

    def start_tool(self, key: str, params: dict, output_dir: Path, service: DockerService,
                   on_complete: Callable[[list, Path], dict] | None = None) -> DockerOperation:
        return self._start(f"tool.{key}", lambda oid: self._run_tool(oid, key, params, output_dir, service, on_complete))

    def start_one_image(self, key: str, operation: str, service: DockerService) -> DockerOperation:
        return self._start(f"image.{operation}.{key}", lambda oid: self._run_one_image(oid, key, operation, service))

    def _start(self, kind: str, target) -> DockerOperation:
        oid = secrets.token_hex(12)
        item = DockerOperation(id=oid, kind=kind, status="queued")
        with self._lock: self._items[oid] = item
        threading.Thread(target=target, args=(oid,), daemon=True, name=f"awe-docker-{oid}").start()
        return self.get(oid)

    def _log(self, oid: str, line: str) -> None:
        with self._lock:
            item = self._items[oid]
            item.logs.append(str(line))
            item.logs = item.logs[-self._max_logs:]

    def _run_images(self, oid: str, operation: str, service: DockerService) -> None:
        self._running(oid)
        try:
            def progress(key, result):
                with self._lock:
                    item = self._items[oid]; item.progress_completed += 1
                self._log(oid, f"{'OK' if result['ok'] else 'FAILED'} {key}: {result.get('error', result['image'])}")
            result = service.tool_image_operation(operation, progress, lambda: oid in self._cancelled, lambda line: self._log(oid, line))
            self._finish(oid, result)
        except Exception as exc: self._fail(oid, exc)

    def _run_one_image(self, oid: str, key: str, operation: str, service: DockerService) -> None:
        self._running(oid)
        try:
            self._log(oid, f"{operation.title()}ing image for {key}…")
            result = service.one_tool_image_operation(key, operation, lambda line: self._log(oid, line))
            self._log(oid, f"Finished {result['image']}")
            self._finish(oid, result)
        except Exception as exc: self._log(oid, f"ERROR: {exc}"); self._fail(oid, exc)

    def _run_tool(self, oid: str, key: str, params: dict, output_dir: Path, service: DockerService,
                  on_complete: Callable[[list, Path], dict] | None = None) -> None:
        self._running(oid)
        try:
            import sys
            source = str(Path(__file__).resolve().parents[2] / "src")
            if source not in sys.path: sys.path.insert(0, source)
            from containers.tool_registry import TOOL_REGISTRY
            tool = TOOL_REGISTRY.get(key)
            if not tool: raise KeyError(key)
            if not service._client().images.list(name=tool.image):
                self._log(oid, f"Preparing image {tool.image}")
                service.one_tool_image_operation(key, "build" if tool.dockerfile else "pull")
            output_dir.mkdir(parents=True, exist_ok=True)
            command = tool.build_command(**params)
            self._log(oid, f"Starting {tool.image}: {command}")
            environment = tool.build_environment(**params)
            container = service._client().containers.run(
                image=tool.image,
                command=command,
                name=tool.container_name(),
                volumes=tool.get_volumes(str(output_dir)),
                environment=environment or None,
                detach=True,
            )
            with self._lock: self._containers[oid] = container
            for chunk in container.logs(stream=True, follow=True):
                self._log(oid, chunk.decode(errors="replace").rstrip())
            container.reload()
            code = container.attrs.get("State", {}).get("ExitCode", 0)
            if oid in self._cancelled: return self._finish(oid, {"container_id": container.short_id, "output_dir": str(output_dir)})
            if code: raise RuntimeError(f"Container exited with code {code}")
            parsed: list = []
            try:
                from containers.parsers import PARSERS
                parser = PARSERS.get(key)
                if parser:
                    parsed = parser(str(output_dir)) or []
            except Exception as exc:
                self._log(oid, f"Parser warning: {exc}")
            result = {"container_id": container.short_id, "output_dir": str(output_dir), "parsed_count": len(parsed)}
            if on_complete and parsed:
                try:
                    result.update(on_complete(parsed, output_dir) or {})
                except Exception as exc:
                    self._log(oid, f"Graph ingestion warning: {exc}")
                    result["ingestion_error"] = str(exc)
            self._finish(oid, result)
        except Exception as exc: self._fail(oid, exc)

    def _running(self, oid):
        with self._lock: self._items[oid].status = "running"

    def _finish(self, oid, result):
        with self._lock:
            item = self._items[oid]
            item.status = "cancelled" if oid in self._cancelled else "completed"
            item.result = result
            item.message = "Cancelled" if item.status == "cancelled" else "Completed"
            self._containers.pop(oid, None)

    def _fail(self, oid, exc):
        with self._lock:
            item = self._items[oid]; item.status = "failed"; item.message = str(exc)
            self._containers.pop(oid, None)
