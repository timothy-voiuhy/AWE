from __future__ import annotations

import json
import secrets
import threading
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Callable

from .docker_service import DockerService
from .schemas import DockerOperation


class DockerOperationNotFound(LookupError):
    pass


class DockerOperationManager:
    def __init__(self, storage_path: Path | None = None, max_logs: int = 2000, max_operations: int = 1000):
        self._max_logs = max_logs
        self._max_operations = max_operations
        self._storage_path = storage_path
        self._items: dict[str, DockerOperation] = {}
        self._cancelled: set[str] = set()
        self._containers: dict[str, list[object]] = {}
        self._lock = threading.RLock()
        self._load()

    def _load(self) -> None:
        if not self._storage_path or not self._storage_path.is_file():
            return
        try:
            raw = json.loads(self._storage_path.read_text(encoding="utf-8"))
            rows = raw.get("operations", raw) if isinstance(raw, dict) else raw
            if not isinstance(rows, list):
                return
            for item in rows:
                operation = DockerOperation.model_validate(item)
                if operation.status in {"queued", "running", "cancelling"}:
                    operation = operation.model_copy(update={
                        "status": "failed",
                        "message": operation.message or "Operation interrupted by backend restart",
                    })
                    operation.logs = [*operation.logs, "Operation interrupted by backend restart"][-self._max_logs:]
                self._items[operation.id] = operation
        except (OSError, ValueError):
            return

    def _persist_locked(self) -> None:
        if not self._storage_path:
            return
        try:
            self._storage_path.parent.mkdir(parents=True, exist_ok=True)
            rows = list(self._items.values())[-self._max_operations:]
            temporary = self._storage_path.with_suffix(".tmp")
            temporary.write_text(json.dumps({"operations": [item.model_dump(mode="json") for item in rows]}, indent=2), encoding="utf-8")
            temporary.replace(self._storage_path)
        except OSError:
            return

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
                containers = self._containers.get(operation_id, [])
                for container in containers:
                    try: container.stop(timeout=5)
                    except Exception: pass
                self._persist_locked()
            return item.model_copy(deep=True)

    def start_images(self, operation: str, service: DockerService) -> DockerOperation:
        item = self._start(f"images.{operation}", lambda oid: self._run_images(oid, operation, service))
        try:
            import sys
            source = str(Path(__file__).resolve().parents[2] / "src")
            if source not in sys.path: sys.path.insert(0, source)
            from containers.tool_registry import TOOL_REGISTRY
            total = sum(1 for tool in TOOL_REGISTRY.values() if (operation == "setup" or (operation == "build") == bool(tool.dockerfile)))
            with self._lock:
                self._items[item.id].progress_total = total
                self._persist_locked()
        except Exception: pass
        return self.get(item.id)

    def start_tool(self, key: str, params: dict, output_dir: Path, service: DockerService,
                   on_complete: Callable[[list, Path], dict] | None = None) -> DockerOperation:
        return self._start(f"tool.{key}", lambda oid: self._run_tool(oid, key, params, output_dir, service, on_complete))

    def start_composite(
        self,
        key: str,
        stages: list[dict],
        params: dict,
        output_dir: Path,
        service: DockerService,
        on_complete: Callable[[list, Path], dict] | None = None,
    ) -> DockerOperation:
        item = self._start(f"composite.{key}", lambda oid: self._run_composite(oid, key, stages, params, output_dir, service, on_complete))
        with self._lock:
            self._items[item.id].progress_total = sum(len(stage.get("tool_keys", [])) for stage in stages)
            self._persist_locked()
        return self.get(item.id)

    def start_one_image(self, key: str, operation: str, service: DockerService) -> DockerOperation:
        return self._start(f"image.{operation}.{key}", lambda oid: self._run_one_image(oid, key, operation, service))

    def _start(self, kind: str, target) -> DockerOperation:
        oid = secrets.token_hex(12)
        item = DockerOperation(id=oid, kind=kind, status="queued")
        with self._lock:
            self._items[oid] = item
            self._persist_locked()
        threading.Thread(target=target, args=(oid,), daemon=True, name=f"awe-docker-{oid}").start()
        return self.get(oid)

    def _log(self, oid: str, line: str) -> None:
        with self._lock:
            item = self._items[oid]
            item.logs.append(str(line))
            item.logs = item.logs[-self._max_logs:]
            self._persist_locked()

    def _run_images(self, oid: str, operation: str, service: DockerService) -> None:
        self._running(oid)
        try:
            def progress(key, result):
                with self._lock:
                    item = self._items[oid]; item.progress_completed += 1
                    self._persist_locked()
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
            parsed, container_id = self._run_tool_sync(oid, key, params, output_dir, service)
            result = {"container_id": container_id, "output_dir": str(output_dir), "parsed_count": len(parsed)}
            if on_complete and parsed:
                try:
                    result.update(on_complete(parsed, output_dir) or {})
                except Exception as exc:
                    self._log(oid, f"Graph ingestion warning: {exc}")
                    result["ingestion_error"] = str(exc)
            self._finish(oid, result)
        except Exception as exc: self._fail(oid, exc)

    def _run_composite(self, oid: str, key: str, stages: list[dict], params: dict, output_dir: Path, service: DockerService,
                       on_complete: Callable[[list, Path], dict] | None = None) -> None:
        self._running(oid)
        try:
            output_dir.mkdir(parents=True, exist_ok=True)
            previous: list = []
            source_map: dict[str, set[str]] = {}
            for index, stage in enumerate(stages):
                if oid in self._cancelled:
                    return self._finish(oid, {"output_dir": str(output_dir)})
                name = stage.get("name") or f"Stage {index + 1}"
                tool_keys = [str(item) for item in stage.get("tool_keys", []) if str(item).strip()]
                self._log(oid, f"[{name}] Starting {len(tool_keys)} tool(s)")
                input_dir = None
                stage_params = {**params, **(stage.get("parameters") or {})}
                if stage.get("input_source") == "previous":
                    values = sorted({value for result in previous for value in self._result_values(result)})
                    if not values:
                        self._log(oid, f"[{name}] No previous values to tunnel; skipping stage")
                        previous = []
                        continue
                    input_dir = output_dir / "_stage_inputs" / f"stage_{index + 1}"
                    input_dir.mkdir(parents=True, exist_ok=True)
                    (input_dir / "input.txt").write_text("\n".join(values) + "\n", encoding="utf-8")
                    stage_params.setdefault("input_file", "/input/input.txt")
                    self._log(oid, f"[{name}] Tunneled {len(values)} value(s) through /input/input.txt")
                stage_results: list = []
                for tool_key in tool_keys:
                    if oid in self._cancelled:
                        return self._finish(oid, {"output_dir": str(output_dir)})
                    tool_dir = output_dir / f"stage_{index + 1}_{tool_key}"
                    parsed, _container_id = self._run_tool_sync(oid, tool_key, stage_params, tool_dir, service, input_dir, f"[{name}/{tool_key}] ")
                    self._attach_previous_sources(parsed, source_map)
                    stage_results.extend(parsed)
                    with self._lock:
                        self._items[oid].progress_completed += 1
                        self._persist_locked()
                previous = self._merge_results(stage_results)
                source_map = self._source_map(previous)
                self._log(oid, f"[{name}] Produced {len(previous)} deduped result(s)")
            result = {"output_dir": str(output_dir), "parsed_count": len(previous), "stages": len(stages)}
            if on_complete:
                try:
                    result.update(on_complete(previous, output_dir) or {})
                except Exception as exc:
                    self._log(oid, f"Graph ingestion warning: {exc}")
                    result["ingestion_error"] = str(exc)
            self._finish(oid, result)
        except Exception as exc: self._fail(oid, exc)

    def _run_tool_sync(self, oid: str, key: str, params: dict, output_dir: Path, service: DockerService,
                       input_dir: Path | None = None, prefix: str = "") -> tuple[list, str]:
        import sys
        source = str(Path(__file__).resolve().parents[2] / "src")
        if source not in sys.path: sys.path.insert(0, source)
        from containers.tool_registry import TOOL_REGISTRY
        tool = TOOL_REGISTRY.get(key)
        if not tool: raise KeyError(key)
        if not service._client().images.list(name=tool.image):
            self._log(oid, f"{prefix}Preparing image {tool.image}")
            service.one_tool_image_operation(key, "build" if tool.dockerfile else "pull")
        output_dir.mkdir(parents=True, exist_ok=True)
        command = tool.build_command(**params)
        self._log(oid, f"{prefix}Starting {tool.image}: {command}")
        environment = tool.build_environment(**params)
        container = service._client().containers.run(
            image=tool.image,
            command=command,
            name=tool.container_name(),
            volumes=tool.get_volumes(str(output_dir), str(input_dir) if input_dir else None),
            environment=environment or None,
            detach=True,
        )
        with self._lock: self._containers.setdefault(oid, []).append(container)
        try:
            for chunk in container.logs(stream=True, follow=True):
                self._log(oid, f"{prefix}{chunk.decode(errors='replace').rstrip()}")
            container.reload()
            code = container.attrs.get("State", {}).get("ExitCode", 0)
            if oid in self._cancelled:
                return [], container.short_id
            if code: raise RuntimeError(f"{key} container exited with code {code}")
            parsed: list = []
            try:
                from containers.parsers import PARSERS
                parser = PARSERS.get(key)
                if parser:
                    parsed = parser(str(output_dir)) or []
            except Exception as exc:
                self._log(oid, f"{prefix}Parser warning: {exc}")
            return parsed, container.short_id
        finally:
            with self._lock:
                containers = self._containers.get(oid, [])
                self._containers[oid] = [item for item in containers if item is not container]

    def _result_data(self, result) -> dict:
        return asdict(result) if is_dataclass(result) else (result if isinstance(result, dict) else {"value": str(result)})

    def _result_values(self, result) -> list[str]:
        data = self._result_data(result)
        values = [data.get("domain"), data.get("host"), data.get("url"), data.get("value"), data.get("name")]
        return [str(value).strip() for value in values if str(value or "").strip()]

    def _merge_results(self, results: list) -> list:
        merged: dict[str, object] = {}
        for result in results:
            key = str(getattr(result, "key", "") or next(iter(self._result_values(result)), "")).lower().rstrip("/")
            if not key:
                continue
            if key in merged and hasattr(merged[key], "merge"):
                merged[key].merge(result)
            else:
                merged[key] = result
        return list(merged.values())

    def _source_map(self, results: list) -> dict[str, set[str]]:
        mapping: dict[str, set[str]] = {}
        for result in results:
            data = self._result_data(result)
            sources = set(str(item) for item in data.get("sources", []) if item)
            for value in self._result_values(result):
                mapping.setdefault(value.lower().rstrip("/"), set()).update(sources)
        return mapping

    def _attach_previous_sources(self, results: list, source_map: dict[str, set[str]]) -> None:
        for result in results:
            values = [value.lower().rstrip("/") for value in self._result_values(result)]
            sources = set().union(*(source_map.get(value, set()) for value in values)) if values else set()
            for source in sources:
                if hasattr(result, "add_source"):
                    result.add_source(source)
                elif isinstance(result, dict):
                    result.setdefault("sources", [])
                    if source not in result["sources"]:
                        result["sources"].append(source)

    def _running(self, oid):
        with self._lock:
            self._items[oid].status = "running"
            self._persist_locked()

    def _finish(self, oid, result):
        with self._lock:
            item = self._items[oid]
            item.status = "cancelled" if oid in self._cancelled else "completed"
            item.result = result
            item.message = "Cancelled" if item.status == "cancelled" else "Completed"
            self._containers.pop(oid, None)
            self._persist_locked()

    def _fail(self, oid, exc):
        with self._lock:
            item = self._items[oid]; item.status = "failed"; item.message = str(exc)
            self._containers.pop(oid, None)
            self._persist_locked()
