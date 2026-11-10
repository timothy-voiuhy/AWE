from __future__ import annotations

import json
import hashlib
import os
import secrets
import shutil
import threading
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Callable

import docker

from .docker_service import DockerService
from .schemas import DockerOperation


class DockerOperationNotFound(LookupError):
    pass


class DockerOperationManager:
    def __init__(self, storage_path: Path | None = None, max_logs: int = 2000, max_operations: int = 1000,
                 workspace_dir: Path | None = None, docker_workspace_dir: Path | None = None):
        self._max_logs = max_logs
        self._max_operations = max_operations
        self._storage_path = storage_path
        self._workspace_dir = workspace_dir.resolve() if workspace_dir else None
        self._docker_workspace_dir = docker_workspace_dir
        self._items: dict[str, DockerOperation] = {}
        self._cancelled: set[str] = set()
        self._containers: dict[str, list[object]] = {}
        self._lock = threading.RLock()
        self._load()

    def _docker_host_path(self, path: Path) -> Path:
        if self._workspace_dir and self._docker_workspace_dir:
            try:
                return self._docker_workspace_dir / path.resolve().relative_to(self._workspace_dir)
            except ValueError:
                pass
        return path

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

    def recent_tool_runs(self, limit: int = 30) -> list[DockerOperation]:
        with self._lock:
            runs = [item for item in reversed(list(self._items.values())) if item.kind.startswith(("tool.", "composite."))]
            return [item.model_copy(deep=True, update={"logs": []}) for item in runs[:limit]]

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

    def cleanup_interrupted_container(self, operation_id: str, service: DockerService) -> None:
        """Stop a container left behind when its worker disappeared on restart."""
        operation = self.get(operation_id)
        container_id = operation.result.get("active_container_id")
        client = service._client()
        candidates = client.containers.list(all=True, filters={"label": f"awe.operation_id={operation_id}"})
        if container_id:
            try:
                candidates.append(client.containers.get(container_id))
            except docker.errors.NotFound:
                pass
        seen: set[str] = set()
        for container in candidates:
            if container.id in seen:
                continue
            seen.add(container.id)
            if container.labels.get("awe.operation_id") != operation_id:
                raise RuntimeError("Interrupted container identity does not match the transform operation")
            container.reload()
            if container.status in {"running", "restarting", "paused"}:
                container.stop(timeout=5)
            container.remove(force=True)

    @staticmethod
    def _checkpoint_path(output_dir: Path) -> Path:
        return output_dir / ".awe-transform-checkpoint.json"

    @staticmethod
    def _has_completed_output(output_dir: Path) -> bool:
        return output_dir.is_dir() and any(
            path.is_file()
            and path.name not in {".awe-transform-checkpoint.json", ".awe-tool-complete"}
            and not {"_seed_inputs", "_stage_inputs"}.intersection(path.relative_to(output_dir).parts)
            for path in output_dir.rglob("*")
        )

    @staticmethod
    def _seed_input_dir(output_dir: Path, values: list[str]) -> Path | None:
        cleaned = list(dict.fromkeys(str(value).strip() for value in values if str(value).strip()))
        if not cleaned:
            return None
        input_dir = output_dir / "_seed_inputs"
        input_dir.mkdir(parents=True, exist_ok=True)
        (input_dir / "input.txt").write_text("\n".join(cleaned) + "\n", encoding="utf-8")
        return input_dir

    @staticmethod
    def _checkpoint_signature(key: str, stages: list[dict], params: dict) -> str:
        payload = json.dumps({"key": key, "stages": stages, "params": params}, sort_keys=True, default=str)
        return hashlib.sha256(payload.encode()).hexdigest()

    def _completed_units(self, output_dir: Path, signature: str) -> set[str]:
        path = self._checkpoint_path(output_dir)
        if not path.exists():
            return set()
        checkpoint = json.loads(path.read_text(encoding="utf-8"))
        if checkpoint.get("signature") != signature:
            raise ValueError("Transform definition or parameters changed; this run cannot resume from its checkpoint")
        return set(checkpoint.get("completed", []))

    def validate_checkpoint(self, output_dir: Path, key: str, stages: list[dict], params: dict) -> None:
        self._completed_units(output_dir, self._checkpoint_signature(key, stages, params))

    def _save_checkpoint(self, output_dir: Path, signature: str, completed: set[str]) -> None:
        path = self._checkpoint_path(output_dir)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps({"signature": signature, "completed": sorted(completed)}), encoding="utf-8")
        temporary.replace(path)

    @staticmethod
    def _parse_output(key: str, output_dir: Path) -> list:
        import sys
        source = str(Path(__file__).resolve().parents[2] / "src")
        if source not in sys.path: sys.path.insert(0, source)
        from containers.parsers import PARSERS
        parser = PARSERS.get(key)
        return (parser(str(output_dir)) or []) if parser else []

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
                   on_complete: Callable[[list, Path], dict] | None = None, *, resume: bool = False,
                   prior_logs: list[str] | None = None, seed_values: list[str] | None = None) -> DockerOperation:
        return self._start(f"tool.{key}", lambda oid: self._run_tool(oid, key, params, output_dir, service, on_complete, resume, seed_values or []), prior_logs)

    def start_composite(
        self,
        key: str,
        stages: list[dict],
        params: dict,
        output_dir: Path,
        service: DockerService,
        on_complete: Callable[[list, Path], dict] | None = None,
        *, resume: bool = False,
        prior_logs: list[str] | None = None,
        seed_values: list[str] | None = None,
    ) -> DockerOperation:
        item = self._start(f"composite.{key}", lambda oid: self._run_composite(oid, key, stages, params, output_dir, service, on_complete, resume, seed_values or []), prior_logs)
        with self._lock:
            self._items[item.id].progress_total = sum(len(stage.get("tool_keys", [])) for stage in stages)
            self._persist_locked()
        return self.get(item.id)

    def start_one_image(self, key: str, operation: str, service: DockerService) -> DockerOperation:
        return self._start(f"image.{operation}.{key}", lambda oid: self._run_one_image(oid, key, operation, service))

    def _start(self, kind: str, target, prior_logs: list[str] | None = None) -> DockerOperation:
        oid = secrets.token_hex(12)
        item = DockerOperation(id=oid, kind=kind, status="queued", logs=[*(prior_logs or [])[-self._max_logs + 1:], "Resuming transform run"] if prior_logs else [])
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
                  on_complete: Callable[[list, Path], dict] | None = None, resume: bool = False,
                  seed_values: list[str] | None = None) -> None:
        self._running(oid)
        try:
            signature = self._checkpoint_signature(key, [], params)
            completed = self._completed_units(output_dir, signature) if resume else set()
            if "tool" in completed:
                if self._has_completed_output(output_dir):
                    self._log(oid, f"Resuming {key} from completed tool output")
                    parsed, container_id = self._parse_output(key, output_dir), ""
                else:
                    self._log(oid, f"Completed output for {key} is missing; rerunning tool")
                    completed.remove("tool")
            else:
                parsed, container_id = [], ""
            if "tool" not in completed:
                if resume and output_dir.exists():
                    shutil.rmtree(output_dir)
                input_dir = self._seed_input_dir(output_dir, seed_values or [])
                tool_params = {**params, **({"input_file": "/input/input.txt"} if input_dir else {})}
                if input_dir:
                    self._log(oid, f"Using {len(seed_values or [])} selected graph output value(s) from /input/input.txt")
                parsed, container_id = self._run_tool_sync(oid, key, tool_params, output_dir, service, input_dir)
                if oid in self._cancelled:
                    return self._finish(oid, {"output_dir": str(output_dir)})
                completed.add("tool")
                self._save_checkpoint(output_dir, signature, completed)
            result = {"container_id": container_id, "output_dir": str(output_dir), "parsed_count": len(parsed)}
            if on_complete:
                result.update(on_complete(parsed, output_dir) or {})
            self._finish(oid, result)
        except Exception as exc: self._fail(oid, exc)

    def _run_composite(self, oid: str, key: str, stages: list[dict], params: dict, output_dir: Path, service: DockerService,
                       on_complete: Callable[[list, Path], dict] | None = None, resume: bool = False,
                       seed_values: list[str] | None = None) -> None:
        self._running(oid)
        try:
            output_dir.mkdir(parents=True, exist_ok=True)
            signature = self._checkpoint_signature(key, stages, params)
            completed = self._completed_units(output_dir, signature) if resume else set()
            with self._lock:
                self._items[oid].progress_completed = len(completed)
                self._persist_locked()
            seed_input_dir = self._seed_input_dir(output_dir, seed_values or [])
            if seed_input_dir:
                self._log(oid, f"Prepared {len(seed_values or [])} selected graph output value(s) as the seed input list")
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
                elif seed_input_dir:
                    input_dir = seed_input_dir
                    stage_params.setdefault("input_file", "/input/input.txt")
                    self._log(oid, f"[{name}] Using selected graph output through /input/input.txt")
                stage_results: list = []
                for tool_index, tool_key in enumerate(tool_keys):
                    if oid in self._cancelled:
                        return self._finish(oid, {"output_dir": str(output_dir)})
                    unit = f"{index}:{tool_index}:{tool_key}"
                    tool_dir = output_dir / f"stage_{index + 1}_{tool_key}"
                    if unit in completed and not self._has_completed_output(tool_dir):
                        self._log(oid, f"[{name}/{tool_key}] Completed output is missing; rerunning tool")
                        completed.remove(unit)
                    if unit not in completed and resume:
                        with self._lock:
                            self._items[oid].progress_completed = len(completed)
                            self._persist_locked()
                    if unit in completed:
                        self._log(oid, f"[{name}/{tool_key}] Reusing completed output")
                        parsed = self._parse_output(tool_key, tool_dir)
                    else:
                        if resume and tool_dir.exists():
                            shutil.rmtree(tool_dir)
                        parsed, _container_id = self._run_tool_sync(oid, tool_key, stage_params, tool_dir, service, input_dir, f"[{name}/{tool_key}] ")
                        if oid in self._cancelled:
                            return self._finish(oid, {"output_dir": str(output_dir)})
                        completed.add(unit)
                        self._save_checkpoint(output_dir, signature, completed)
                        with self._lock:
                            self._items[oid].progress_completed += 1
                            self._persist_locked()
                    self._attach_previous_sources(parsed, source_map)
                    stage_results.extend(parsed)
                previous = self._merge_results(stage_results)
                source_map = self._source_map(previous)
                self._log(oid, f"[{name}] Produced {len(previous)} deduped result(s)")
            result = {"output_dir": str(output_dir), "parsed_count": len(previous), "stages": len(stages)}
            if on_complete:
                result.update(on_complete(previous, output_dir) or {})
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
        if tool.output_owner:
            os.chown(output_dir, *tool.output_owner)
        command = tool.build_command(**params)
        self._log(oid, f"{prefix}Starting {tool.image}: {command}")
        environment = tool.build_environment(**params)
        volumes = {
            str(self._docker_host_path(Path(source))): mount
            for source, mount in tool.get_volumes(str(output_dir), str(input_dir) if input_dir else None).items()
        }
        container = service._client().containers.run(
            image=tool.image,
            command=["-c", command],
            entrypoint=["sh"],
            name=tool.container_name(),
            volumes=volumes,
            environment=environment or None,
            labels={"awe.operation_id": oid},
            detach=True,
        )
        with self._lock:
            self._containers.setdefault(oid, []).append(container)
            self._items[oid].result["active_container_id"] = container.id
            self._persist_locked()
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
            try:
                container.remove(force=True)
                with self._lock:
                    self._items[oid].result.pop("active_container_id", None)
                    self._persist_locked()
            except Exception as exc:
                self._log(oid, f"{prefix}Could not remove finished container: {exc}")

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
