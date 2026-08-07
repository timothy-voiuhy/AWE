from __future__ import annotations

import docker

from .schemas import DockerContainer


class DockerService:
    SERVICE_CONTAINERS = frozenset({"awe_mongodb"})
    def _client(self): return docker.from_env()

    def list(self) -> list[DockerContainer]:
        result = []
        for container in self._client().containers.list(all=True, filters={"name": "awe_"}):
            tags = container.image.tags
            result.append(DockerContainer(id=container.short_id, name=container.name, image=tags[0] if tags else container.image.short_id, status=container.status, created=container.attrs.get("State", {}).get("StartedAt", container.attrs.get("Created", "")), is_service=container.name in self.SERVICE_CONTAINERS))
        return result

    def stop(self, container_id: str) -> None:
        container = self._client().containers.get(container_id)
        if not container.name.startswith("awe_"):
            raise PermissionError("Only AWE containers can be managed")
        container.stop(timeout=5)

    def start(self, container_id: str) -> None:
        container = self._client().containers.get(container_id)
        if not container.name.startswith("awe_"):
            raise PermissionError("Only AWE containers can be managed")
        if container.name not in self.SERVICE_CONTAINERS:
            raise PermissionError("Only AWE service containers can be restarted")
        container.start()

    def remove(self, container_id: str) -> None:
        container = self._client().containers.get(container_id)
        if not container.name.startswith("awe_"):
            raise PermissionError("Only AWE containers can be managed")
        if container.name in self.SERVICE_CONTAINERS:
            raise PermissionError("Service containers cannot be removed")
        container.remove(force=True)

    def images(self, managed_tags: set[str] | None = None) -> list[dict]:
        result = []
        for image in self._client().images.list():
            tags = image.tags or ["<none>:<none>"]
            if managed_tags is not None and not (set(tags) & managed_tags): continue
            result.append({"id": image.short_id, "tags": tags, "size_mb": round(image.attrs.get("Size", 0) / 1048576, 1)})
        return result

    def image_exists(self, image: str) -> bool:
        try:
            self._client().images.get(image)
            return True
        except docker.errors.ImageNotFound:
            return False

    def tool_image_operation(self, operation: str, progress=None, cancelled=None, log=None) -> dict:
        import sys
        from pathlib import Path
        source = str(Path(__file__).resolve().parents[2] / "src")
        if source not in sys.path: sys.path.insert(0, source)
        from containers.tool_registry import TOOL_REGISTRY
        results = []
        for key, tool in TOOL_REGISTRY.items():
            if cancelled and cancelled(): break
            if operation == "build" and not tool.dockerfile: continue
            if operation == "pull" and tool.dockerfile: continue
            if self.image_exists(tool.image):
                continue
            try:
                if operation in ("pull", "setup") and not tool.dockerfile:
                    self.pull_image(tool.image, (lambda line, k=key: log(f"[{k}] {line}")) if log else None)
                elif operation in ("build", "setup") and tool.dockerfile:
                    self.build_image_path(tool.dockerfile, tool.image, (lambda line, k=key: log(f"[{k}] {line}")) if log else None)
                results.append({"key": key, "image": tool.image, "ok": True})
            except Exception as exc: results.append({"key": key, "image": tool.image, "ok": False, "error": str(exc)})
            if progress: progress(key, results[-1])
        return {"operation": operation, "results": results}

    def one_tool_image_operation(self, key: str, operation: str, log=None) -> dict:
        import sys
        from pathlib import Path
        source = str(Path(__file__).resolve().parents[2] / "src")
        if source not in sys.path: sys.path.insert(0, source)
        from containers.tool_registry import TOOL_REGISTRY
        tool = TOOL_REGISTRY.get(key)
        if not tool: raise KeyError(key)
        if operation == "pull": self.pull_image(tool.image, log)
        elif operation == "build":
            if not tool.dockerfile: raise ValueError("Tool has no Dockerfile")
            self.build_image_path(tool.dockerfile, tool.image, log)
        else: raise ValueError("Invalid operation")
        return {"key": key, "image": tool.image, "ok": True}

    def remove_image(self, image: str) -> None: self._client().images.remove(image, force=False)

    def pull_image(self, image: str, progress=None) -> dict:
        client = self._client()
        if progress:
            for item in client.api.pull(image, stream=True, decode=True):
                status = item.get("status", "")
                detail = item.get("progress", "")
                if status: progress(f"{status}{' ' + detail if detail else ''}")
            pulled = client.images.get(image)
        else:
            pulled = client.images.pull(image)
        return {"id": pulled.short_id, "tags": pulled.tags or [image]}

    def build_image(self, dockerfile: str, tag: str) -> dict:
        import io, tarfile
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w") as archive:
            data = dockerfile.encode()
            info = tarfile.TarInfo("Dockerfile"); info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        stream.seek(0)
        image, logs = self._client().images.build(fileobj=stream, custom_context=True, dockerfile="Dockerfile", tag=tag, rm=True)
        return {"id": image.short_id, "tags": image.tags, "logs": [x.get("stream", "").strip() for x in logs if x.get("stream")]}

    def build_image_path(self, dockerfile_path: str, tag: str, progress=None) -> dict:
        from pathlib import Path
        path = Path(dockerfile_path)
        client = self._client()
        if progress:
            output = []
            for item in client.api.build(path=str(path.parent), dockerfile=path.name, tag=tag, rm=True, decode=True):
                line = item.get("stream", "").strip()
                if line: output.append(line); progress(line)
                if item.get("error"): raise RuntimeError(item["error"])
            image = client.images.get(tag)
            return {"id": image.short_id, "tags": image.tags, "logs": output}
        image, logs = client.images.build(path=str(path.parent), dockerfile=path.name, tag=tag, rm=True)
        return {"id": image.short_id, "tags": image.tags, "logs": [x.get("stream", "").strip() for x in logs if x.get("stream")]}

    def prune(self) -> int:
        removed=0
        for container in self._client().containers.list(all=True, filters={"name":"awe_"}):
            if container.status in ("exited","dead","created") and container.name not in self.SERVICE_CONTAINERS: container.remove(force=True); removed+=1
        return removed

    def logs(self, container_id: str, tail: int = 500) -> list[str]:
        container=self._client().containers.get(container_id)
        if not container.name.startswith("awe_"): raise PermissionError("Only AWE containers can be inspected")
        return container.logs(tail=tail).decode(errors="replace").splitlines()

    def status(self) -> dict:
        client = self._client()
        client.ping()
        return {"available": True, "version": client.version().get("Version", "unknown"), "message": "Docker daemon reachable"}
