import docker

from .schemas import DockerContainer


class DockerService:
    def _client(self): return docker.from_env()

    def list(self) -> list[DockerContainer]:
        result = []
        for container in self._client().containers.list(all=True, filters={"name": "awe_"}):
            tags = container.image.tags
            result.append(DockerContainer(id=container.short_id, name=container.name, image=tags[0] if tags else container.image.short_id, status=container.status, created=container.attrs.get("Created", "")))
        return result

    def stop(self, container_id: str) -> None:
        container = self._client().containers.get(container_id)
        if not container.name.startswith("awe_"):
            raise PermissionError("Only AWE containers can be managed")
        container.stop(timeout=5)

    def remove(self, container_id: str) -> None:
        container = self._client().containers.get(container_id)
        if not container.name.startswith("awe_"):
            raise PermissionError("Only AWE containers can be managed")
        container.remove(force=True)
