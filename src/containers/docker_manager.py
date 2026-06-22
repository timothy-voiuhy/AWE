"""
Thin wrapper around the Docker SDK for managing AWE tool containers.
All container names are prefixed with 'awe_' for easy filtering.
"""
import logging
import time
from typing import Generator, Optional

logger = logging.getLogger(__name__)

try:
    import docker
    from docker.errors import BuildError, DockerException, ImageNotFound, NotFound
    _SDK_AVAILABLE = True
except ImportError:
    _SDK_AVAILABLE = False


class DockerUnavailableError(RuntimeError):
    pass


class DockerManager:
    def __init__(self):
        self._client = None

    # ── connectivity ──────────────────────────────────────────────────────────

    def _get_client(self):
        if not _SDK_AVAILABLE:
            raise DockerUnavailableError(
                "docker package not installed.\n"
                "Run: pip install docker"
            )
        if self._client is None:
            try:
                self._client = docker.from_env()
            except DockerException as exc:
                raise DockerUnavailableError(
                    f"Cannot reach Docker daemon.\n"
                    f"Make sure Docker is running: {exc}"
                ) from exc
        return self._client

    def is_available(self) -> tuple[bool, str]:
        """Return (ok, reason_string)."""
        try:
            self._get_client().ping()
            return True, "Docker daemon reachable"
        except DockerUnavailableError as exc:
            return False, str(exc)
        except Exception as exc:
            return False, str(exc)

    def server_version(self) -> str:
        return self._get_client().version().get("Version", "unknown")

    # ── images ────────────────────────────────────────────────────────────────

    def image_exists(self, image: str) -> bool:
        try:
            self._get_client().images.get(image)
            return True
        except ImageNotFound:
            return False

    def pull_image(self, image: str) -> Generator[str, None, None]:
        """Generator — yields status lines while pulling."""
        client = self._get_client()
        for line in client.api.pull(image, stream=True, decode=True):
            status = line.get("status", "")
            detail = line.get("progressDetail", {})
            prog = ""
            if detail.get("total"):
                pct = int(detail.get("current", 0) / detail["total"] * 100)
                prog = f" {pct}%"
            yield f"{status}{prog}"

    def list_images(self) -> list[dict]:
        images = self._get_client().images.list()
        result = []
        for img in images:
            tags = img.tags or ["<none>:<none>"]
            result.append({
                "id": img.short_id,
                "tags": tags,
                "size_mb": round(img.attrs.get("Size", 0) / 1_048_576, 1),
            })
        return result

    def build_image(self, dockerfile_path: str, tag: str) -> Generator[str, None, None]:
        """Generator — yields build log lines; raises RuntimeError on build failure."""
        import pathlib
        client = self._get_client()
        context = str(pathlib.Path(dockerfile_path).parent)
        dockerfile = pathlib.Path(dockerfile_path).name
        failed = False
        error_msg = ""
        try:
            for chunk in client.api.build(
                path=context,
                dockerfile=dockerfile,
                tag=tag,
                rm=True,
                decode=True,
            ):
                stream = chunk.get("stream", "")
                if stream.strip():
                    yield stream.rstrip()
                err = chunk.get("error", "")
                if err:
                    failed = True
                    error_msg = err.rstrip()
                    yield f"ERROR: {error_msg}"
        except BuildError as exc:
            raise RuntimeError(str(exc)) from exc
        if failed:
            raise RuntimeError(f"Build failed: {error_msg}")

    def remove_image(self, image: str, force: bool = False):
        self._get_client().images.remove(image, force=force)

    # ── containers ────────────────────────────────────────────────────────────

    def run_container(
        self,
        image: str,
        command: str,
        name: str,
        volumes: dict,
        environment: Optional[dict] = None,
        network: str = "bridge",
    ):
        """Start a detached container; return the Container object."""
        return self._get_client().containers.run(
            image=image,
            command=command,
            name=name,
            volumes=volumes,
            environment=environment or {},
            network=network,
            detach=True,
        )

    def list_awe_containers(self) -> list[dict]:
        """All containers whose name starts with 'awe_'."""
        containers = self._get_client().containers.list(
            all=True,
            filters={"name": "awe_"},
        )
        result = []
        for c in containers:
            started = c.attrs.get("State", {}).get("StartedAt", "")[:19].replace("T", " ")
            result.append({
                "id": c.short_id,
                "full_id": c.id,
                "name": c.name,
                "image": c.image.tags[0] if c.image.tags else c.image.short_id,
                "status": c.status,
                "started": started,
            })
        return result

    def get_container(self, container_id: str):
        try:
            return self._get_client().containers.get(container_id)
        except NotFound:
            return None

    def stop_container(self, container_id: str, timeout: int = 5):
        c = self.get_container(container_id)
        if c and c.status == "running":
            c.stop(timeout=timeout)

    def remove_container(self, container_id: str, force: bool = True):
        c = self.get_container(container_id)
        if c:
            c.remove(force=force)

    def stream_logs(self, container_id: str) -> Generator[str, None, None]:
        """Yield decoded log lines; follows the container until it exits."""
        c = self.get_container(container_id)
        if c is None:
            return
        try:
            for chunk in c.logs(stream=True, follow=True):
                yield chunk.decode(errors="replace").rstrip("\n")
        except Exception as exc:
            yield f"[log stream error: {exc}]"

    # Names of long-lived service containers that should never be pruned
    SERVICE_CONTAINERS: frozenset[str] = frozenset({"awe_mongodb"})

    def prune_stopped(self) -> int:
        """Remove all stopped tool containers; return count removed.
        Service containers (e.g. awe_mongodb) are intentionally skipped."""
        removed = 0
        for info in self.list_awe_containers():
            if (info["status"] in ("exited", "dead", "created")
                    and info["name"] not in self.SERVICE_CONTAINERS):
                self.remove_container(info["full_id"])
                removed += 1
        return removed

    # ── Service containers (long-running, port-bound) ─────────────────────────

    def ensure_service_container(
        self,
        name: str,
        image: str,
        ports: dict,
        volumes: dict,
        environment: Optional[dict] = None,
        restart_policy: Optional[dict] = None,
    ):
        """Return a running service container, starting or creating it as needed.

        `ports` uses Docker SDK format: {"<port>/tcp": ("<host_ip>", host_port)}
        If the named container already exists but is stopped it is started rather
        than recreated (data volumes are preserved).
        """
        client = self._get_client()
        try:
            container = client.containers.get(name)
            if container.status != "running":
                logger.info("Starting existing container %s", name)
                container.start()
            return container
        except NotFound:
            pass

        if not self.image_exists(image):
            logger.info("Pulling image %s …", image)
            for line in self.pull_image(image):
                logger.debug("pull %s: %s", image, line)

        logger.info("Creating service container %s from %s", name, image)
        return client.containers.run(
            image=image,
            name=name,
            ports=ports,
            volumes=volumes,
            environment=environment or {},
            restart_policy=restart_policy or {"Name": "unless-stopped"},
            detach=True,
        )

    def stop_service_container(self, name: str, timeout: int = 10) -> None:
        """Stop a named service container without removing it (data is preserved)."""
        try:
            container = self._get_client().containers.get(name)
            if container.status == "running":
                logger.info("Stopping service container %s", name)
                container.stop(timeout=timeout)
        except NotFound:
            pass


# Module-level singleton — safe to import anywhere
manager = DockerManager()
