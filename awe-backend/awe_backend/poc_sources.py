"""Immutable PoC source snapshots and tracked Docker builds."""
import hashlib
import io
import json
import shutil
import subprocess
import tarfile
import threading
import zipfile
from pathlib import Path
from urllib.parse import urlsplit

from .run_outputs import RunOutputs


def unpack_source(raw: bytes, destination: Path):
    if len(raw) > 50 * 1024 * 1024:
        raise ValueError("Archive exceeds 50 MiB")
    destination.mkdir(parents=True, exist_ok=True)
    total = 0
    def write(name, size, data):
        nonlocal total
        target = destination / name
        if Path(name).is_absolute() or ".." in Path(name).parts or not target.resolve().is_relative_to(destination.resolve()):
            raise ValueError("Archive path escapes source directory")
        total += size
        if total > 200 * 1024 * 1024:
            raise ValueError("Expanded archive exceeds 200 MiB")
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("wb") as file:
            shutil.copyfileobj(data, file)
    if zipfile.is_zipfile(io.BytesIO(raw)):
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            if len(archive.infolist()) > 10000:
                raise ValueError("Archive has too many entries")
            for info in archive.infolist():
                if info.external_attr >> 16 & 0o170000 == 0o120000:
                    raise ValueError("Source archives cannot contain symbolic links")
                if not info.is_dir():
                    with archive.open(info) as file:
                        write(info.filename, info.file_size, file)
    else:
        with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
            for index, info in enumerate(archive):
                if index > 10000 or (not info.isfile() and not info.isdir()):
                    raise ValueError("Source archives must contain regular files and directories only")
                if info.isfile():
                    with archive.extractfile(info) as file:
                        write(info.name, info.size, file)


def build_poc(project_dir: Path, run_id: str, payload, raw: bytes | None, settings):
    import sys
    source = str(settings.legacy_src_dir)
    if source not in sys.path:
        sys.path.insert(0, source)
    from config.config import CUSTOM_TOOLS_DIR
    from containers.custom_tools import register_custom_tool
    from containers.custom_tools import CustomToolConfig
    from containers.tool_registry import TOOL_REGISTRY
    from .docker_service import DockerService
    record = RunOutputs(project_dir, run_id)
    staging = project_dir / ".awe-builds" / run_id
    try:
        if payload.key in TOOL_REGISTRY and not isinstance(TOOL_REGISTRY[payload.key], CustomToolConfig):
            raise ValueError("A PoC cannot replace a built-in tool")
        staging.mkdir(parents=True)
        record.append("Preparing PoC source snapshot", "system")
        if payload.repository:
            url = urlsplit(payload.repository)
            if url.scheme != "https" or not url.hostname or url.username or url.password:
                raise ValueError("Use a public HTTPS repository URL without credentials")
            if not payload.revision or payload.revision.startswith("-"):
                raise ValueError("A Git revision is required")
            def git(*args):
                result = subprocess.run(["git", *args], cwd=staging, capture_output=True, text=True, timeout=120, env={**__import__('os').environ, "GIT_TERMINAL_PROMPT": "0"})
                if result.returncode:
                    raise ValueError(result.stderr[:2000])
                return result.stdout.strip()
            git("init", ".")
            git("fetch", "--depth=1", "--", payload.repository, payload.revision)
            git("checkout", "--detach", "FETCH_HEAD")
            revision = git("rev-parse", "HEAD")
            metadata = {"kind": "git", "repository": payload.repository, "revision": revision}
        else:
            if raw is None:
                raise ValueError("Provide a repository or source archive")
            unpack_source(raw, staging)
            revision = hashlib.sha256(raw).hexdigest()
            metadata = {"kind": "archive", "sha256": revision}
        if payload.dockerfile:
            (staging / "Dockerfile").write_text(payload.dockerfile)
        if not (staging / "Dockerfile").is_file():
            raise ValueError("A Dockerfile is required at the source root")
        if any(path.is_symlink() and not path.resolve().is_relative_to(staging.resolve()) for path in staging.rglob("*")):
            raise ValueError("Source links must stay inside the source snapshot")
        tool_dir = Path(CUSTOM_TOOLS_DIR) / payload.key
        build_hash = hashlib.sha256((revision + payload.dockerfile + payload.command_template).encode()).hexdigest()[:20]
        snapshot = tool_dir / "sources" / build_hash
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        if not snapshot.exists():
            shutil.copytree(staging, snapshot, ignore=shutil.ignore_patterns(".git"))
        image = f"awe/poc-{payload.key}:{build_hash}"
        record.update(source_metadata=metadata, image=image)
        record.append(f"Building {image}", "system")
        client = DockerService()._client()
        for event in client.api.build(path=str(snapshot), tag=image, rm=True, decode=True):
            if event.get("error"):
                raise RuntimeError(event["error"])
            if event.get("stream"):
                record.append(event["stream"], "build")
        config = payload.model_dump(exclude={"repository", "revision", "dockerfile", "parser"})
        config.update(image=image, source_metadata=metadata, dockerfile=f"sources/{build_hash}/Dockerfile")
        tool_dir.mkdir(parents=True, exist_ok=True)
        (tool_dir / "tool.json").write_text(json.dumps(config, indent=2))
        if payload.parser:
            (tool_dir / "parser.py").write_text(payload.parser)
        elif (tool_dir / "parser.py").exists():
            (tool_dir / "parser.py").unlink()
        register_custom_tool(str(tool_dir))
        record.update(status="completed", message="PoC built and registered", tool_key=payload.key)
        record.append("PoC built and registered", "system")
    except Exception as exc:
        record.update(status="failed", message=str(exc))
        record.append(str(exc), "system")


def start_build(project_dir, run_id, payload, raw, settings):
    record = RunOutputs(project_dir, run_id)
    record.update(kind=f"poc.build.{payload.key}", status="running", output_dir=str(project_dir / ".awe-builds" / run_id))
    threading.Thread(target=build_poc, args=(project_dir, run_id, payload, raw, settings), daemon=True).start()
    return record.metadata()
