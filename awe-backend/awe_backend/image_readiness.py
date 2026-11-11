"""Exact image availability and evidence-based freshness, without implicit pulls."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
from pathlib import Path
from threading import Lock
import time

import docker
from docker.utils.build import exclude_paths

BUILD_LABEL = "org.awe.build-context-sha256"
_checks: dict[tuple[str, str], dict] = {}
_lock = Lock()
CACHE_SECONDS = 900


def canonical_reference(reference: str) -> str:
    from docker.utils import parse_repository_tag
    repository, tag = parse_repository_tag(reference)
    parts = repository.split("/")
    if parts[0] in {"docker.io", "index.docker.io"}:
        parts = parts[1:]
    if len(parts) == 1:
        parts.insert(0, "library")
    if "." not in parts[0] and ":" not in parts[0] and parts[0] != "localhost":
        parts.insert(0, "docker.io")
    separator = "@" if "@" in reference else ":"
    return "/".join(parts) + separator + (tag or "latest")


def invalidate_image(reference):
    with _lock:
        for key in list(_checks):
            if key[0] == reference:
                del _checks[key]


def context_fingerprint(dockerfile: str) -> str:
    path = Path(dockerfile).resolve()
    root = path.parent
    ignore = root / ".dockerignore"
    patterns = ignore.read_text().splitlines() if ignore.is_file() else []
    digest = hashlib.sha256()
    for name in sorted(exclude_paths(str(root), patterns, path.name)):
        entry = root / name
        digest.update(name.encode() + b"\0")
        digest.update(str(entry.lstat().st_mode).encode() + b"\0")
        if entry.is_symlink():
            digest.update(str(entry.readlink()).encode())
        elif entry.is_file():
            with entry.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
        digest.update(b"\0")
    return digest.hexdigest()


def image_state(tool, service, *, refresh=False) -> dict:
    base = {"image": tool.image, "image_present": False, "update_status": "unchecked", "update_message": "Not checked for updates.", "update_checked_at": ""}
    try:
        client = service._client()
        image = client.images.get(tool.image)
    except docker.errors.ImageNotFound:
        return {**base, "update_message": "Required image is not installed."}
    base["image_present"] = True
    if tool.dockerfile:
        try:
            recorded = (image.attrs.get("Config", {}).get("Labels") or {}).get(BUILD_LABEL)
            if not recorded:
                return {**base, "update_status": "unknown", "update_message": "Build provenance unavailable. Rebuild once to track source changes."}
            changed = recorded != context_fingerprint(tool.dockerfile)
            return {**base, "update_status": "outdated" if changed else "current", "update_message": "Build sources changed; rebuild this image." if changed else "Matches current build sources. Base-image and package updates require a rebuild."}
        except OSError:
            return {**base, "update_status": "unknown", "update_message": "Build sources are unavailable. Restore the Dockerfile/build context."}
    cache_key = (tool.image, image.id)
    with _lock:
        cached = _checks.get(cache_key)
    if cached and not refresh and time.time() - cached["time"] < CACHE_SECONDS:
        return {**base, **cached["state"]}
    if not refresh:
        return base
    checked_at = datetime.now(timezone.utc).isoformat()
    try:
        client.api.timeout = 15
        remote = client.images.get_registry_data(tool.image).id
        local = {item.rsplit("@", 1)[-1] for item in image.attrs.get("RepoDigests", [])}
        if not remote or not local:
            state = {"update_status": "unknown", "update_message": "No comparable registry digest. Pull the required reference to establish provenance."}
        else:
            changed = remote not in local
            state = {"update_status": "outdated" if changed else "current", "update_message": "Registry digest changed; pull an update." if changed else "Matches the registry digest."}
    except Exception:
        # Do not expose registry URLs, authentication headers, or SDK tracebacks.
        state = {"update_status": "unknown", "update_message": "Registry check failed. Check registry access, credentials, or rate limits and retry."}
    state["update_checked_at"] = checked_at
    with _lock:
        _checks[cache_key] = {"time": time.time(), "state": state}
    return {**base, **state}


def check_updates(tools, service) -> list[dict]:
    unique = {tool.image: tool for tool in tools}
    with ThreadPoolExecutor(max_workers=4) as pool:
        return list(pool.map(lambda tool: image_state(tool, service, refresh=True), unique.values()))


def tool_preflight(keys, service) -> dict:
    import sys
    from .config import get_settings
    source = str(get_settings().legacy_src_dir.resolve())
    if source not in sys.path: sys.path.insert(0, source)
    from containers.tool_registry import TOOL_REGISTRY
    from containers.parsers import PARSERS
    checks = []
    for key in dict.fromkeys(keys):
        tool = TOOL_REGISTRY.get(key)
        if tool is None:
            checks.append({"tool_key": key, "ready": False, "issues": [{"code": "tool_missing", "message": "Tool is no longer registered. Restore it or edit the transform stages.", "action": "edit"}]})
            continue
        issues = []
        try:
            state = image_state(tool, service)
            if not state["image_present"]:
                action = "build" if tool.dockerfile else "pull"
                issues.append({"code": "image_missing", "message": f"Required image {tool.image} is not installed. {action.capitalize()} it before running.", "action": action})
            elif state["update_status"] == "outdated":
                issues.append({"code": "image_outdated", "message": state["update_message"], "action": "build" if tool.dockerfile else "pull", "warning": True})
        except Exception:
            state = {"image": tool.image, "image_present": False, "update_status": "unknown"}
            issues.append({"code": "docker_unavailable", "message": "Cannot inspect Docker. Check the daemon and socket access, then retry.", "action": "retry"})
        if "structured" in tool.output_channels and not callable(PARSERS.get(key)):
            issues.append({"code": "parser_missing", "message": "Structured output requires a registered parser. Restore or repair parser.py in the tool definition.", "action": "edit"})
        parser_path = getattr(tool, "parser_path", "")
        if "structured" in tool.output_channels and parser_path:
            try:
                compile(Path(parser_path).read_text(), parser_path, "exec")
            except (OSError, SyntaxError):
                issues.append({"code": "parser_invalid", "message": "The parser file is missing or has invalid Python syntax. Repair it before running.", "action": "edit"})
        checks.append({"tool_key": key, **state, "ready": not any(not issue.get("warning") for issue in issues), "issues": issues})
    return {"ready": bool(checks) and all(item["ready"] for item in checks), "tools": checks}


def transform_preflight(transform, service) -> dict:
    keys = [key for stage in transform.stages for key in stage.tool_keys] if transform.stages else [transform.tool_key]
    return tool_preflight(keys, service)


def require_ready(report):
    from fastapi import HTTPException
    if not report["ready"]:
        messages = [f"{item['tool_key']}: {issue['message']}" for item in report["tools"] for issue in item["issues"] if not issue.get("warning")]
        raise HTTPException(status_code=409, detail="Preflight failed. " + " ".join(messages))
