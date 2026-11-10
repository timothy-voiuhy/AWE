"""Project-local durable run events and artifacts; independent of UI attachments."""
from __future__ import annotations

import hashlib
import json
import mimetypes
import re
import threading
from datetime import datetime, timezone
from pathlib import Path

_LOCK = threading.RLock()
_ID = re.compile(r"^[a-zA-Z0-9_-]{1,100}$")


class RunOutputs:
    def __init__(self, project_dir: Path, run_id: str):
        if not _ID.fullmatch(run_id):
            raise ValueError("Invalid run ID")
        self.project_dir = project_dir.resolve()
        self.root = self.project_dir / ".awe-runs" / run_id
        self.run_id = run_id

    def metadata(self) -> dict:
        try:
            return json.loads((self.root / "run.json").read_text())
        except FileNotFoundError:
            raise KeyError(self.run_id)

    def update(self, **values) -> dict:
        with _LOCK:
            self.root.mkdir(parents=True, exist_ok=True)
            try:
                data = self.metadata()
            except KeyError:
                data = {"id": self.run_id, "created_at": datetime.now(timezone.utc).isoformat(), "last_sequence": 0}
            data.update(values)
            tmp = self.root / "run.tmp"
            tmp.write_text(json.dumps(data))
            tmp.replace(self.root / "run.json")
            return data

    def append(self, text: str, stream: str = "stdout", stage: str = "", limit: int | None = None):
        if len(text) > 65536:
            for start in range(0, len(text), 65536):
                self.append(text[start:start + 65536], stream, stage, limit)
            return
        if limit is None:
            from .config import get_settings
            limit = get_settings().run_log_max_bytes
        with _LOCK:
            meta = self.metadata()
            if meta.get("logs_truncated"):
                return
            path = self.root / "events.jsonl"
            if path.exists() and path.stat().st_size >= limit:
                text, stream = "Transcript limit reached; further output is not recorded.", "system"
                meta["logs_truncated"] = True
            seq = meta["last_sequence"] + 1
            event = {"sequence": seq, "timestamp": datetime.now(timezone.utc).isoformat(), "stream": stream, "stage": stage, "data": text[:65536]}
            with path.open("a") as file:
                if seq % 128 == 1:
                    with (self.root / "event-index.jsonl").open("a") as index:
                        index.write(json.dumps([seq, file.tell()]) + "\n")
                file.write(json.dumps(event) + "\n")
            self.update(last_sequence=seq, logs_truncated=meta.get("logs_truncated", False))

    def events(self, after: int = 0, limit: int = 200, search: str = "") -> dict:
        self.metadata()
        items = []
        cursor = after
        path = self.root / "events.jsonl"
        if path.exists():
            offset = 0
            index_path = self.root / "event-index.jsonl"
            if index_path.exists():
                with index_path.open() as index:
                    for row in index:
                        if not row.endswith("\n"):
                            break
                        sequence, position = json.loads(row)
                        if sequence > after + 1:
                            break
                        offset = position
            with path.open() as file:
                file.seek(offset)
                for line in file:
                    if not line.endswith("\n"):
                        break
                    event = json.loads(line)
                    if event["sequence"] <= after:
                        continue
                    cursor = event["sequence"]
                    if not search or search.casefold() in event["data"].casefold():
                        items.append(event)
                    if len(items) >= limit:
                        break
        return {"events": items, "cursor": cursor, "truncated": self.metadata().get("logs_truncated", False)}

    def collect(self, patterns: list[str] | None = None, limit: int | None = None) -> list[dict]:
        if limit is None:
            from .config import get_settings
            limit = get_settings().run_artifact_max_bytes
        with _LOCK:
            meta = self.metadata()
            output = Path(meta.get("output_dir", self.root / "files")).resolve()
            if not output.is_relative_to(self.project_dir):
                raise ValueError("Output directory is outside project")
            found, total, truncated = {}, 0, False
            for pattern in patterns or ["**/*"]:
                if Path(pattern).is_absolute() or ".." in Path(pattern).parts:
                    raise ValueError("Artifact patterns must be relative to output directory")
                for path in sorted(output.glob(pattern)):
                    if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(output):
                        continue
                    if any(part.startswith(".awe") for part in path.relative_to(output).parts):
                        continue
                    relative = path.relative_to(output).as_posix()
                    aid = hashlib.sha256(relative.encode()).hexdigest()[:24]
                    if aid in found:
                        continue
                    size = path.stat().st_size
                    if total + size > limit:
                        truncated = True
                        continue
                    total += size
                    digest = hashlib.sha256()
                    with path.open("rb") as file:
                        for chunk in iter(lambda: file.read(1024 * 1024), b""):
                            digest.update(chunk)
                    found[aid] = {"id": aid, "name": relative, "size": size, "mime_type": mimetypes.guess_type(path.name)[0] or "application/octet-stream", "sha256": digest.hexdigest()}
            self.update(artifacts=list(found.values()), artifacts_truncated=truncated)
            return list(found.values())

    def artifact(self, artifact_id: str) -> tuple[Path, dict]:
        meta = self.metadata()
        item = next((a for a in meta.get("artifacts", []) if a["id"] == artifact_id), None)
        if item is None:
            raise KeyError(artifact_id)
        output = Path(meta["output_dir"]).resolve()
        candidate = output / item["name"]
        if candidate.is_symlink() or not candidate.resolve().is_relative_to(output) or not output.is_relative_to(self.project_dir) or not candidate.is_file():
            raise KeyError(artifact_id)
        return candidate, item


def project_runs(project_dir: Path) -> list[dict]:
    rows = []
    for path in (project_dir / ".awe-runs").glob("*/run.json"):
        try:
            rows.append(json.loads(path.read_text()))
        except (OSError, ValueError):
            continue
    return sorted(rows, key=lambda r: r.get("created_at", ""), reverse=True)
