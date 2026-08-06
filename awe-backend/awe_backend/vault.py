from __future__ import annotations

import json
import os
import shutil
import uuid
import base64
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken

VAULT_DIR = Path(os.path.expanduser("~")) / ".config" / "awe" / "vault"
FILES_DIR = VAULT_DIR / "files"
VAULT_FILE = VAULT_DIR / "vault.json"
IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".svg", ".ico", ".tiff"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _id() -> str:
    return uuid.uuid4().hex


def _safe_name(value: str) -> str:
    name = os.path.basename(value).strip() or "file"
    return "".join(c if c.isalnum() or c in " ._-()" else "_" for c in name)


class VaultService:
    """Global category/item vault matching the Qt VaultStore contract."""

    def __init__(self, secret_key="development-only-change-me"):
        self._data: dict | None = None
        self._fernet = Fernet(base64.urlsafe_b64encode(hashlib.sha256(secret_key.encode()).digest()))

    def _load(self) -> dict:
        if self._data is None:
            try:
                self._data = json.loads(VAULT_FILE.read_text())
            except Exception:
                self._data = {}
            self._data.setdefault("categories", [])
            self._data.setdefault("items", [])
        return self._data

    def _save(self) -> None:
        VAULT_DIR.mkdir(parents=True, exist_ok=True)
        temporary = VAULT_FILE.with_suffix(".tmp")
        temporary.write_text(json.dumps(self._load(), indent=2))
        temporary.replace(VAULT_FILE)

    def categories(self) -> list[dict]:
        return sorted(self._load()["categories"], key=lambda item: item.get("order", 0))

    def add_category(self, name: str, accent: str = "#89b4fa") -> dict:
        categories = self._load()["categories"]
        category = {"id": _id(), "name": name.strip() or "Untitled", "accent": accent, "created_at": _now(), "order": len(categories)}
        categories.append(category); self._save(); return category

    def update_category(self, category_id: str, name: str | None = None, accent: str | None = None) -> dict | None:
        category = next((item for item in self.categories() if item["id"] == category_id), None)
        if category is None: return None
        if name is not None: category["name"] = name.strip() or category["name"]
        if accent is not None: category["accent"] = accent
        self._save(); return category

    def delete_category(self, category_id: str) -> bool:
        data = self._load(); items = [item for item in data["items"] if item.get("category_id") == category_id]
        for item in items: self._unlink(item)
        data["items"] = [item for item in data["items"] if item.get("category_id") != category_id]
        data["categories"] = [item for item in data["categories"] if item["id"] != category_id]
        shutil.rmtree(FILES_DIR / category_id, ignore_errors=True); self._save(); return bool(items or len(data["categories"]))

    def items(self, category_id: str) -> list[dict]:
        return sorted([item for item in self._load()["items"] if item.get("category_id") == category_id], key=lambda item: item.get("created_at", ""))

    def add_item(self, category_id: str, item_type: str, title: str, **values) -> dict:
        item = {"id": _id(), "category_id": category_id, "type": item_type, "title": title.strip() or item_type.title(), "created_at": _now(), **values}
        self._load()["items"].append(item); self._save(); return item

    def update_item(self, item_id: str, **values) -> dict | None:
        item = next((item for item in self._load()["items"] if item["id"] == item_id), None)
        if item is None: return None
        item.update({key: value for key, value in values.items() if value is not None}); self._save(); return item

    def delete_item(self, item_id: str) -> bool:
        data = self._load(); item = next((item for item in data["items"] if item["id"] == item_id), None)
        if item is None: return False
        self._unlink(item); data["items"] = [row for row in data["items"] if row["id"] != item_id]; self._save(); return True

    def add_file(self, category_id: str, filename: str, content: bytes) -> dict:
        folder = FILES_DIR / category_id; folder.mkdir(parents=True, exist_ok=True)
        stored = f"{_id()}__{_safe_name(filename)}"; (folder / stored).write_bytes(content)
        suffix = Path(filename).suffix.lower(); item_type = "image" if suffix in IMAGE_EXTENSIONS else "pdf" if suffix == ".pdf" else "file"
        return self.add_item(category_id, item_type, filename, filename=stored)

    def file_path(self, item: dict) -> Path | None:
        filename = item.get("filename")
        return FILES_DIR / item["category_id"] / filename if filename else None

    def _unlink(self, item: dict) -> None:
        path = self.file_path(item)
        if path: path.unlink(missing_ok=True)

    # Compatibility for the initially shipped project credential API.
    def _legacy_items(self, project_dir):
        path = Path(project_dir) / ".awe-vault.enc"
        try: return json.loads(self._fernet.decrypt(path.read_bytes()))
        except FileNotFoundError: return []
        except (InvalidToken, ValueError) as exc: raise RuntimeError("Vault cannot be decrypted") from exc

    def _legacy_write(self, project_dir, items):
        path = Path(project_dir) / ".awe-vault.enc"; temporary = path.with_suffix(".tmp")
        temporary.write_bytes(self._fernet.encrypt(json.dumps(items).encode())); temporary.chmod(0o600); temporary.replace(path)

    def list(self, project_dir):
        from .schemas import VaultItem
        return [VaultItem.model_validate(item) for item in self._legacy_items(project_dir)]

    def create(self, project_dir, payload):
        from .schemas import VaultItem
        item = VaultItem(id=_id(), created_at=_now(), **payload.model_dump())
        items = [row.model_dump() for row in self.list(project_dir)]; items.append(item.model_dump()); self._legacy_write(project_dir, items); return item

    def delete(self, project_dir, item_id):
        items = self.list(project_dir); kept = [item for item in items if item.id != item_id]
        if len(kept) == len(items): return False
        self._legacy_write(project_dir, [item.model_dump() for item in kept]); return True
