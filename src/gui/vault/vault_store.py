"""
VaultStore — persistence for the global AWE Vault.

The Vault is *global* (shared across every project), so it deliberately does NOT
use the per-project MongoDB (`AweRepository`). It follows the same convention as
`gui.appearance` and `gui.browserWindow`: a JSON metadata file plus copied files
on disk, all under ``~/.config/awe/vault/``.

    ~/.config/awe/vault/
        vault.json                                  # categories + item metadata
        files/<category_id>/<uuid>__<originalname>  # copied images / pdfs / files

This module is pure logic (no Qt) so it can be reasoned about and tested on its own.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)

VAULT_DIR = Path(os.path.expanduser("~")) / ".config" / "awe" / "vault"
FILES_DIR = VAULT_DIR / "files"
_VAULT_FILE = VAULT_DIR / "vault.json"

# Extensions treated as directly-viewable images (lightbox gallery).
_IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".svg", ".ico", ".tiff"}

# Item types
IMAGE = "image"
PDF = "pdf"
FILE = "file"
LINK = "link"
NOTE = "note"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_id() -> str:
    return uuid.uuid4().hex


def _safe_name(name: str) -> str:
    """Keep a readable original filename but strip anything path-hostile."""
    name = os.path.basename(name).strip() or "file"
    return "".join(c if (c.isalnum() or c in " ._-()") else "_" for c in name)


def _infer_type(path: str) -> str:
    ext = os.path.splitext(path)[1].lower()
    if ext in _IMAGE_EXTS:
        return IMAGE
    if ext == ".pdf":
        return PDF
    return FILE


class VaultStore:
    """Read/write access to the global vault. Cheap to construct; loads lazily."""

    def __init__(self) -> None:
        self._data: dict | None = None

    # ── JSON load / save ────────────────────────────────────────────────────
    def reload(self) -> None:
        """Drop the in-memory cache so the next access re-reads vault.json.

        Used to pick up changes written by another VaultStore instance (e.g.
        another open project window sharing the same global vault file)."""
        self._data = None

    def _load(self) -> dict:
        if self._data is None:
            try:
                self._data = json.loads(_VAULT_FILE.read_text())
            except Exception:
                self._data = {}
            self._data.setdefault("categories", [])
            self._data.setdefault("items", [])
        return self._data

    def _save(self) -> None:
        VAULT_DIR.mkdir(parents=True, exist_ok=True)
        _VAULT_FILE.write_text(json.dumps(self._load(), indent=2))

    # ── Categories ──────────────────────────────────────────────────────────
    def list_categories(self) -> list[dict]:
        cats = self._load()["categories"]
        return sorted(cats, key=lambda c: c.get("order", 0))

    def get_category(self, category_id: str) -> dict | None:
        for c in self._load()["categories"]:
            if c["id"] == category_id:
                return c
        return None

    def add_category(self, name: str, accent: str) -> dict:
        cats = self._load()["categories"]
        cat = {
            "id": _new_id(),
            "name": name.strip() or "Untitled",
            "accent": accent,
            "created_at": _now(),
            "order": (max((c.get("order", 0) for c in cats), default=-1) + 1),
        }
        cats.append(cat)
        self._save()
        return cat

    def rename_category(self, category_id: str, name: str) -> None:
        cat = self.get_category(category_id)
        if cat is not None:
            cat["name"] = name.strip() or cat["name"]
            self._save()

    def set_accent(self, category_id: str, accent: str) -> None:
        cat = self.get_category(category_id)
        if cat is not None:
            cat["accent"] = accent
            self._save()

    def delete_category(self, category_id: str) -> None:
        data = self._load()
        data["categories"] = [c for c in data["categories"] if c["id"] != category_id]
        # Drop the category's items (unlinking their copied files) and folder.
        for item in [i for i in data["items"] if i.get("category_id") == category_id]:
            self._unlink_item_file(item)
        data["items"] = [i for i in data["items"] if i.get("category_id") != category_id]
        shutil.rmtree(FILES_DIR / category_id, ignore_errors=True)
        self._save()

    # ── Items ───────────────────────────────────────────────────────────────
    def list_items(self, category_id: str) -> list[dict]:
        items = [i for i in self._load()["items"] if i.get("category_id") == category_id]
        return sorted(items, key=lambda i: i.get("created_at", ""))

    def get_item(self, item_id: str) -> dict | None:
        for i in self._load()["items"]:
            if i["id"] == item_id:
                return i
        return None

    def _add_item(self, item: dict) -> dict:
        self._load()["items"].append(item)
        self._save()
        return item

    def add_link(self, category_id: str, url: str, title: str = "") -> dict:
        url = url.strip()
        return self._add_item({
            "id": _new_id(),
            "category_id": category_id,
            "type": LINK,
            "title": (title.strip() or url),
            "url": url,
            "created_at": _now(),
        })

    def add_note(self, category_id: str, text: str, title: str = "", lang: str = "txt") -> dict:
        return self._add_item({
            "id": _new_id(),
            "category_id": category_id,
            "type": NOTE,
            "title": (title.strip() or "Note"),
            "text": text,
            "lang": lang or "txt",
            "created_at": _now(),
        })

    def add_file(self, category_id: str, src_path: str) -> dict:
        """Copy ``src_path`` into the vault and register it as an item."""
        src = Path(src_path)
        dest_dir = FILES_DIR / category_id
        dest_dir.mkdir(parents=True, exist_ok=True)
        stored = f"{_new_id()}__{_safe_name(src.name)}"
        shutil.copy2(src, dest_dir / stored)
        return self._add_item({
            "id": _new_id(),
            "category_id": category_id,
            "type": _infer_type(src.name),
            "title": src.name,
            "filename": stored,
            "created_at": _now(),
        })

    def add_file_bytes(self, category_id: str, data: bytes, suffix: str, title: str = "") -> dict:
        """Register raw bytes (e.g. a pasted image) as a file-backed item."""
        dest_dir = FILES_DIR / category_id
        dest_dir.mkdir(parents=True, exist_ok=True)
        base = _safe_name(title) or "pasted"
        if not base.lower().endswith(suffix.lower()):
            base = base + suffix
        stored = f"{_new_id()}__{base}"
        (dest_dir / stored).write_bytes(data)
        return self._add_item({
            "id": _new_id(),
            "category_id": category_id,
            "type": _infer_type(stored),
            "title": title or base,
            "filename": stored,
            "created_at": _now(),
        })

    def rename_item(self, item_id: str, title: str) -> None:
        item = self.get_item(item_id)
        if item is not None:
            item["title"] = title.strip() or item["title"]
            self._save()

    def update_note(self, item_id: str, title: str, text: str, lang: str) -> None:
        item = self.get_item(item_id)
        if item is not None and item.get("type") == NOTE:
            item["title"] = title.strip() or item.get("title", "Note")
            item["text"] = text
            item["lang"] = lang or "txt"
            self._save()

    def set_link_url(self, item_id: str, url: str) -> None:
        item = self.get_item(item_id)
        if item is not None and item.get("type") == LINK:
            item["url"] = url.strip()
            self._save()

    def delete_item(self, item_id: str) -> None:
        data = self._load()
        item = self.get_item(item_id)
        if item is not None:
            self._unlink_item_file(item)
        data["items"] = [i for i in data["items"] if i["id"] != item_id]
        self._save()

    # ── Files ───────────────────────────────────────────────────────────────
    def abs_path(self, item: dict) -> Path | None:
        """Absolute path of a file-backed item, or None for link/note items."""
        fn = item.get("filename")
        if not fn:
            return None
        return FILES_DIR / item["category_id"] / fn

    def _unlink_item_file(self, item: dict) -> None:
        path = self.abs_path(item)
        if path is not None:
            try:
                path.unlink(missing_ok=True)
            except Exception:
                log.warning("Could not remove vault file %s", path, exc_info=True)
