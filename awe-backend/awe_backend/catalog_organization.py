"""Persistent catalog folders, independent of execution/result categories."""
import hashlib
import json
import secrets
import threading
from pathlib import Path

_LOCK = threading.RLock()
_FALLBACK = "uncategorized"


class CatalogOrganization:
    def __init__(self, workspace: Path):
        self.path = workspace / ".awe-catalog-organization.json"

    def _read(self):
        try:
            return json.loads(self.path.read_text())
        except FileNotFoundError:
            return {"categories": [{"id": _FALLBACK, "name": "Uncategorized", "parent_id": None}], "assignments": {}, "defaults": {}}

    def _validate(self, data):
        categories = {item["id"]: item for item in data["categories"]}
        if len(categories) > 500:
            raise ValueError("A catalog can contain at most 500 categories")
        siblings = set()
        for item in categories.values():
            name = item["name"].strip()
            if not name or len(name) > 80 or "/" in name or any(ord(char) < 32 for char in name):
                raise ValueError("Use a category name of 1–80 characters without slashes or control characters")
            item["name"] = name
            identity = (item["parent_id"], name.casefold())
            if identity in siblings:
                raise ValueError("A category with that name already exists under this parent")
            siblings.add(identity)
            seen, parent = {item["id"]}, item["parent_id"]
            while parent is not None:
                if parent in seen:
                    raise ValueError("A category cannot be placed inside itself or a descendant")
                if parent not in categories:
                    raise ValueError("Parent category does not exist")
                seen.add(parent)
                if len(seen) > 8:
                    raise ValueError("Categories may be nested at most eight levels deep")
                parent = categories[parent]["parent_id"]
        if categories[_FALLBACK]["parent_id"] is not None:
            raise ValueError("Uncategorized must remain a root category")

    def _transaction(self, items, change=None):
        with _LOCK:
            data = self._read()
            previous = json.dumps(data, sort_keys=True)
            for label in {*items.values(), "Exploits"}:
                if label not in data["defaults"]:
                    existing = next((item for item in data["categories"] if item["parent_id"] is None and item["name"].casefold() == label.casefold()), None)
                    identity = existing["id"] if existing else "default_" + hashlib.sha256(label.encode()).hexdigest()[:20]
                    if not existing:
                        data["categories"].append({"id": identity, "name": label, "parent_id": None})
                    data["defaults"][label] = identity
            if change:
                change(data)
            self._validate(data)
            if json.dumps(data, sort_keys=True) != previous:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                temporary = self.path.with_suffix(".tmp")
                temporary.write_text(json.dumps(data, indent=2))
                temporary.replace(self.path)
            return {**data, "placements": {key: data["assignments"].get(key, data["defaults"][label]) for key, label in items.items()}}

    def snapshot(self, items):
        return self._transaction(items)

    def save_category(self, items, name, parent_id, category_id=None):
        def change(data):
            if category_id:
                category = next((item for item in data["categories"] if item["id"] == category_id), None)
                if category is None:
                    raise KeyError(category_id)
                category.update(name=name, parent_id=parent_id)
            else:
                data["categories"].append({"id": secrets.token_hex(12), "name": name, "parent_id": parent_id})
        return self._transaction(items, change)

    def delete_category(self, items, category_id):
        def change(data):
            if category_id == _FALLBACK:
                raise ValueError("The fallback category cannot be deleted")
            category = next((item for item in data["categories"] if item["id"] == category_id), None)
            if category is None:
                raise KeyError(category_id)
            replacement = category["parent_id"] or _FALLBACK
            data["categories"].remove(category)
            for child in data["categories"]:
                if child["parent_id"] == category_id:
                    child["parent_id"] = category["parent_id"]
            for mapping in (data["assignments"], data["defaults"]):
                for key, value in mapping.items():
                    if value == category_id:
                        mapping[key] = replacement
        return self._transaction(items, change)

    def assign(self, items, item_keys, category_id):
        def change(data):
            if not any(item["id"] == category_id for item in data["categories"]):
                raise ValueError("Category does not exist")
            if not set(item_keys).issubset(items):
                raise ValueError("One or more catalog items do not exist")
            data["assignments"].update({key: category_id for key in item_keys})
        return self._transaction(items, change)
