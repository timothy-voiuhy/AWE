"""
Per-project settings stored in MongoDB.

Keys are plain strings (e.g. "github_token", "resolver_path").
Values are any JSON-serialisable type.

Usage:
    repo = SettingsRepository(project_dir)
    repo.set("github_token", "ghp_abc123")
    token = repo.get("github_token", default="")
    all_settings = repo.get_all()
"""
from datetime import datetime, timezone

from database.mongo import get_db


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class SettingsRepository:
    def __init__(self, project_dir: str, uri: str = "mongodb://localhost:27017"):
        self._db = get_db(project_dir, uri)
        self._db.project_settings.create_index("key", unique=True)

    def get(self, key: str, default=None):
        doc = self._db.project_settings.find_one({"key": key}, {"value": 1})
        return doc["value"] if doc else default

    def set(self, key: str, value):
        self._db.project_settings.update_one(
            {"key": key},
            {"$set": {"key": key, "value": value, "updated_at": _now()}},
            upsert=True,
        )

    def delete(self, key: str):
        self._db.project_settings.delete_one({"key": key})

    def get_all(self) -> dict:
        return {d["key"]: d["value"] for d in self._db.project_settings.find()}

    def set_many(self, mapping: dict):
        for k, v in mapping.items():
            self.set(k, v)


# Canonical setting keys — used across executor, UI, and tool registry
class Keys:
    GITHUB_TOKEN        = "github_token"
    SHODAN_KEY          = "shodan_api_key"
    RESOLVER_PATH       = "resolver_path"        # inside container
    DEFAULT_WORDLIST    = "default_wordlist"     # inside container
    NUCLEI_TEMPLATES    = "nuclei_templates_path"
    DEFAULT_THREADS     = "default_threads"
    DEFAULT_RATE_LIMIT  = "default_rate_limit"
    DEFAULT_CONCURRENCY = "default_concurrency"
    MONGO_URI           = "mongo_uri"

DEFAULTS = {
    Keys.RESOLVER_PATH:       "/wordlists/resolvers.txt",
    Keys.DEFAULT_WORDLIST:    "/wordlists/common.txt",
    Keys.DEFAULT_THREADS:     "10",
    Keys.DEFAULT_RATE_LIMIT:  "150",
    Keys.DEFAULT_CONCURRENCY: "25",
}
