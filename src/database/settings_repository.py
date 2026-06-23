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

    # ── Per-tool command overrides ────────────────────────────────────────────
    # Stored as key = "tool_cmd:<tool_key>", value = command string

    _CMD_PREFIX = "tool_cmd:"

    def get_tool_command(self, tool_key: str) -> str | None:
        """Return the user-overridden command string, or None if not set."""
        return self.get(self._CMD_PREFIX + tool_key, default=None)

    def set_tool_command(self, tool_key: str, command: str):
        self.set(self._CMD_PREFIX + tool_key, command)

    def reset_tool_command(self, tool_key: str):
        """Delete the override — tool falls back to build_command()."""
        self.delete(self._CMD_PREFIX + tool_key)

    def get_all_tool_commands(self) -> dict[str, str]:
        """Return {tool_key: command} for every stored override."""
        prefix = self._CMD_PREFIX
        return {
            k[len(prefix):]: v
            for k, v in self.get_all().items()
            if k.startswith(prefix)
        }

    def reset_all_tool_commands(self):
        """Delete every tool command override."""
        prefix = self._CMD_PREFIX
        all_keys = [k for k in self.get_all() if k.startswith(prefix)]
        for k in all_keys:
            self.delete(k)


# Canonical setting keys — used across executor, UI, and tool registry
class Keys:
    # API credentials
    GITHUB_TOKEN        = "github_token"
    SHODAN_KEY          = "shodan_api_key"
    # Tool paths (container-relative)
    RESOLVER_PATH       = "resolver_path"
    DEFAULT_WORDLIST    = "default_wordlist"
    NUCLEI_TEMPLATES    = "nuclei_templates_path"
    # Scan defaults
    DEFAULT_THREADS     = "default_threads"
    DEFAULT_RATE_LIMIT  = "default_rate_limit"
    DEFAULT_CONCURRENCY = "default_concurrency"
    # Proxy
    PROXY_PORT          = "proxy_listen_port"
    UPSTREAM_PROXY      = "upstream_proxy_url"
    # Display
    EDITOR_FONT_SIZE    = "editor_font_size"
    # Internal
    MONGO_URI           = "mongo_uri"

DEFAULTS = {
    Keys.RESOLVER_PATH:       "/wordlists/resolvers.txt",
    Keys.DEFAULT_WORDLIST:    "/wordlists/common.txt",
    Keys.DEFAULT_THREADS:     "10",
    Keys.DEFAULT_RATE_LIMIT:  "150",
    Keys.DEFAULT_CONCURRENCY: "25",
    Keys.PROXY_PORT:          "8080",
    Keys.UPSTREAM_PROXY:      "",
    Keys.EDITOR_FONT_SIZE:    "9",
}
