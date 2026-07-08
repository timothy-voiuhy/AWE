"""
Scope model for AWE.

ScopeConfig is the single source of truth for what is in/out of scope
for a given project.  It is stored in MongoDB (via AweRepository) and
read by the SiteMap, the pipeline executor, and the proxy traffic filter.

Entry types
-----------
domain   : "example.com"         — exact hostname match (+ subdomains if include_subdomains)
wildcard : "*.example.com"        — any subdomain at any depth, plus the apex
url      : "https://example.com/api" — host + path-prefix match
regex    : ".*\\.example\\.com"   — raw regex applied to the full host string

Out-of-scope entries are checked after in-scope and take priority.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit


# ── Entry ─────────────────────────────────────────────────────────────────────

@dataclass
class ScopeEntry:
    value: str
    entry_type: str = "domain"   # "domain" | "wildcard" | "url" | "regex"
    in_scope: bool = True        # False  → out-of-scope exclusion

    def to_dict(self) -> dict:
        return {"value": self.value, "entry_type": self.entry_type, "in_scope": self.in_scope}

    @staticmethod
    def from_dict(d: dict) -> "ScopeEntry":
        return ScopeEntry(
            value=d["value"],
            entry_type=d.get("entry_type", "domain"),
            in_scope=d.get("in_scope", True),
        )

    def to_pattern(self) -> re.Pattern:
        """Compile this entry to a regex pattern matched against a hostname."""
        t = self.entry_type
        v = self.value.strip()

        if t == "regex":
            return re.compile(v, re.IGNORECASE)

        if t == "wildcard":
            # "*.example.com" → matches "example.com" AND any subdomain at any
            # depth ("sub.example.com", "a.b.c.example.com", …) — a single
            # label (`[^.]+`) would wrongly stop matching past one level deep.
            apex = v.lstrip("*").lstrip(".")
            escaped = re.escape(apex)
            return re.compile(rf"^({escaped}|.+\.{escaped})$", re.IGNORECASE)

        if t == "url":
            parsed = urlsplit(v if "://" in v else "https://" + v)
            host = re.escape(parsed.hostname or v)
            path = re.escape(parsed.path.rstrip("/")) if parsed.path and parsed.path != "/" else ""
            if path:
                return re.compile(rf"^{host}(:\d+)?{path}", re.IGNORECASE)
            return re.compile(rf"^{host}(:\d+)?", re.IGNORECASE)

        # default: domain — exact hostname match
        escaped = re.escape(v)
        return re.compile(rf"^{escaped}$", re.IGNORECASE)


# ── Config ────────────────────────────────────────────────────────────────────

@dataclass
class ScopeConfig:
    entries: list[ScopeEntry] = field(default_factory=list)
    include_subdomains: bool = True

    # ── serialisation ─────────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        return {
            "entries": [e.to_dict() for e in self.entries],
            "include_subdomains": self.include_subdomains,
        }

    @staticmethod
    def from_dict(d: dict) -> "ScopeConfig":
        return ScopeConfig(
            entries=[ScopeEntry.from_dict(e) for e in d.get("entries", [])],
            include_subdomains=d.get("include_subdomains", True),
        )

    # ── matching ──────────────────────────────────────────────────────────────

    def matches(self, host_or_url: str) -> bool:
        """Return True if *host_or_url* is in scope (not explicitly excluded).

        An empty scope config matches everything (open scope).
        """
        if not self.entries:
            return True

        host = _extract_host(host_or_url)

        # url-type entries carry a path (e.g. "https://target.com/api") that
        # must be matched against the original string — reducing everything
        # to a bare hostname first (as domain/wildcard/regex entries want)
        # would make such an entry's path suffix unmatchable forever.
        def _subject(entry: ScopeEntry) -> str:
            return host_or_url if entry.entry_type == "url" else host

        in_entries  = [e for e in self.entries if e.in_scope]
        out_entries = [e for e in self.entries if not e.in_scope]

        # Out-of-scope exclusions win
        for entry in out_entries:
            try:
                if entry.to_pattern().search(_subject(entry)):
                    return False
            except re.error:
                continue

        if not in_entries:
            return True  # no explicit in-scope list → everything is in scope

        # Direct match
        for entry in in_entries:
            try:
                if entry.to_pattern().search(_subject(entry)):
                    return True
            except re.error:
                continue

        # Subdomain expansion for domain-type entries when include_subdomains=True
        if self.include_subdomains:
            for entry in in_entries:
                if entry.entry_type == "domain":
                    apex = re.escape(entry.value.strip())
                    if re.search(rf"(^|\.){apex}$", host, re.IGNORECASE):
                        return True

        return False

    def to_regex_patterns(self) -> list[str]:
        """Return a list of regex strings for in-scope hosts (for proxy filter)."""
        patterns: list[str] = []
        for entry in self.entries:
            if not entry.in_scope:
                continue
            try:
                patterns.append(entry.to_pattern().pattern)
                if self.include_subdomains and entry.entry_type == "domain":
                    apex = re.escape(entry.value.strip())
                    patterns.append(rf"(^|\.){apex}$")
            except re.error:
                pass
        return patterns or ["."]   # "." = match everything when scope is empty

    def _compiled(self, in_scope: bool) -> list[re.Pattern]:
        compiled = []
        for e in self.entries:
            if e.in_scope == in_scope:
                try:
                    compiled.append(e.to_pattern())
                except re.error:
                    pass
        return compiled


# ── helpers ───────────────────────────────────────────────────────────────────

def _extract_host(value: str) -> str:
    """Best-effort extraction of the hostname from a URL or bare host string."""
    if "://" in value:
        parsed = urlsplit(value)
        return parsed.hostname or value
    # strip path
    return value.split("/")[0].split(":")[0]
