"""Traffic helpers API handlers and helpers."""

from ..schemas import ScopeConfig
from ..schemas import TrafficEntry
from urllib.parse import urlsplit
import fnmatch
import re


def _traffic_entry(doc: dict) -> TrafficEntry:
    return TrafficEntry.model_validate({**doc, "id": str(doc["_id"])})


def _traffic_summary(doc: dict) -> TrafficEntry:
    """Build the list representation without transferring captured bodies.

    Traffic bodies can be hundreds of kilobytes each.  The list view only
    needs request/response metadata; the full document is still available
    through GET /traffic/{traffic_id} when the user selects an entry.
    """
    value = {**doc, "id": str(doc["_id"])}
    for field in ("request", "response"):
        message = dict(value.get(field) or {})
        body = message.pop("body", "")
        if isinstance(body, str):
            message["body_length"] = len(body.encode("utf-8"))
        message.pop("body_encoding", None)
        message.pop("body_truncated", None)
        if field == "request":
            message.pop("headers", None)
        else:
            headers = message.get("headers")
            if isinstance(headers, dict):
                message["headers"] = {
                    key: header_value
                    for key, header_value in headers.items()
                    if key.lower() in {"content-type", "content-length"}
                }
        value[field] = message
    return TrafficEntry.model_validate(value)


def _traffic_scope_host_patterns(target: str, scope: ScopeConfig) -> list[str]:
    """Build Mongo host regexes for unassigned external-device captures.

    External clients cannot always send the AWE project marker.  Restricting
    the Mongo query to scope candidates before sorting/limiting prevents a
    busy shared proxy from hiding the current project's traffic behind a
    global newest-record limit.  Final URL/path matching still happens in
    ``_traffic_belongs_to_project``.
    """
    patterns: list[str] = []

    def add_domain(value: str, subdomains: bool = True) -> None:
        host = value.strip().lower().lstrip("*.")
        if not host:
            return
        suffix = rf"(?:^|\.){re.escape(host)}$" if subdomains else rf"^{re.escape(host)}$"
        if suffix not in patterns:
            patterns.append(suffix)

    target_host = (urlsplit(target if "://" in target else f"https://{target}").hostname or "").lower()
    included = [entry for entry in scope.entries if entry.in_scope]
    if not included:
        add_domain(target_host, scope.include_subdomains)
        return patterns

    for entry in included:
        value = entry.value.strip()
        if entry.entry_type == "regex":
            try:
                re.compile(value, re.IGNORECASE)
            except re.error:
                continue
            patterns.append(value)
            continue
        if entry.entry_type == "url":
            host = (urlsplit(value if "://" in value else f"https://{value}").hostname or "").lower()
            add_domain(host, False)
            continue
        add_domain(value, entry.entry_type == "wildcard" or scope.include_subdomains)
    return patterns


def _traffic_project_query(
    project_id: str,
    target: str | None = None,
    scope: ScopeConfig | None = None,
) -> dict:
    """Match tagged traffic and scoped captures from unmarked devices."""
    unassigned: dict = {
        "$or": [
            {"project_id": None},
            {"project_id": {"$exists": False}},
        ]
    }
    if target and scope:
        patterns = _traffic_scope_host_patterns(target, scope)
        if patterns:
            unassigned["host"] = {"$regex": "|".join(f"(?:{pattern})" for pattern in patterns), "$options": "i"}
    return {"$or": [{"project_id": project_id}, unassigned]}


def _traffic_belongs_to_project(
    doc: dict,
    project_id: str,
    target: str,
    scope: ScopeConfig,
) -> bool:
    """Apply project isolation to a captured traffic document.

    A proxy-authenticated/embedded-browser capture has an explicit project
    marker and is accepted only for that exact project.  An unmarked capture
    can be shown as a convenience for external devices, but only if its URL
    is within the current project's scope.
    """
    marker = doc.get("project_id")
    if marker:
        return marker == project_id
    request = doc.get("request") or {}
    url = request.get("url") or f"https://{doc.get('host', '')}{doc.get('path', '/') or '/'}"
    return _host_in_project_scope(str(url), target, scope)


def _host_in_project_scope(url: str, target: str, scope: ScopeConfig) -> bool:
    host = (urlsplit(url).hostname or "").lower()
    if not host or urlsplit(url).scheme not in ("http", "https"):
        return False
    target_host = (urlsplit(target if "://" in target else f"https://{target}").hostname or "").lower()
    excluded = [entry.value.lower().lstrip("*.") for entry in scope.entries if not entry.in_scope]
    if any(host == value or host.endswith(f".{value}") for value in excluded):
        return False
    included = [entry for entry in scope.entries if entry.in_scope]
    if not included:
        return host == target_host or (scope.include_subdomains and host.endswith(f".{target_host}"))
    for entry in included:
        value = entry.value
        if entry.entry_type == "url" and url.startswith(value): return True
        if entry.entry_type == "wildcard" and fnmatch.fnmatch(host, value.lower()): return True
        if entry.entry_type == "regex":
            try:
                if re.search(value, host, re.IGNORECASE): return True
            except re.error:
                continue
        domain = value.lower().lstrip("*.")
        if host == domain or (scope.include_subdomains and host.endswith(f".{domain}")): return True
    return False
