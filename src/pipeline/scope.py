"""
Scope filtering for pipeline results.

in_scope patterns:  fnmatch-style — "*.example.com", "example.com"
out_of_scope:       same — checked first, takes priority

Empty in_scope list means "everything is in scope" (only exclusions apply).
"""
import fnmatch
from urllib.parse import urlsplit


def _extract_host(value: str) -> str:
    """Extract hostname from a URL or return as-is if already a domain/IP."""
    if value.startswith(("http://", "https://")):
        try:
            return urlsplit(value).hostname or value
        except Exception:
            pass
    return value.split(":")[0]  # strip port


def is_in_scope(
    value: str,
    in_scope: list[str],
    out_of_scope: list[str],
) -> bool:
    host = _extract_host(value).lower()

    for pattern in out_of_scope:
        if fnmatch.fnmatch(host, pattern.lower()):
            return False

    if not in_scope:
        return True

    for pattern in in_scope:
        if fnmatch.fnmatch(host, pattern.lower()):
            return True

    return False


def filter_values(
    values: list[str],
    in_scope: list[str],
    out_of_scope: list[str],
) -> list[str]:
    if not in_scope and not out_of_scope:
        return values
    return [v for v in values if is_in_scope(v, in_scope, out_of_scope)]


def parse_scope_text(text: str) -> list[str]:
    """Parse a comma/newline-separated scope string into a list of patterns."""
    parts = []
    for part in text.replace(",", "\n").splitlines():
        p = part.strip()
        if p:
            parts.append(p)
    return parts
