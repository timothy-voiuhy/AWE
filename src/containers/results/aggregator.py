"""
Result aggregation engine.

Workflow:
  1. Scan output_dir for each tool's output file
  2. Parse into typed model objects (via parsers.py)
  3. Deduplicate within each tool (same tool, same key)
  4. Merge across tools within a category (combine sources)
  5. Return: per-tool results + merged combined results

Public API
──────────
  load_all(output_dir)             → CategoryResults for every category
  load_category(cat, output_dir)   → CategoryResults for one category
  CategoryResults.combined         → deduplicated, source-merged list
  CategoryResults.per_tool         → {tool_key: [results]} raw per-tool
  CategoryResults.stats            → {tool_key: count, "combined": count}
"""
import logging
from dataclasses import dataclass, field
from typing import Any

from containers.results.models import BaseResult
from containers.results.parsers import PARSERS
from containers.tool_registry import TOOL_CATEGORIES

logger = logging.getLogger(__name__)


def _dedup(results: list[BaseResult]) -> list[BaseResult]:
    """Deduplicate within a single list, merging sources of duplicates."""
    seen: dict[str, BaseResult] = {}
    for r in results:
        k = r.key
        if k in seen:
            seen[k].merge(r)
        else:
            seen[k] = r
    return list(seen.values())


def _merge_tool_results(tool_results: dict[str, list[BaseResult]]) -> list[BaseResult]:
    """Merge results from all tools, deduplicating by key across tools."""
    combined: dict[str, BaseResult] = {}
    for results in tool_results.values():
        for r in results:
            k = r.key
            if k in combined:
                combined[k].merge(r)
            else:
                # Store a shallow copy so per-tool data stays intact
                combined[k] = r
    return list(combined.values())


@dataclass
class CategoryResults:
    category: str
    per_tool: dict[str, list[BaseResult]] = field(default_factory=dict)
    combined: list[BaseResult] = field(default_factory=list)

    @property
    def stats(self) -> dict[str, int]:
        s = {tool: len(results) for tool, results in self.per_tool.items()}
        s["combined"] = len(self.combined)
        return s

    @property
    def total_unique(self) -> int:
        return len(self.combined)

    @property
    def total_raw(self) -> int:
        return sum(len(r) for r in self.per_tool.values())

    def has_results(self) -> bool:
        return bool(self.combined)


def load_category(category: str, output_dir: str) -> CategoryResults:
    """Parse and aggregate all tool outputs for a given category."""
    tool_keys = TOOL_CATEGORIES.get(category, [])
    per_tool: dict[str, list[BaseResult]] = {}

    for tool_key in tool_keys:
        parser = PARSERS.get(tool_key)
        if parser is None:
            continue
        try:
            results = parser(output_dir)
            if results:
                per_tool[tool_key] = _dedup(results)
                logger.debug("%s/%s: %d results", category, tool_key, len(per_tool[tool_key]))
        except Exception as exc:
            logger.warning("Parser %s failed: %s", tool_key, exc)

    combined = _merge_tool_results(per_tool)

    # Apply category-specific post-processing
    combined = _post_process(category, combined)

    return CategoryResults(
        category=category,
        per_tool=per_tool,
        combined=combined,
    )


def load_all(output_dir: str) -> dict[str, CategoryResults]:
    """Parse and aggregate all categories from tool output files."""
    results = {}
    for category in TOOL_CATEGORIES:
        cat_results = load_category(category, output_dir)
        results[category] = cat_results
    return results


def load_from_session(session_id: str, repo) -> dict[str, CategoryResults]:
    """
    Load all results for a session directly from MongoDB.
    Much faster than re-parsing files; sources are already merged.
    `repo` is an AweRepository instance.
    """
    from containers.results.models import CATEGORY_MODEL, result_from_dict

    all_results: dict[str, CategoryResults] = {}

    for category in CATEGORY_MODEL:
        docs = repo.get_results(session_id, category=category)
        if not docs:
            all_results[category] = CategoryResults(category=category)
            continue

        per_tool: dict[str, list[BaseResult]] = {}
        combined: list[BaseResult] = []

        for doc in docs:
            obj = result_from_dict(category, doc.get("data", {}), doc.get("sources", []))
            if obj is None:
                continue
            combined.append(obj)
            for source in obj.sources:
                per_tool.setdefault(source, []).append(obj)

        combined = _post_process(category, combined)
        all_results[category] = CategoryResults(
            category=category,
            per_tool=per_tool,
            combined=combined,
        )

    return all_results


# ── Category-specific post-processing ────────────────────────────────────────

def _post_process(category: str, results: list[BaseResult]) -> list[BaseResult]:
    if category == "subdomain":
        return _post_subdomains(results)
    if category == "crawl":
        return _post_endpoints(results)
    if category == "vuln":
        return _post_vulns(results)
    if category == "params":
        return _post_params(results)
    return results


def _post_subdomains(results):
    from containers.results.models import SubdomainResult
    import re
    valid = []
    seen_keys = set()
    for r in results:
        if not isinstance(r, SubdomainResult):
            continue
        k = r.key
        if not k or k in seen_keys:
            continue
        # Filter out obviously invalid entries
        if len(k) > 253 or " " in k:
            continue
        seen_keys.add(k)
        valid.append(r)
    # Sort: fewer dots (apex) first, then alphabetically
    valid.sort(key=lambda r: (r.domain.count("."), r.domain))
    return valid


def _post_endpoints(results):
    from containers.results.models import EndpointResult
    from urllib.parse import urlsplit, urlencode, parse_qsl, urlunparse
    import re

    seen_keys = set()
    filtered = []

    # Extensions to exclude (static assets)
    _STATIC_EXT = re.compile(
        r"\.(jpg|jpeg|gif|png|svg|webp|ico|woff|woff2|ttf|eot|css|map|pdf|zip|gz)$",
        re.IGNORECASE,
    )

    for r in results:
        if not isinstance(r, EndpointResult):
            filtered.append(r)
            continue
        url = r.url.strip()
        if not url or not url.startswith(("http://", "https://")):
            continue
        try:
            p = urlsplit(url)
            path = p.path.rstrip("/") or "/"
            if _STATIC_EXT.search(path):
                continue
            normalized = f"{p.scheme}://{p.netloc}{path}".lower()
        except Exception:
            normalized = url.lower()

        if normalized in seen_keys:
            # merge sources into existing
            for existing in filtered:
                if hasattr(existing, "key") and existing.key == r.key:
                    existing.merge(r)
                    break
            continue
        seen_keys.add(normalized)
        filtered.append(r)

    # Sort by host then path
    def _sort_key(r):
        try:
            p = urlsplit(r.url)
            return (p.netloc, p.path)
        except Exception:
            return (r.url, "")

    filtered.sort(key=_sort_key)
    return filtered


def _post_vulns(results):
    from containers.results.models import VulnFinding, SEVERITY_ORDER
    results.sort(key=lambda r: r.severity_order if isinstance(r, VulnFinding) else 99)
    return results


def _post_params(results):
    from containers.results.models import ParamResult
    # Sort: endpoint then param name
    results.sort(key=lambda r: (
        r.endpoint if isinstance(r, ParamResult) else "",
        r.name if isinstance(r, ParamResult) else "",
    ))
    return results


# ── Convenience: stats across all categories ──────────────────────────────────

def summary_stats(all_results: dict[str, CategoryResults]) -> dict[str, Any]:
    return {
        cat: {
            "unique": cr.total_unique,
            "raw": cr.total_raw,
            "tools_with_results": [t for t, r in cr.per_tool.items() if r],
        }
        for cat, cr in all_results.items()
    }
