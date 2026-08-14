"""
User-registered custom tools.

A custom tool lives on disk under CUSTOM_TOOLS_DIR/<key>/ as:
  tool.json   — metadata (display_name, category, image, command_template, param_specs, ...)
  Dockerfile  — built automatically on first run if the image isn't present
  parser.py   — must define parse(output_dir: str) -> list[BaseResult]

Registering a tool mutates TOOL_REGISTRY / TOOL_CATEGORIES (from
containers.tool_registry) and PARSERS (from containers.parsers) IN PLACE —
those are shared dict objects every other module already holds a reference
to via `from ... import TOOL_REGISTRY` etc., so in-place mutation (never
reassignment) is what makes a newly-registered tool immediately visible
everywhere (Docker Manager's Images/Launch tabs, the pipeline executor)
without an app restart.

load_custom_tools() is called once at app startup (see awe.py) and is
best-effort: one tool with a broken tool.json is skipped and logged, it
never aborts the scan or crashes the app. A tool whose parser.py fails to
import is still registered in TOOL_REGISTRY (so it's buildable/runnable)
but left out of PARSERS — the pipeline executor already tolerates a missing
parser (zero structured results, no crash).

register_custom_tool() is the interactive path used by the "Add Custom
Tool" dialog: unlike the startup scan, it raises on any failure (bad
tool.json OR a broken parser) so the GUI can show the error inline before
anything gets registered into memory.
"""
import importlib.util
import json
import logging
import os
import re
import shutil
from dataclasses import dataclass, field

from config.config import CUSTOM_TOOLS_DIR
from containers.parsers import PARSERS
from containers.results.models import CATEGORY_MODEL
from containers.tool_registry import ToolConfig, TOOL_CATEGORIES, TOOL_REGISTRY

logger = logging.getLogger(__name__)

_KEY_RE = re.compile(r"^[a-z0-9_]+$")

# Populated by load_custom_tools(); (tool_dir, error_message) for every
# directory under CUSTOM_TOOLS_DIR that failed to load at startup.
_LOAD_ERRORS: list[tuple[str, str]] = []


class _SafeDict(dict):
    """format_map() helper — missing placeholders render as "" instead of
    raising KeyError, since a custom tool's command_template may reference
    only a subset of its declared param_specs at runtime."""

    def __missing__(self, key):
        return ""


def slugify_key(text: str) -> str:
    """Best-effort key derivation from a display name, e.g. for GUI live-preview."""
    slug = re.sub(r"[^a-z0-9_]+", "_", text.strip().lower()).strip("_")
    return slug or "tool"


@dataclass
class CustomToolConfig(ToolConfig):
    """A ToolConfig built at runtime from user-supplied metadata, rather
    than a hand-authored @dataclass subclass like the built-in tools."""
    key: str = ""
    display_name: str = ""
    image: str = ""
    command_template: str = ""
    param_specs: list = field(default_factory=list)
    tool_dir: str = ""
    parser_path: str = ""

    def build_command(self, **kwargs) -> str:
        return self.command_template.format_map(_SafeDict(**kwargs))

    def param_spec(self) -> list[dict]:
        return self.param_specs


def _load_one(tool_dir: str, strict_parser: bool) -> str:
    """Load one custom tool directory, mutating TOOL_REGISTRY/TOOL_CATEGORIES/
    PARSERS in place. Returns the registered key. Raises on any tool.json
    problem; raises on a parser.py problem only when strict_parser=True."""
    tool_json_path = os.path.join(tool_dir, "tool.json")
    with open(tool_json_path) as f:
        meta = json.load(f)

    key = (meta.get("key") or "").strip() or os.path.basename(tool_dir.rstrip("/\\"))
    if not _KEY_RE.match(key):
        raise ValueError(
            f"invalid tool key {key!r} — must be lowercase letters, digits, underscore only"
        )
    category = meta.get("category", "")
    if category not in CATEGORY_MODEL:
        raise ValueError(
            f"unknown category {category!r} — must be one of {sorted(CATEGORY_MODEL)}"
        )
    display_name = meta.get("display_name") or key

    dockerfile_path = os.path.join(tool_dir, meta.get("dockerfile") or "Dockerfile")
    parser_path = os.path.join(tool_dir, meta.get("parser_file") or "parser.py")

    parse_fn = None
    if os.path.exists(parser_path):
        try:
            module_name = f"awe_custom_parser_{key}"
            spec = importlib.util.spec_from_file_location(module_name, parser_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            candidate = getattr(module, "parse", None)
            if not callable(candidate):
                raise ValueError("parser.py has no callable parse(output_dir) function")
            parse_fn = candidate
        except Exception as exc:
            if strict_parser:
                raise
            logger.warning("Custom tool %r parser failed to load: %s", key, exc)
            parse_fn = None
    elif strict_parser:
        raise FileNotFoundError(f"parser file not found: {parser_path}")

    cfg = CustomToolConfig(
        key=key,
        display_name=display_name,
        image=meta.get("image") or f"awe/custom_{key}",
        description=meta.get("description", ""),
        category=category,
        dockerfile=dockerfile_path if os.path.exists(dockerfile_path) else None,
        command_template=meta.get("command_template", ""),
        param_specs=meta.get("param_specs", []),
        input_types=tuple(meta.get("input_types", []) or ()),
        output_types=tuple(meta.get("output_types", []) or ()),
        relationship_types=tuple(meta.get("relationship_types", []) or ()),
        execution_mode=str(meta.get("execution_mode", "passive")),
        credential_fields=tuple(meta.get("credential_fields", []) or ()),
        tool_dir=tool_dir,
        parser_path=parser_path,
    )

    # In-place mutation only — never reassign TOOL_REGISTRY / TOOL_CATEGORIES
    # / PARSERS, every other module already holds a reference to these same
    # dict objects and would not see a rebound name.
    old = TOOL_REGISTRY.get(key)
    if isinstance(old, CustomToolConfig) and old.category != category:
        old_bucket = TOOL_CATEGORIES.get(old.category)
        if old_bucket and key in old_bucket:
            old_bucket.remove(key)
    TOOL_REGISTRY[key] = cfg
    bucket = TOOL_CATEGORIES.setdefault(category, [])
    if key not in bucket:
        bucket.append(key)

    if parse_fn is not None:
        PARSERS[key] = parse_fn
    else:
        PARSERS.pop(key, None)

    return key


def load_custom_tools() -> None:
    """Best-effort scan of CUSTOM_TOOLS_DIR — call once at app startup.
    Never raises; a tool that fails to load is skipped and recorded in
    _LOAD_ERRORS rather than aborting the scan."""
    _LOAD_ERRORS.clear()
    if not os.path.isdir(CUSTOM_TOOLS_DIR):
        return
    for name in sorted(os.listdir(CUSTOM_TOOLS_DIR)):
        tool_dir = os.path.join(CUSTOM_TOOLS_DIR, name)
        if not os.path.isdir(tool_dir):
            continue
        try:
            _load_one(tool_dir, strict_parser=False)
        except Exception as exc:
            logger.warning("Skipping custom tool at %s: %s", tool_dir, exc)
            _LOAD_ERRORS.append((tool_dir, str(exc)))


def register_custom_tool(tool_dir: str) -> str:
    """Interactive registration — raises on any failure (bad tool.json,
    unknown category, or a parser.py that fails to import / lacks parse())
    so the GUI can show the error without leaving a half-registered tool
    in memory."""
    return _load_one(tool_dir, strict_parser=True)


def remove_custom_tool(key: str) -> None:
    cfg = TOOL_REGISTRY.get(key)
    if not isinstance(cfg, CustomToolConfig):
        raise ValueError(f"{key!r} is not a registered custom tool")
    TOOL_REGISTRY.pop(key, None)
    bucket = TOOL_CATEGORIES.get(cfg.category)
    if bucket and key in bucket:
        bucket.remove(key)
    PARSERS.pop(key, None)
    if cfg.tool_dir and os.path.isdir(cfg.tool_dir):
        shutil.rmtree(cfg.tool_dir)


def list_custom_tools() -> list[dict]:
    """Metadata for the Custom Tools tab table — one row per registered
    tool, plus one row per on-disk directory that failed to load at all."""
    rows = []
    seen_dirs = set()
    for key, cfg in TOOL_REGISTRY.items():
        if not isinstance(cfg, CustomToolConfig):
            continue
        seen_dirs.add(os.path.normpath(cfg.tool_dir))
        rows.append({
            "key": key,
            "display_name": cfg.display_name,
            "category": cfg.category,
            "image": cfg.image,
            "dockerfile": cfg.dockerfile or "",
            "parser_path": cfg.parser_path,
            "tool_dir": cfg.tool_dir,
            "has_parser": key in PARSERS,
            "status": "ok" if key in PARSERS else "no parser",
        })

    if os.path.isdir(CUSTOM_TOOLS_DIR):
        for name in sorted(os.listdir(CUSTOM_TOOLS_DIR)):
            tool_dir = os.path.join(CUSTOM_TOOLS_DIR, name)
            norm = os.path.normpath(tool_dir)
            if not os.path.isdir(tool_dir) or norm in seen_dirs:
                continue
            err = next((msg for path, msg in _LOAD_ERRORS
                        if os.path.normpath(path) == norm), "failed to load")
            rows.append({
                "key": name, "display_name": name, "category": "", "image": "",
                "dockerfile": "", "parser_path": "", "tool_dir": tool_dir,
                "has_parser": False, "status": f"error: {err}",
            })
    return rows
