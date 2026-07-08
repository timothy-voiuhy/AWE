"""Static-asset detection for the Results page's Endpoints/Parameters tables.

CSS, JS, image, font, and media requests are rarely interesting from an
attack-surface standpoint and tend to dominate crawl/parameter output by
sheer volume, so the Results page hides them by default (toggle: "Hide
Static Assets"). This is a display-time filter — it doesn't affect what gets
captured/stored, and is independent of proxy.traffic_extractor's own
narrower static-extension set (used there for CDN cache-behaviour
classification, a different concern).
"""
from pathlib import PurePosixPath
from urllib.parse import urlsplit

STATIC_ASSET_EXTS: frozenset[str] = frozenset({
    ".css", ".scss", ".less", ".sass",
    ".js", ".mjs", ".jsx",
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".webp", ".bmp", ".avif", ".tiff",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp4", ".mp3", ".avi", ".wav", ".ogg", ".flac", ".mkv", ".webm", ".mov",
    ".map",
})


def is_static_asset(url: str) -> bool:
    """True if url's path ends in a known static-asset extension."""
    if not url:
        return False
    path = urlsplit(url).path if "://" in url else url
    ext = PurePosixPath(path).suffix.lower()
    return ext in STATIC_ASSET_EXTS
