import json
import os

from containers.parsers._common import _read_json
from containers.results.models import LiveHost


def parse_whatweb(output_dir: str) -> list[LiveHost]:
    data = _read_json(os.path.join(output_dir, "whatweb_results.json"))
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        return []
    results = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        url = str(entry.get("target", entry.get("url", "")))
        if not url:
            continue
        plugins = entry.get("plugins", {}) or {}
        technologies = []
        if isinstance(plugins, dict):
            for name, details in plugins.items():
                version = ""
                if isinstance(details, list) and details and isinstance(details[0], dict):
                    versions = details[0].get("version", [])
                    version = "/".join(str(v) for v in versions) if isinstance(versions, list) else str(versions or "")
                technologies.append(f"{name} {version}".strip())
        record = LiveHost(
            url=url,
            status_code=int(entry.get("http_status", entry.get("status", 0)) or 0),
            title=str(entry.get("title", "")),
            technologies=technologies,
            webserver=str(entry.get("server", "")),
        )
        record.add_source("whatweb")
        results.append(record)
    return results
