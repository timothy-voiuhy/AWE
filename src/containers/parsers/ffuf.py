import os

from containers.parsers._common import _read_json
from containers.results.models import FuzzResult


def parse_ffuf(output_dir: str) -> list[FuzzResult]:
    results = []
    data = _read_json(os.path.join(output_dir, "ffuf_results.json"))
    if not data:
        return results
    base_url = data.get("commandline", "").replace("/FUZZ", "")
    for entry in data.get("results", []):
        url = entry.get("url", "")
        path = url.replace(base_url, "") if base_url else url
        r = FuzzResult(
            url=base_url.rstrip("/"),
            path=path.lstrip("/"),
            status_code=entry.get("status", 0),
            content_length=entry.get("length", 0),
            words=entry.get("words", 0),
            lines=entry.get("lines", 0),
            redirect_url=entry.get("redirectlocation", ""),
        )
        r.add_source("ffuf")
        results.append(r)
    return results
