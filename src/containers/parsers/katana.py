import os

from containers.parsers._common import _read_jsonl, _parse_url_lines, _URL_RE
from containers.results.models import EndpointResult


def parse_katana(output_dir: str) -> list[EndpointResult]:
    results = []
    for obj in _read_jsonl(os.path.join(output_dir, "katana_results.txt")):
        url = obj.get("request", {}).get("endpoint", "") or obj.get("endpoint", "")
        method = obj.get("request", {}).get("method", "GET")
        ct = obj.get("response", {}).get("headers", {}).get("content-type", "")
        status = obj.get("response", {}).get("status_code", 0)
        if url and _URL_RE.match(url):
            r = EndpointResult(url=url.rstrip("/"), method=method,
                               status_code=status, content_type=ct.split(";")[0])
            r.add_source("katana")
            results.append(r)
    # also handle plain URL per line
    if not results:
        results = _parse_url_lines(
            os.path.join(output_dir, "katana_results.txt"), "katana"
        )
    return results
