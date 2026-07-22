import os
import re

from containers.parsers._common import _read_lines
from containers.results.models import EndpointResult

_KR_RE = re.compile(
    r"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+\d+\s+\[.*?\]\s+(https?://\S+)", re.I
)


def parse_kiterunner(output_dir: str) -> list[EndpointResult]:
    results = []
    for line in _read_lines(os.path.join(output_dir, "kiterunner_results.txt")):
        m = _KR_RE.search(line)
        if not m:
            continue
        r = EndpointResult(url=m.group(2).rstrip("/"), method=m.group(1).upper())
        r.add_source("kiterunner")
        results.append(r)
    return results
