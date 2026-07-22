import os

from containers.parsers._common import _read_lines, _URL_RE
from containers.results.models import EndpointResult


def parse_xnlinkfinder(output_dir: str) -> list[EndpointResult]:
    results = []
    for line in _read_lines(os.path.join(output_dir, "xnlinkfinder_results.txt")):
        if _URL_RE.match(line):
            r = EndpointResult(url=line.rstrip("/"))
        elif line.startswith("/"):
            r = EndpointResult(url=line)
        else:
            continue
        r.add_source("xnlinkfinder")
        results.append(r)
    return results
