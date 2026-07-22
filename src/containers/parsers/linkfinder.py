import os

from containers.parsers._common import _read_lines, _URL_RE
from containers.results.models import EndpointResult


def parse_linkfinder(output_dir: str) -> list[EndpointResult]:
    results = []
    for candidate in ["linkfinder_results.txt", "linkFinder_Subdomains.txt"]:
        for line in _read_lines(os.path.join(output_dir, candidate)):
            if _URL_RE.match(line):
                r = EndpointResult(url=line.rstrip("/"))
            elif line.startswith("/"):
                r = EndpointResult(url=line)   # relative path
            else:
                continue
            r.add_source("linkfinder")
            results.append(r)
    return results
