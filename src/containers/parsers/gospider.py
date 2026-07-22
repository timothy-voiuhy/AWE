import json
import os

from containers.parsers._common import _read_lines, _URL_RE
from containers.results.models import EndpointResult


def parse_gospider(output_dir: str) -> list[EndpointResult]:
    results = []
    for line in _read_lines(os.path.join(output_dir, "gospider_results.txt")):
        try:
            obj = json.loads(line)
            url = obj.get("output", "")
            if _URL_RE.match(url):
                r = EndpointResult(url=url.rstrip("/"),
                                   status_code=obj.get("status", 0))
                r.add_source("gospider")
                results.append(r)
            # sub-urls
            for sub in obj.get("data", []):
                sub_url = sub if isinstance(sub, str) else sub.get("url", "")
                if _URL_RE.match(sub_url):
                    sr = EndpointResult(url=sub_url.rstrip("/"))
                    sr.add_source("gospider")
                    results.append(sr)
        except json.JSONDecodeError:
            if _URL_RE.match(line):
                r = EndpointResult(url=line.rstrip("/"))
                r.add_source("gospider")
                results.append(r)
    return results
