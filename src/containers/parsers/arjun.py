import os

from containers.parsers._common import _read_json
from containers.results.models import ParamResult


def parse_arjun(output_dir: str) -> list[ParamResult]:
    results = []
    data = _read_json(os.path.join(output_dir, "arjun_results.json"))
    if isinstance(data, dict):
        data = [data]
    if isinstance(data, list):
        for entry in data:
            if not isinstance(entry, dict):
                continue
            url = entry.get("url", "")
            method = entry.get("method", "GET")
            for param in entry.get("params", []):
                r = ParamResult(name=param, endpoint=url,
                                method=method, param_type="query")
                r.add_source("arjun")
                results.append(r)
    return results
