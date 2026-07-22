import os
import re

from containers.parsers._common import _read_lines
from containers.results.models import ParamResult


def parse_parameth(output_dir: str) -> list[ParamResult]:
    results = []
    for line in _read_lines(os.path.join(output_dir, "parameth_results.txt")):
        # parameth: "Found parameter: name=value at URL"
        m = re.search(r"Found\s+parameter[:\s]+(\w+)(?:=\S+)?\s+at\s+(\S+)", line, re.I)
        if m:
            r = ParamResult(name=m.group(1), endpoint=m.group(2), method="GET")
            r.add_source("parameth")
            results.append(r)
        else:
            # plain "name=value" lines
            m2 = re.match(r"^([A-Za-z_]\w*)[=\s]", line)
            if m2:
                r = ParamResult(name=m2.group(1), endpoint="")
                r.add_source("parameth")
                results.append(r)
    return results
