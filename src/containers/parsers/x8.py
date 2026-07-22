import os
import re

from containers.parsers._common import _read_lines
from containers.results.models import ParamResult


def parse_x8(output_dir: str) -> list[ParamResult]:
    results = []
    for line in _read_lines(os.path.join(output_dir, "x8_results.txt")):
        # x8 output: "param | endpoint | method | type"
        parts = [p.strip() for p in line.split("|")]
        if len(parts) >= 2:
            r = ParamResult(
                name=parts[0],
                endpoint=parts[1] if len(parts) > 1 else "",
                method=parts[2] if len(parts) > 2 else "GET",
                param_type=parts[3] if len(parts) > 3 else "query",
            )
            r.add_source("x8")
            results.append(r)
        elif re.match(r"^[A-Za-z_]\w*$", line):
            r = ParamResult(name=line, endpoint="")
            r.add_source("x8")
            results.append(r)
    return results
