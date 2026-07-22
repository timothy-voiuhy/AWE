import os
import re

from containers.parsers._common import _read_lines
from containers.results.models import PortResult


def parse_naabu(output_dir: str) -> list[PortResult]:
    results = []
    for line in _read_lines(os.path.join(output_dir, "naabu_results.txt")):
        m = re.match(r"^([^:]+):(\d+)", line)
        if m:
            r = PortResult(host=m.group(1), port=int(m.group(2)), state="open")
            r.add_source("naabu")
            results.append(r)
    return results
