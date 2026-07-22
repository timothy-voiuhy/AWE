import os
import re

from containers.parsers._common import _read_lines
from containers.results.models import DNSRecord


def parse_dnsx(output_dir: str) -> list[DNSRecord]:
    results = []
    for line in _read_lines(os.path.join(output_dir, "dnsx_results.txt")):
        # dnsx format: "example.com [A] [1.2.3.4]"  or  "example.com A 1.2.3.4"
        m = re.match(
            r"^(\S+)\s+\[?([A-Z]+)\]?\s+\[?([^\]\s]+)\]?", line, re.IGNORECASE
        )
        if m:
            r = DNSRecord(name=m.group(1).lower(),
                          record_type=m.group(2).upper(),
                          value=m.group(3))
            r.add_source("dnsx")
            results.append(r)
    return results
