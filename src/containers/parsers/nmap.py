import os
import re

from containers.parsers._common import _read_lines
from containers.results.models import PortResult


def parse_nmap(output_dir: str) -> list[PortResult]:
    results = []
    lines = _read_lines(os.path.join(output_dir, "nmap_results.txt"))
    current_host = ""
    for line in lines:
        host_m = re.match(r"Nmap scan report for (\S+)", line)
        if host_m:
            current_host = host_m.group(1).strip("()")
            continue
        port_m = re.match(
            r"^(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+(\S+)\s*(.*)", line
        )
        if port_m and current_host:
            r = PortResult(
                host=current_host,
                port=int(port_m.group(1)),
                protocol=port_m.group(2),
                state=port_m.group(3),
                service=port_m.group(4),
                version=port_m.group(5).strip(),
            )
            r.add_source("nmap")
            results.append(r)
    return results
