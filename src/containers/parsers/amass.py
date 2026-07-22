import os
import re

from containers.parsers._common import _read_lines, _is_domain, _norm_domain
from containers.results.models import SubdomainResult


def parse_amass(output_dir: str) -> list[SubdomainResult]:
    results = []
    # Docker output → /.config/amass/amass_.txt (mounted to output_dir)
    for candidate in ["amass_.txt", "amass_results.txt"]:
        for line in _read_lines(os.path.join(output_dir, candidate)):
            # amass output: "sub.example.com (FQDN) --> a_record --> 1.2.3.4"
            parts = line.split()
            if not parts:
                continue
            domain = _norm_domain(parts[0])
            if not _is_domain(domain):
                continue
            ip = ""
            if "-->" in line and len(parts) >= 5:
                ip = parts[-1] if re.match(r"\d+\.\d+\.\d+\.\d+", parts[-1]) else ""
            r = SubdomainResult(domain=domain, ip_addresses=[ip] if ip else [])
            r.add_source("amass")
            results.append(r)
    return results
