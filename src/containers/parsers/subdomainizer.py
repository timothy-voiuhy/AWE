import os

from containers.parsers._common import _read_lines, _is_domain, _norm_domain
from containers.results.models import SubdomainResult


def parse_subdomainizer(output_dir: str) -> list[SubdomainResult]:
    results = []
    for candidate in ["subdomainizer_results.txt", "subdomainizerSubdomains.txt"]:
        for line in _read_lines(os.path.join(output_dir, candidate)):
            # SubDomainizer outputs one domain per line; skip URLs and secrets
            domain = _norm_domain(line)
            if _is_domain(domain):
                r = SubdomainResult(domain=domain)
                r.add_source("subdomainizer")
                results.append(r)
    return results
