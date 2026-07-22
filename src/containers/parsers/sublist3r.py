import os

from containers.parsers._common import _parse_subdomain_lines
from containers.results.models import SubdomainResult


def parse_sublist3r(output_dir: str) -> list[SubdomainResult]:
    results = []
    for candidate in ["sublist3r_results.txt", "sublisterSubdomains.txt"]:
        results.extend(_parse_subdomain_lines(
            os.path.join(output_dir, candidate), "sublist3r"
        ))
    return results
