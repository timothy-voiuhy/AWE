import os

from containers.parsers._common import _parse_subdomain_lines
from containers.results.models import SubdomainResult


def parse_ctl(output_dir: str) -> list[SubdomainResult]:
    return _parse_subdomain_lines(
        os.path.join(output_dir, "ctl_results.txt"), "ctl"
    )
