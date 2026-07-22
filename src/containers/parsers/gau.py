import os

from containers.parsers._common import _parse_url_lines
from containers.results.models import EndpointResult


def parse_gau(output_dir: str) -> list[EndpointResult]:
    return _parse_url_lines(
        os.path.join(output_dir, "gau_results.txt"), "gau"
    )
