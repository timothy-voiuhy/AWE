import os

from containers.parsers._common import _read_lines, _URL_RE
from containers.results.models import VulnFinding


def parse_gxss(output_dir: str) -> list[VulnFinding]:
    results = []
    for line in _read_lines(os.path.join(output_dir, "gxss_results.txt")):
        if not _URL_RE.match(line):
            continue
        r = VulnFinding(
            template_id="gxss",
            name="Reflected Parameter Detected",
            severity="medium",
            url=line,
            matched=line,
            description="Parameter value reflected in response body.",
            tags=["xss", "reflection"],
        )
        r.add_source("gxss")
        results.append(r)
    return results
