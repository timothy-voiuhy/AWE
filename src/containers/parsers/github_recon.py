import os

from containers.parsers._common import _read_lines, _is_domain, _URL_RE
from containers.results.models import OSINTResult


def parse_github_recon(output_dir: str) -> list[OSINTResult]:
    results = []
    for line in _read_lines(os.path.join(output_dir, "github_recon_results.txt")):
        if _URL_RE.match(line):
            r = OSINTResult(result_type="github_endpoint", value=line, provider="github")
        elif _is_domain(line):
            r = OSINTResult(result_type="github_domain", value=line, provider="github")
        else:
            r = OSINTResult(result_type="github_match", value=line, provider="github")
        r.add_source("github_recon")
        results.append(r)
    return results
