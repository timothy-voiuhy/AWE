import os

from containers.parsers._common import _read_lines
from containers.results.models import VulnFinding


def parse_jwt_tool(output_dir: str) -> list[VulnFinding]:
    results = []
    keywords = [
        "vulnerable", "accepted", "success", "alg:none", "claim",
        "invalid", "expired", "forged", "bypass", "confusion",
    ]
    for line in _read_lines(os.path.join(output_dir, "jwt_tool_output.txt")):
        if any(kw in line.lower() for kw in keywords):
            r = VulnFinding(
                template_id="jwt_tool",
                name="JWT Finding",
                severity="high",
                url="",
                matched=line.strip(),
                description=line.strip(),
                tags=["jwt"],
            )
            r.add_source("jwt_tool")
            results.append(r)
    return results
