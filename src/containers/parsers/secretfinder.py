import os
import re

from containers.parsers._common import _read_lines
from containers.results.models import VulnFinding

_SECRET_RE = re.compile(
    r"\[(?:CRITICAL|HIGH|MEDIUM|LOW|INFO)\]\s*(.+?):\s*(.+)", re.I
)


def parse_secretfinder(output_dir: str) -> list[VulnFinding]:
    results = []
    for line in _read_lines(os.path.join(output_dir, "secretfinder_results.txt")):
        m = _SECRET_RE.match(line)
        if not m:
            continue
        secret_type = m.group(1).strip()
        value       = m.group(2).strip()
        sev_m = re.match(r"\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]", line, re.I)
        sev_map = {"critical": "critical", "high": "high",
                   "medium": "medium", "low": "low", "info": "info"}
        sev = sev_map.get((sev_m.group(1).lower() if sev_m else ""), "medium")
        r = VulnFinding(
            template_id="secretfinder",
            name=f"Exposed Secret: {secret_type}",
            severity=sev,
            url="",
            matched=value[:120],
            description=f"{secret_type} found in JavaScript: {value[:200]}",
            tags=["secrets", "exposure", "js"],
        )
        r.add_source("secretfinder")
        results.append(r)
    return results
