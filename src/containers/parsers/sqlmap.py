import re
from pathlib import Path

from containers.parsers._common import _read_lines
from containers.results.models import VulnFinding

_INJECT_RE = re.compile(
    r"(parameter\s+'?([^']+)'?\s+is\s+'([^']+)'\s+injectable"
    r"|identified the following injection point"
    r"|Type:\s+(.+))",
    re.I,
)


def parse_sqlmap(output_dir: str) -> list[VulnFinding]:
    results = []
    for log_file in Path(output_dir).rglob("log"):
        current_target = ""
        for line in _read_lines(str(log_file)):
            target_m = re.search(r"testing URL\s+'?(https?://\S+?)'?$", line, re.I)
            if target_m:
                current_target = target_m.group(1)
            if _INJECT_RE.search(line):
                r = VulnFinding(
                    template_id="sqlmap",
                    name="SQL Injection",
                    severity="critical",
                    url=current_target,
                    matched=line.strip(),
                    description=line.strip(),
                    tags=["sqli", "cwe-89"],
                )
                r.add_source("sqlmap")
                results.append(r)
    return results
