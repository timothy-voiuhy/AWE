import json
import os

from containers.parsers._common import _read_json
from containers.results.models import OSINTResult


def parse_gitleaks(output_dir: str) -> list[OSINTResult]:
    data = _read_json(os.path.join(output_dir, "gitleaks_results.json"))
    if not isinstance(data, list):
        return []
    results = []
    for finding in data:
        if not isinstance(finding, dict):
            continue
        path = str(finding.get("File", finding.get("file", "")))
        line = str(finding.get("StartLine", finding.get("line", "")))
        rule = str(finding.get("RuleID", finding.get("rule_id", "unknown")))
        fingerprint = str(finding.get("Fingerprint", ""))
        value = fingerprint or f"{path}:{line}:{rule}"
        # Never persist the detected secret itself in the graph database.
        record = OSINTResult(
            result_type="secret", value=value, extra=rule,
            provider="gitleaks",
            metadata={
                "file": path,
                "line": line,
                "rule_id": rule,
                "commit": finding.get("Commit", finding.get("commit", "")),
                "author": finding.get("Author", finding.get("author", "")),
                "redacted": True,
            },
        )
        record.add_source("gitleaks")
        results.append(record)
    return results
