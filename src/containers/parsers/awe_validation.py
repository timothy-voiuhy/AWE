"""Keep detector verification and redacted evidence in structured findings."""
import json
from pathlib import Path
from containers.results.models import VulnFinding


def parse_validation(output_dir):
    path = Path(output_dir) / "validation-report.json"
    if not path.is_file():
        return []
    report = json.loads(path.read_text())
    if report.get("schema_version") != 1 or not str(report.get("profile", "")).startswith("awe_"):
        raise ValueError("Unsupported AWE validation report")
    requests = {record["id"]: record for record in report.get("requests", [])}
    results = []
    for finding in report.get("findings", [])[:1000]:
        verification = finding.get("verification")
        if verification not in {"candidate", "verified_behavior"}:
            raise ValueError("Validation finding has an unknown verification level")
        records = [requests[identity] for identity in finding.get("evidence_ids", []) if identity in requests]
        result = VulnFinding(template_id=f"{report['profile']}:{finding['rule']}", name=finding["title"], severity=finding["severity"], url=report.get("target_url") or (records[-1]["url"] if records else ""), description=finding.get("detail") or report.get("limitations", ""), tags=[*report.get("cwe", []), verification], verification=verification, evidence={"report": "validation-report.json", "outcome": report.get("outcome"), "requests": records, "facts": finding.get("facts", {})})
        result.value = result.key
        result.add_source(report["profile"])
        results.append(result)
    return results
