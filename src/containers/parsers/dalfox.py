import os

from containers.parsers._common import _read_jsonl
from containers.results.models import VulnFinding


def parse_dalfox(output_dir: str) -> list[VulnFinding]:
    results = []
    for obj in _read_jsonl(os.path.join(output_dir, "dalfox_results.txt")):
        raw_sev = obj.get("severity", obj.get("type", "medium"))
        sev_map = {"G": "high", "E": "medium", "HIGH": "high",
                   "MEDIUM": "medium", "LOW": "low"}
        severity = sev_map.get(str(raw_sev).upper(), "medium")
        url = obj.get("data", obj.get("url", ""))
        r = VulnFinding(
            template_id="dalfox",
            name="Cross-Site Scripting (XSS)",
            severity=severity,
            url=url,
            matched=obj.get("poc", obj.get("payload", url)),
            description=f"Param: {obj.get('param', '?')} — Payload: {obj.get('payload', '')}",
            tags=["xss", "cwe-79"],
        )
        r.add_source("dalfox")
        results.append(r)
    return results
