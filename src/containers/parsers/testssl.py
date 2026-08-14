import json
import os

from containers.parsers._common import _read_json
from containers.results.models import VulnFinding


def _entries(value):
    if isinstance(value, list):
        for item in value:
            yield from _entries(item)
    elif isinstance(value, dict):
        if any(key in value for key in ("id", "finding", "severity", "cve")):
            yield value
        for key, child in value.items():
            if key not in {"scanResult", "scanresults", "results", "findings"}:
                continue
            yield from _entries(child)


def _severity(value: str) -> str:
    value = value.lower().strip()
    if value in {"critical", "high", "medium", "low", "info"}:
        return value
    if value in {"warn", "warning", "bad", "fail", "failed"}:
        return "medium"
    return "info"


def parse_testssl(output_dir: str) -> list[VulnFinding]:
    data = _read_json(os.path.join(output_dir, "testssl_results.json"))
    if data is None:
        return []
    results = []
    for index, entry in enumerate(_entries(data)):
        finding = str(entry.get("finding", entry.get("title", entry.get("description", ""))))
        status = str(entry.get("severity", entry.get("rating", entry.get("status", ""))))
        if not finding or status.lower() in {"ok", "not vulnerable", "pass", "passed"}:
            continue
        host = str(entry.get("fqdn", entry.get("host", entry.get("target", entry.get("ip", "")))))
        url = host if "://" in host else (f"https://{host}" if host else "")
        template_id = str(entry.get("id", entry.get("cve", f"testssl-{index}")))
        record = VulnFinding(
            template_id=f"testssl:{template_id}", name=finding,
            severity=_severity(status), url=url, matched=str(entry.get("ip", "")),
            description=str(entry.get("cve", entry.get("severity", ""))),
            tags=["tls", "testssl"],
        )
        record.add_source("testssl")
        results.append(record)
    return results
