import os

from containers.parsers._common import _read_json, _read_lines
from containers.results.models import VulnFinding


def parse_subzy(output_dir: str) -> list[VulnFinding]:
    results = []
    data = _read_json(os.path.join(output_dir, "subzy_results.json"))
    if isinstance(data, list):
        for entry in data:
            if not isinstance(entry, dict):
                continue
            if not entry.get("vulnerable", False):
                continue
            subdomain = entry.get("subdomain", entry.get("target", ""))
            service   = entry.get("service", entry.get("fingerprint", ""))
            r = VulnFinding(
                template_id="subzy",
                name="Subdomain Takeover",
                severity="high",
                url=subdomain,
                matched=f"{subdomain} → {service}",
                description=f"Unclaimed {service} resource; subdomain may be hijacked.",
                tags=["takeover", "subdomain"],
            )
            r.add_source("subzy")
            results.append(r)
    else:
        for line in _read_lines(os.path.join(output_dir, "subzy_results.txt")):
            if "[VULNERABLE]" not in line.upper():
                continue
            r = VulnFinding(
                template_id="subzy",
                name="Subdomain Takeover",
                severity="high",
                url=line,
                matched=line.strip(),
                description=line.strip(),
                tags=["takeover", "subdomain"],
            )
            r.add_source("subzy")
            results.append(r)
    return results
