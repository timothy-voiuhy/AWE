import os

from containers.parsers._common import _read_json
from containers.results.models import VulnFinding


def parse_wafw00f(output_dir: str) -> list[VulnFinding]:
    results = []
    data = _read_json(os.path.join(output_dir, "wafw00f_results.json"))
    entries = data if isinstance(data, list) else ([data] if isinstance(data, dict) else [])
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        url      = entry.get("url", "")
        detected = entry.get("detected", False)
        firewall = entry.get("firewall", "Unknown WAF")
        severity = "info" if detected else "info"
        r = VulnFinding(
            template_id="wafw00f",
            name=f"WAF Detected: {firewall}" if detected else "No WAF Detected",
            severity=severity,
            url=url,
            matched=firewall if detected else "none",
            description=(
                f"{firewall} is protecting {url}." if detected
                else f"No WAF detected in front of {url}."
            ),
            tags=["waf", "recon"],
        )
        r.add_source("wafw00f")
        results.append(r)
    return results
