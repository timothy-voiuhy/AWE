import os

from containers.parsers._common import _read_json
from containers.results.models import VulnFinding


def parse_corsy(output_dir: str) -> list[VulnFinding]:
    results = []
    data = _read_json(os.path.join(output_dir, "corsy_results.json"))
    if not isinstance(data, dict):
        return results
    for url, detail in data.items():
        if not isinstance(detail, dict):
            continue
        cls = detail.get("class", "")
        if not cls or cls.lower() in ("not vulnerable", "secure"):
            continue
        origin = detail.get("origin", "")
        creds  = detail.get("credentials", False)
        sev    = "high" if creds else "medium"
        r = VulnFinding(
            template_id="corsy",
            name=f"CORS Misconfiguration: {cls}",
            severity=sev,
            url=url,
            matched=f"Reflected origin: {origin}, credentials: {creds}",
            description=(
                f"{cls} CORS policy on {url}. "
                f"Origin '{origin}' is reflected"
                + (" with credentials." if creds else ".")
            ),
            tags=["cors", "cwe-942"],
        )
        r.add_source("corsy")
        results.append(r)
    return results
