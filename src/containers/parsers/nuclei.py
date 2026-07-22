import os

from containers.parsers._common import _read_jsonl
from containers.results.models import VulnFinding


def parse_nuclei(output_dir: str) -> list[VulnFinding]:
    results = []
    for obj in _read_jsonl(os.path.join(output_dir, "nuclei_results.jsonl")):
        info = obj.get("info", {})
        r = VulnFinding(
            template_id=obj.get("template-id", ""),
            name=info.get("name", obj.get("template-id", "")),
            severity=info.get("severity", "").lower(),
            url=obj.get("matched-at", obj.get("host", "")),
            matched=obj.get("matched-at", ""),
            description=info.get("description", ""),
            tags=info.get("tags", []) if isinstance(info.get("tags"), list)
                 else info.get("tags", "").split(","),
        )
        r.add_source("nuclei")
        results.append(r)
    return results
