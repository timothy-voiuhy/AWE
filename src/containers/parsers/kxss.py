import os
import re

from containers.parsers._common import _read_lines
from containers.results.models import VulnFinding


def parse_kxss(output_dir: str) -> list[VulnFinding]:
    results = []
    for line in _read_lines(os.path.join(output_dir, "kxss_results.txt")):
        url_m = re.search(r"(https?://\S+)", line)
        chars_m = re.search(r"chars?:\s*(.+)", line, re.I)
        if not url_m:
            continue
        chars = chars_m.group(1).strip() if chars_m else "unknown"
        r = VulnFinding(
            template_id="kxss",
            name="Reflected Parameter Detected",
            severity="medium",
            url=url_m.group(1),
            matched=line.strip(),
            description=f"Parameter reflected unescaped. Surviving chars: {chars}",
            tags=["xss", "reflection"],
        )
        r.add_source("kxss")
        results.append(r)
    return results
