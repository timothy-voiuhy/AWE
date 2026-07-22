# NOTE: this is the AWE parser for the "httpx" recon tool's output,
# unrelated to the httpx HTTP client library (this module lives under
# containers.parsers, not the top-level httpx package).
import json
import os
import re

from containers.parsers._common import _read_lines
from containers.results.models import LiveHost


def parse_httpx(output_dir: str) -> list[LiveHost]:
    results = []
    # httpx can output plain text or JSON; try JSON first
    for line in _read_lines(os.path.join(output_dir, "httpx_results.txt")):
        try:
            obj = json.loads(line)
            raw_cpe = obj.get("cpe", []) or []
            cpe_list = [
                c["cpe"] if isinstance(c, dict) else c
                for c in raw_cpe if c
            ]
            r = LiveHost(
                url=obj.get("url", ""),
                status_code=obj.get("status_code", 0),
                title=obj.get("title", ""),
                technologies=obj.get("tech", []) or [],
                content_length=obj.get("content_length", 0),
                redirect_url=obj.get("location", ""),
                host=obj.get("host", ""),
                host_ip=obj.get("host_ip", ""),
                ip_addresses=obj.get("a", []) or [],
                ipv6_addresses=obj.get("aaaa", []) or [],
                cname=obj.get("cname", []) or [],
                webserver=obj.get("webserver", ""),
                scheme=obj.get("scheme", ""),
                port=str(obj.get("port", "")),
                words=obj.get("words", 0),
                lines=obj.get("lines", 0),
                cdn=bool(obj.get("cdn", False)),
                cdn_name=obj.get("cdn_name", ""),
                cdn_type=obj.get("cdn_type", ""),
                cpe=cpe_list,
            )
        except json.JSONDecodeError:
            # plain text: "https://example.com [200] [Title]"
            m = re.match(r"^(https?://\S+)\s+\[(\d+)\]\s*(?:\[([^\]]*)\])?", line)
            if not m:
                continue
            r = LiveHost(url=m.group(1), status_code=int(m.group(2)),
                         title=m.group(3) or "")
        if r.url:
            r.add_source("httpx")
            results.append(r)
    return results
