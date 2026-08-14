import glob
import json
import os
import re

from containers.parsers._common import _is_domain, _URL_RE
from containers.results.models import OSINTResult

_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def _record(kind: str, value: str, source_value: str = "") -> OSINTResult:
    record = OSINTResult(
        result_type=kind, value=value.strip(), provider="theharvester",
        metadata={"source": source_value} if source_value else {},
    )
    record.add_source("theharvester")
    return record


def parse_theharvester(output_dir: str) -> list[OSINTResult]:
    results = []
    files = glob.glob(os.path.join(output_dir, "theharvester_results*"))
    for path in files:
        if path.endswith(".json"):
            try:
                data = json.load(open(path, errors="replace"))
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(data, dict):
                continue
            for value in data.get("emails", []) or []:
                if isinstance(value, str) and _EMAIL_RE.match(value):
                    results.append(_record("email", value))
            for value in data.get("hosts", data.get("subdomains", [])) or []:
                if isinstance(value, str):
                    host = value.split(":", 1)[0]
                    if _is_domain(host):
                        results.append(_record("subdomain", host))
            for value in data.get("ips", []) or []:
                if isinstance(value, str) and _IP_RE.match(value):
                    results.append(_record("ip", value))
            for value in data.get("people", data.get("names", [])) or []:
                if isinstance(value, str) and value.strip():
                    results.append(_record("person", value))
            for value in data.get("interesting_urls", data.get("urls", [])) or []:
                if isinstance(value, str) and _URL_RE.match(value):
                    results.append(_record("url", value))
        else:
            try:
                lines = open(path, errors="replace").read().splitlines()
            except OSError:
                continue
            for raw in lines:
                value = raw.strip()
                if not value or value.startswith(("[", "-", "=")):
                    continue
                if _EMAIL_RE.match(value):
                    results.append(_record("email", value))
                elif _URL_RE.match(value):
                    results.append(_record("url", value))
                elif _is_domain(value):
                    results.append(_record("subdomain", value))
                elif _IP_RE.match(value):
                    results.append(_record("ip", value))
    return results
