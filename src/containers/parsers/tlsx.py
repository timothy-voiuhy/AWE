import json
import os

from containers.parsers._common import _read_lines
from containers.results.models import OSINTResult


def _list(value):
    if isinstance(value, list):
        return [str(item) for item in value if item]
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return []


def parse_tlsx(output_dir: str) -> list[OSINTResult]:
    results = []
    for line in _read_lines(os.path.join(output_dir, "tlsx_results.jsonl")):
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue
        host = str(obj.get("host", obj.get("input", obj.get("hostname", ""))))
        cn = str(obj.get("subject_cn", obj.get("cn", "")))
        sans = _list(obj.get("subject_an", obj.get("san", obj.get("subject_alt_names", []))))
        fingerprint = str(obj.get("sha256", obj.get("fingerprint", obj.get("serial", ""))))
        value = fingerprint or cn or host
        if not value:
            continue
        metadata = {
            "common_name": cn,
            "sans": sans,
            "organization": obj.get("subject_org", obj.get("organization", "")),
            "tls_version": obj.get("tls_version", obj.get("version", "")),
            "cipher": obj.get("cipher", ""),
            "sha256": obj.get("sha256", ""),
            "jarm": obj.get("jarm", ""),
            "ja3": obj.get("ja3", ""),
            "serial": obj.get("serial", ""),
            "probe_status": obj.get("probe_status", obj.get("status", "")),
            "expired": bool(obj.get("expired", False)),
            "self_signed": bool(obj.get("self_signed", False)),
            "mismatched": bool(obj.get("mismatched", False)),
            "untrusted": bool(obj.get("untrusted", False)),
        }
        record = OSINTResult(
            result_type="certificate", value=value, extra=cn or host,
            provider="tlsx", related_host=host, metadata=metadata,
        )
        record.add_source("tlsx")
        results.append(record)
    return results
