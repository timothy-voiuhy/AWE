import ipaddress
import json
import os

from containers.parsers._common import _read_lines
from containers.results.models import OSINTResult


def _cidr(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def parse_asnmap(output_dir: str) -> list[OSINTResult]:
    results = []
    for line in _read_lines(os.path.join(output_dir, "asnmap_results.jsonl")):
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            if _cidr(line):
                record = OSINTResult(result_type="netblock", value=line, provider="asnmap")
                record.add_source("asnmap")
                results.append(record)
            continue

        if not isinstance(obj, dict):
            continue
        asn = str(obj.get("as_number", obj.get("asn", ""))).upper()
        org = str(obj.get("as_name", obj.get("organization", "")))
        target = str(obj.get("input", ""))
        country = str(obj.get("as_country", obj.get("country", "")))
        ranges = obj.get("as_range", obj.get("ranges", [])) or []
        if isinstance(ranges, str):
            ranges = [ranges]

        if asn:
            record = OSINTResult(
                result_type="asn", value=asn, extra=org, provider="asnmap",
                related_host=target,
                metadata={"country": country, "input": target, "ranges": ranges},
            )
            record.add_source("asnmap")
            results.append(record)
        for network in ranges:
            network = str(network).strip()
            if not _cidr(network):
                continue
            record = OSINTResult(
                result_type="netblock", value=network, extra=asn or org,
                provider="asnmap", related_host=target,
                metadata={"asn": asn, "organization": org, "country": country},
            )
            record.add_source("asnmap")
            results.append(record)
    return results
