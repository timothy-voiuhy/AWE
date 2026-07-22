import os
import re

from containers.parsers._common import _read_lines
from containers.results.models import DNSRecord


def parse_metabigor(output_dir: str) -> list[DNSRecord]:
    results = []
    for line in _read_lines(os.path.join(output_dir, "metabigor_results.txt")):
        # metabigor: CIDR lines like "192.168.0.0/24" or ASN lines
        m_cidr = re.match(r"^(\d+\.\d+\.\d+\.\d+/\d+)", line)
        m_asn  = re.match(r"^(AS\d+)\s+(.*)", line, re.IGNORECASE)
        if m_cidr:
            r = DNSRecord(name="netblock", record_type="CIDR", value=m_cidr.group(1))
        elif m_asn:
            r = DNSRecord(name=m_asn.group(2).strip(), record_type="ASN",
                          value=m_asn.group(1).upper())
        else:
            r = DNSRecord(name=line, record_type="INFO", value="")
        r.add_source("metabigor")
        results.append(r)
    return results
