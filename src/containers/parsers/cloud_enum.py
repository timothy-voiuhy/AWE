import os

from containers.parsers._common import _read_lines
from containers.results.models import OSINTResult


def parse_cloud_enum(output_dir: str) -> list[OSINTResult]:
    results = []
    provider_map = {"s3": "aws", "blob": "azure", "storage.googleapis": "gcp"}
    for line in _read_lines(os.path.join(output_dir, "cloud_enum_results.txt")):
        if not line or line.startswith("["):
            continue
        provider = "unknown"
        for keyword, prov in provider_map.items():
            if keyword in line.lower():
                provider = prov
                break
        r = OSINTResult(
            result_type="cloud_bucket",
            value=line,
            provider=provider,
        )
        r.add_source("cloud_enum")
        results.append(r)
    return results
