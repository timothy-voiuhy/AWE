import json
import os

from containers.parsers._common import _read_lines
from containers.results.models import OSINTResult


def parse_s3scanner(output_dir: str) -> list[OSINTResult]:
    results = []
    for line in _read_lines(os.path.join(output_dir, "s3scanner_results.jsonl")):
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue
        bucket = str(obj.get("bucket", obj.get("name", obj.get("bucket_name", ""))))
        if not bucket:
            continue
        provider = str(obj.get("provider", "aws"))
        result = OSINTResult(
            result_type="cloud_bucket", value=bucket, provider=provider,
            extra=str(obj.get("status", obj.get("permissions", ""))),
            metadata={
                "provider": provider,
                "permissions": obj.get("permissions", obj.get("permission", {})),
                "region": obj.get("region", ""),
                "objects": obj.get("objects", obj.get("object_count", 0)),
            },
        )
        result.add_source("s3scanner")
        results.append(result)
    return results
