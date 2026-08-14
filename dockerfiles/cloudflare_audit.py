#!/usr/bin/env python3
"""Read-only Cloudflare zone/DNS inventory for graph ingestion."""
import argparse
import json
import os
import sys

from cloudflare import Cloudflare


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--zone", default="", help="optional zone name")
    parser.add_argument("--output", default="/output/cloudflare_results.json")
    args = parser.parse_args()
    token = os.environ.get("CLOUDFLARE_API_TOKEN", "")
    if not token:
        print("CLOUDFLARE_API_TOKEN is required", file=sys.stderr)
        return 2
    client = Cloudflare(api_token=token)
    zones = []
    for zone in client.zones.list(name=args.zone or None, per_page=100):
        item = {
            "id": getattr(zone, "id", ""),
            "name": getattr(zone, "name", ""),
            "status": getattr(zone, "status", ""),
            "type": getattr(zone, "type", ""),
            "plan": getattr(getattr(zone, "plan", None), "name", ""),
            "account": getattr(getattr(zone, "account", None), "name", ""),
            "records": [],
        }
        zone_id = item["id"]
        if zone_id:
            for record in client.dns.records.list(zone_id=zone_id, per_page=100):
                item["records"].append({
                    "id": getattr(record, "id", ""),
                    "name": getattr(record, "name", ""),
                    "type": getattr(record, "type", ""),
                    "content": getattr(record, "content", ""),
                    "proxied": getattr(record, "proxied", False),
                    "ttl": getattr(record, "ttl", 0),
                })
        zones.append(item)
    with open(args.output, "w") as handle:
        json.dump({"zones": zones}, handle)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
