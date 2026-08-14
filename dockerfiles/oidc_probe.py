#!/usr/bin/env python3
"""Safe OIDC discovery probe; it performs one metadata GET only."""
import argparse
import json
import ssl
import urllib.request


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("issuer")
    parser.add_argument("--output", default="/output/oidc_results.json")
    args = parser.parse_args()
    issuer = args.issuer.rstrip("/")
    url = issuer if issuer.endswith("/.well-known/openid-configuration") else issuer + "/.well-known/openid-configuration"
    request = urllib.request.Request(url, headers={"User-Agent": "AWE-oidc-probe/1.0"})
    with urllib.request.urlopen(request, timeout=15, context=ssl.create_default_context()) as response:
        data = json.loads(response.read().decode("utf-8", errors="replace"))
        data["issuer_url"] = url
        data["http_status"] = response.status
    with open(args.output, "w") as handle:
        json.dump(data, handle)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
