import json
import os
from pathlib import Path

from containers.parsers._common import _read_lines
from containers.results.models import VulnFinding


def parse_graphql_tools(output_dir: str) -> list:
    results = []
    keywords = [
        "graphql", "apollo", "hasura", "graphene", "strawberry", "dgraph",
        "ariadne", "juniper", "absinthe", "sangria", "lighthouse",
        "vulnerable", "found", "detected", "introspection", "error",
        "engine", "identified", "version",
    ]
    for line in _read_lines(os.path.join(output_dir, "fingerprint.txt")):
        if any(k in line.lower() for k in keywords):
            r = VulnFinding(
                template_id="graphql_tools",
                name="GraphQL Finding",
                severity="info",
                url="",
                matched=line.strip(),
                description=line.strip(),
                tags=["graphql"],
            )
            r.add_source("graphql_tools")
            results.append(r)

    schema_path = os.path.join(output_dir, "schema.json")
    if os.path.exists(schema_path):
        try:
            data = json.loads(Path(schema_path).read_text(errors="replace"))
            types = (data.get("data", {}).get("__schema", {}).get("types") or [])
            user_types = [t for t in types if t.get("name", "").startswith("__") is False]
            r = VulnFinding(
                template_id="graphql_schema",
                name="GraphQL Schema Discovered",
                severity="medium",
                url="",
                matched=f"{len(user_types)} types recovered via clairvoyance",
                description=f"Schema inferred via field-suggestion fuzzing: {len(user_types)} types found.",
                tags=["graphql", "schema", "discovery"],
            )
            r.add_source("graphql_tools")
            results.append(r)
        except Exception:
            pass

    return results
