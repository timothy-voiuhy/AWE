"""Graph-contract coverage for the Docker tool registry.

Every entity-producing tool must declare input_types + output_types so it
appears in the network graph (and reports graph_enabled=True in the tool
listing). This guards against a tool being added without graph contracts, and
against the registry drifting out of the graph vocabulary the ingest/edge layer
understands.
"""
import sys
from pathlib import Path

_LEGACY_SRC = Path(__file__).resolve().parents[2] / "src"
if str(_LEGACY_SRC) not in sys.path:
    sys.path.insert(0, str(_LEGACY_SRC))

from containers.tool_registry import TOOL_REGISTRY  # noqa: E402
from containers.parsers import PARSERS  # noqa: E402

# Tools that legitimately produce no graph entity (a wordlist is an artifact,
# not a node). Kept explicit so a regression here is a conscious decision.
NON_GRAPH_TOOLS = {"cewl"}

# The node-type vocabulary the graph ingest/edge layer resolves. A tool may only
# advertise types drawn from this set; anything else would land as an untyped
# "discovered_by" node and signals a typo or an unmodelled entity.
GRAPH_VOCABULARY = {
    "target", "domain", "subdomain", "ip", "url", "endpoint", "port", "param",
    "dns_record", "tech", "technology", "cdn", "screenshot",
    "vuln", "vulnerability", "misconfiguration", "secret", "repository", "file",
    "osint", "asn", "netblock", "certificate", "tls_finding",
    "email", "person", "organization", "token",
    "cloud_asset", "cloud_resource", "cloud_bucket", "cloud_finding",
    "cloud_account", "cloudflare_zone",
    "platform", "component", "identity", "identity_provider", "oidc_endpoint",
    "cluster", "workload", "container_image",
}


def _graph_enabled(key, tool):
    return bool(getattr(tool, "input_types", ()) and getattr(tool, "output_types", ()) and key in PARSERS)


def test_every_entity_tool_is_graph_enabled():
    missing = sorted(
        key for key, tool in TOOL_REGISTRY.items()
        if key not in NON_GRAPH_TOOLS and not _graph_enabled(key, tool)
    )
    assert not missing, f"tools missing graph contracts: {missing}"


def test_non_graph_tools_declare_no_contracts():
    # If one of these ever gains real entity output, move it out of the set
    # deliberately rather than letting it drift in silently.
    for key in NON_GRAPH_TOOLS:
        tool = TOOL_REGISTRY[key]
        assert not getattr(tool, "input_types", ()), f"{key} unexpectedly declares input_types"
        assert not getattr(tool, "output_types", ()), f"{key} unexpectedly declares output_types"


def test_contract_types_are_within_the_known_vocabulary():
    bad = {}
    for key, tool in TOOL_REGISTRY.items():
        unknown = (set(getattr(tool, "input_types", ())) | set(getattr(tool, "output_types", ()))) - GRAPH_VOCABULARY
        if unknown:
            bad[key] = sorted(unknown)
    assert not bad, f"tools advertising unknown graph types: {bad}"


def test_graph_enabled_coverage_is_complete():
    enabled = [k for k, t in TOOL_REGISTRY.items() if _graph_enabled(k, t)]
    assert len(enabled) == len(TOOL_REGISTRY) - len(NON_GRAPH_TOOLS)


# Tools that actively probe, brute-force, fuzz, or exploit the target must be
# gated behind explicit approval (execution_mode in the active/high_risk set).
APPROVAL_REQUIRED = {
    "nmap", "naabu", "nuclei", "arjun", "ffuf", "sqlmap", "dalfox",
    "kiterunner", "shuffledns", "x8", "parameth",
    "prowler", "kubescape", "cloudflare_audit",
}
# Tools that must never silently reach out and touch the target.
PASSIVE_ONLY = {
    "subfinder", "amass", "assetfinder", "ctl", "sublist3r", "metabigor",
    "gau", "waybackurls", "github_recon", "cloud_enum", "asnmap",
    "theharvester", "gitleaks", "dnsx",
}


def test_intrusive_tools_require_approval():
    not_gated = sorted(
        k for k in APPROVAL_REQUIRED
        if getattr(TOOL_REGISTRY[k], "execution_mode", "passive") not in {"active", "high_risk"}
    )
    assert not not_gated, f"intrusive tools not behind the approval gate: {not_gated}"


def test_passive_tools_stay_passive():
    leaked = sorted(
        k for k in PASSIVE_ONLY
        if getattr(TOOL_REGISTRY[k], "execution_mode", "passive") != "passive"
    )
    assert not leaked, f"passive tools marked as target-contacting: {leaked}"
