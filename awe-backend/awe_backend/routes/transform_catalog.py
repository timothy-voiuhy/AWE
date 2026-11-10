"""Transform catalog API handlers and helpers."""

from ..config import Settings
from ..schemas import GraphEntity
from ..schemas import TransformManifest
from dataclasses import asdict
from dataclasses import is_dataclass
from pathlib import Path
from urllib.parse import urlsplit
import json
import sys


_COMPOSITE_TRANSFORMS_FILE = ".awe-composite-transforms.json"


def _transform_seed(entity: GraphEntity, parameter: str) -> str:
    """Turn graph values into the input shape expected by legacy tools."""
    raw = entity.value or entity.label
    if parameter in {"domain", "host"}:
        candidate = str(raw).strip()
        parsed = urlsplit(candidate if "://" in candidate else f"https://{candidate}")
        return parsed.hostname or candidate.split("/", 1)[0]
    if parameter in {"url", "endpoint"}:
        candidate = str(raw).strip()
        return candidate if "://" in candidate else f"https://{candidate}"
    return str(raw)


def _project_transform_file(project_dir: Path) -> Path:
    return project_dir / _COMPOSITE_TRANSFORMS_FILE


def _load_project_transforms(project_dir: Path) -> list[TransformManifest]:
    path = _project_transform_file(project_dir)
    if not path.is_file():
        return []
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        return [TransformManifest.model_validate(item) for item in raw if isinstance(item, dict)]
    except (OSError, ValueError):
        return []


def _save_project_transforms(project_dir: Path, transforms: list[TransformManifest]) -> None:
    path = _project_transform_file(project_dir)
    path.write_text(json.dumps([item.model_dump(mode="json") for item in transforms], indent=2), encoding="utf-8")


def _default_composite_transforms(available: set[str]) -> list[TransformManifest]:
    enum_tools = [tool for tool in ("subfinder", "assetfinder", "amass", "ctl") if tool in available]
    if not enum_tools or "httpx" not in available:
        return []
    return [TransformManifest(
        id="composite:enumerate_subdomains",
        tool_key="composite:enumerate_subdomains",
        display_name="Enumerate subdomains",
        category="subdomain",
        description="Collect subdomains from multiple enumeration tools, tunnel the deduped list into httpx, and ingest only live hosts.",
        input_types=["target", "domain", "subdomain"],
        output_types=["subdomain"],
        relationship_types=["has_subdomain"],
        mode="safe_active",
        requires_approval=False,
        parameters=[
            {"key": "domain", "label": "Target domain", "type": "text", "default": ""},
            {"key": "flags", "label": "httpx extra flags", "type": "text", "default": ""},
        ],
        stages=[
            {"name": "Enumerate", "tool_keys": enum_tools, "input_source": "seed", "parameters": {}},
            {"name": "Live probe", "tool_keys": ["httpx"], "input_source": "previous", "parameters": {}},
        ],
    )]


def execution_options(tool) -> dict:
    return {"execution_kind": tool.execution_kind, "output_channels": list(tool.output_channels), "artifact_paths": list(tool.artifact_paths), "execution_timeout": tool.execution_timeout, "session_idle_timeout": tool.session_idle_timeout, "source_metadata": tool.source_metadata}


def _graph_transforms(settings: Settings, project_dir: Path | None = None) -> list[TransformManifest]:
    """Expose safe graph adapters over the existing Docker tool registry."""
    source = str(settings.legacy_src_dir)
    if source not in sys.path:
        sys.path.insert(0, source)
    try:
        from containers.tool_registry import TOOL_REGISTRY
    except Exception:
        TOOL_REGISTRY = {}
    # Curated display labels for the first-class recon transforms. Everything
    # else — input/output/relationship types and the risk mode that drives the
    # approval gate — is read from the tool registry, which is the single source
    # of truth (see tool_registry.ToolConfig). This keeps the graph adapter and
    # the /docker/tools listing from drifting apart.
    curated_labels = {
        "subfinder": "Subfinder subdomains", "amass": "Map related domains",
        "dnsx": "Resolve DNS records", "httpx": "Probe HTTP services",
        "naabu": "Discover open ports", "nmap": "Fingerprint services",
        "katana": "Crawl endpoints", "gospider": "Discover linked endpoints",
        "arjun": "Discover URL parameters", "nuclei": "Scan for vulnerabilities",
        "wafw00f": "Detect WAF and CDN", "gowitness": "Capture a screenshot",
        "github_recon": "Search GitHub intelligence", "cloud_enum": "Enumerate cloud assets",
        "asnmap": "Map ASN ownership and network ranges",
        "tlsx": "Collect TLS certificates and fingerprints",
        "testssl": "Assess TLS protocols and cryptographic weaknesses",
        "theharvester": "Collect email, name, IP, URL, and subdomain OSINT",
        "gitleaks": "Find redacted secrets in repository history",
        "whatweb": "Fingerprint web technologies and versions",
        "s3scanner": "Check cloud bucket permissions",
        "wpscan": "Enumerate WordPress components and findings",
        "droopescan": "Enumerate Drupal components and findings",
        "prowler": "Audit cloud, Kubernetes, GitHub, and identity posture",
        "kubescape": "Scan Kubernetes clusters, manifests, and images",
        "trivy": "Scan container images, repositories, filesystems, and IaC",
        "cloudflare_audit": "Inventory Cloudflare zones and DNS",
        "oidc_probe": "Discover OpenID Connect issuer metadata",
    }
    manifests: list[TransformManifest] = _default_composite_transforms(set(TOOL_REGISTRY))
    for key, label in curated_labels.items():
        tool = TOOL_REGISTRY.get(key)
        if not tool or not getattr(tool, "input_types", ()) or not getattr(tool, "output_channels", ()):
            continue
        mode = getattr(tool, "execution_mode", "passive")
        manifests.append(TransformManifest(
            **execution_options(tool),
            id=f"docker:{key}", tool_key=key, display_name=label,
            category=getattr(tool, "category", "Other") or "Other",
            description=getattr(tool, "description", ""),
            input_types=list(tool.input_types),
            output_types=list(tool.output_types),
            relationship_types=list(getattr(tool, "relationship_types", ())) or ["discovered_by"],
            mode=mode,
            requires_approval=mode in {"active", "high_risk"},
            parameters=tool.param_spec(),
        ))
        transform_path = getattr(tool, "tool_dir", "")
        if transform_path:
            manifest_file = Path(transform_path) / "transform.json"
            if manifest_file.is_file():
                try:
                    raw = json.loads(manifest_file.read_text(encoding="utf-8"))
                    manifests[-1] = TransformManifest.model_validate({**manifests[-1].model_dump(), **raw, "id": raw.get("id", f"docker:{key}"), "tool_key": key})
                except (OSError, ValueError):
                    pass
    # Custom tools opt into graph transforms by declaring graph contracts in
    # tool.json. They remain invisible to the graph until both input and
    # output types are present, which prevents an arbitrary Docker helper from
    # being mistaken for a typed transform.
    existing = {item.tool_key for item in manifests}
    for key, tool in TOOL_REGISTRY.items():
        if key in existing or not getattr(tool, "input_types", ()) or not getattr(tool, "output_channels", ()):
            continue
        manifests.append(TransformManifest(
            **execution_options(tool),
            id=f"docker:{key}", tool_key=key, display_name=tool.display_name,
            category=getattr(tool, "category", "Other") or "Other",
            description=getattr(tool, "description", ""),
            input_types=list(tool.input_types), output_types=list(tool.output_types),
            relationship_types=list(getattr(tool, "relationship_types", ())) or ["discovered_by"],
            mode=getattr(tool, "execution_mode", "passive"),
            requires_approval=getattr(tool, "execution_mode", "passive") in {"active", "high_risk"},
            parameters=tool.param_spec(),
        ))
    if project_dir is not None:
        custom = _load_project_transforms(project_dir)
        existing_ids = {item.id for item in manifests}
        manifests.extend(item for item in custom if item.id not in existing_ids)
    return manifests


def _graph_result_kind(data: dict, manifest: TransformManifest) -> str:
    """Resolve a parser result to the graph vocabulary advertised by a manifest."""
    raw = str(data.get("result_type") or data.get("kind") or "").strip()
    aliases = {"vulnerability": "vuln", "technology": "tech", "parameter": "param"}
    candidate = aliases.get(raw, raw)
    if candidate in manifest.output_types:
        return candidate
    if raw in manifest.output_types:
        return raw
    if len(manifest.output_types) == 1:
        return manifest.output_types[0]
    for option in manifest.output_types:
        if option in data or option.rstrip("s") in data:
            return option
    return manifest.output_types[0] if manifest.output_types else "custom"


def _graph_result_value(data: dict, kind: str = "") -> str:
    if kind == "subdomain":
        value = data.get("domain") or data.get("host") or data.get("value")
        if not value and data.get("url"):
            value = urlsplit(str(data["url"])).hostname or data["url"]
        return str(value or "")
    return str(data.get("value") or data.get("domain") or data.get("url") or data.get("name") or data.get("host") or data.get("label") or "")


def _graph_result_edge(kind: str) -> str:
    return {
        "subdomain": "has_subdomain",
        "platform": "runs", "component": "has_component", "vuln": "has_finding",
        "vulnerability": "has_finding", "misconfiguration": "has_finding",
        "cloud_asset": "has_cloud_asset", "cloud_resource": "has_resource",
        "cloud_account": "contains", "cloud_bucket": "has_cloud_asset",
        "cloud_finding": "has_cloud_finding", "cloudflare_zone": "contains",
        "dns_record": "has_dns", "cluster": "contains", "workload": "contains",
        "container_image": "uses_image", "identity": "has_identity",
        "identity_provider": "uses_identity_provider", "oidc_endpoint": "exposes",
        "certificate": "has_certificate", "tls_finding": "has_tls_finding",
        "asn": "announces", "netblock": "contains",
        "endpoint": "exposes", "secret": "contains_secret", "repository": "has_repository",
    }.get(kind, "discovered_by")


def _normalise_composite_results(manifest: TransformManifest, parsed: list) -> list:
    if not manifest.stages or manifest.output_types != ["subdomain"]:
        return parsed
    merged: dict[str, dict] = {}
    for result in parsed:
        data = asdict(result) if is_dataclass(result) else (result if isinstance(result, dict) else {"value": str(result)})
        host = str(data.get("domain") or data.get("host") or data.get("value") or "").strip().rstrip(".")
        if not host and data.get("url"):
            host = (urlsplit(str(data["url"])).hostname or "").strip().rstrip(".")
        if not host:
            continue
        row = merged.setdefault(host.lower(), {"kind": "subdomain", "domain": host, "value": host, "live": bool(data.get("url") or data.get("status_code")), "urls": [], "sources": []})
        if data.get("url") and data["url"] not in row["urls"]:
            row["urls"].append(data["url"])
        if data.get("status_code") and not row.get("status_code"):
            row["status_code"] = data["status_code"]
        if data.get("title") and not row.get("title"):
            row["title"] = data["title"]
        for source in data.get("sources", []) or []:
            if source and source not in row["sources"]:
                row["sources"].append(source)
    return list(merged.values())


def _redact_transform_params(manifest: TransformManifest, params: dict) -> tuple[dict, dict]:
    secret_keys = {str(item.get("key")) for item in manifest.parameters if item.get("type") == "secret" or item.get("default") == "secret"}
    return (
        {key: ("[redacted]" if key in secret_keys else value) for key, value in params.items()},
        {key: value for key, value in params.items() if key in secret_keys and value not in (None, "", "[redacted]")},
    )
