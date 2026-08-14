"""Parsers for architecture-specific platform and posture tools."""
import glob
import os
from typing import Any

from containers.parsers._common import _read_json, _read_jsonl, _norm_url
from containers.results.models import OSINTResult


def _result(tool: str, result_type: str, value: str, *, extra: str = "",
            provider: str = "", related_host: str = "", metadata: dict | None = None) -> OSINTResult:
    item = OSINTResult(result_type=result_type, value=str(value), extra=extra,
                       provider=provider, related_host=related_host,
                       metadata=metadata or {})
    item.add_source(tool)
    return item


def _walk(value: Any):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


def parse_wpscan(output_dir: str) -> list[OSINTResult]:
    data = _read_json(os.path.join(output_dir, "wpscan_results.json")) or {}
    if not isinstance(data, dict):
        return []
    url = _norm_url(str(data.get("target_url", "")))
    host = url
    results = [_result("wpscan", "platform", "WordPress", extra=str((data.get("version") or {}).get("number", "")), related_host=host,
                       metadata={"target": url, "status": data.get("status_code", 0)})]
    for group, kind in (("plugins", "plugin"), ("themes", "theme")):
        for name, item in (data.get(group) or {}).items():
            if not isinstance(item, dict):
                item = {}
            version = str((item.get("version") or {}).get("number", ""))
            results.append(_result("wpscan", "component", str(name), extra=version, related_host=host,
                                   metadata={"component_type": kind, "status": item.get("status", "unknown")}))
            for vuln in item.get("vulnerabilities", []) or []:
                if not isinstance(vuln, dict):
                    continue
                refs = vuln.get("references", {}) or {}
                results.append(_result("wpscan", "vulnerability", str(vuln.get("title") or vuln.get("id") or name),
                                       extra=str(vuln.get("fixed_in", "")), related_host=host,
                                       metadata={"component": name, "component_type": kind, "references": refs,
                                                 "severity": vuln.get("severity", "unknown")}))
    for username in (data.get("users") or {}).keys():
        results.append(_result("wpscan", "identity", str(username), related_host=host, metadata={"type": "wordpress_user"}))
    return results


def parse_droopescan(output_dir: str) -> list[OSINTResult]:
    data = _read_json(os.path.join(output_dir, "droopescan_results.json")) or {}
    results = [_result("droopescan", "platform", "Drupal", metadata={"scanner": "droopescan"})]
    if isinstance(data, dict):
        for field, kind in (("plugins", "module"), ("themes", "theme"), ("interesting_urls", "endpoint"), ("version", "version")):
            values = data.get(field, [])
            if isinstance(values, dict):
                values = list(values.values())
            if not isinstance(values, list):
                values = [values]
            for value in values:
                if isinstance(value, dict):
                    label = value.get("name") or value.get("url") or value.get("version") or value.get("location")
                    meta = value
                else:
                    label, meta = value, {}
                if label:
                    results.append(_result("droopescan", "component" if kind in {"module", "theme"} else "misconfiguration",
                                           str(label), metadata={"component_type": kind, **meta}))
    return results


def parse_prowler(output_dir: str) -> list[OSINTResult]:
    results: list[OSINTResult] = []
    paths = glob.glob(os.path.join(output_dir, "**", "*.json"), recursive=True)
    for path in paths:
        data = _read_json(path)
        for obj in _walk(data):
            finding_id = obj.get("finding_info", {}).get("uid") or obj.get("FindingId") or obj.get("finding_id")
            title = obj.get("finding_info", {}).get("title") or obj.get("Title") or obj.get("title")
            status = str(obj.get("status_code") or obj.get("Status") or obj.get("status", "")).upper()
            resource = obj.get("resources", [{}])[0] if isinstance(obj.get("resources"), list) and obj.get("resources") else {}
            resource_id = resource.get("uid") or obj.get("ResourceId") or obj.get("resource_id") or ""
            provider = str(obj.get("cloud", {}).get("provider") or obj.get("Provider") or "")
            if resource_id:
                results.append(_result("prowler", "cloud_resource", str(resource_id), provider=provider,
                                       metadata={"service": obj.get("service_name") or obj.get("ServiceName", ""), "region": obj.get("region", "")}))
            if finding_id or title:
                results.append(_result("prowler", "misconfiguration", str(finding_id or title), extra=str(title or ""),
                                       provider=provider, metadata={"status": status, "severity": obj.get("severity") or obj.get("Severity", ""),
                                                                     "resource": resource_id, "service": obj.get("service_name") or obj.get("ServiceName", "")}))
    return results


def parse_kubescape(output_dir: str) -> list[OSINTResult]:
    data = _read_json(os.path.join(output_dir, "kubescape_results.json")) or {}
    results: list[OSINTResult] = []
    for obj in _walk(data):
        control = obj.get("controlID") or obj.get("control_id")
        resource = obj.get("resourceID") or obj.get("resource_id") or obj.get("resourceName")
        status = str(obj.get("status") or obj.get("statusCode") or "").lower()
        if resource:
            results.append(_result("kubescape", "workload", str(resource), provider="kubernetes",
                                   metadata={"namespace": obj.get("namespace", ""), "kind": obj.get("resourceKind", "")}))
        if control or obj.get("name"):
            label = str(control or obj.get("name"))
            results.append(_result("kubescape", "misconfiguration", label, provider="kubernetes",
                                   metadata={"status": status, "resource": resource or "", "description": obj.get("description", "")}))
    return results


def parse_trivy(output_dir: str) -> list[OSINTResult]:
    data = _read_json(os.path.join(output_dir, "trivy_results.json")) or {}
    results: list[OSINTResult] = []
    for scan in data.get("Results", []) if isinstance(data, dict) else []:
        target = str(scan.get("Target", ""))
        if target:
            results.append(_result("trivy", "container_image", target, metadata={"class": scan.get("Class", ""), "type": scan.get("Type", "")}))
        for vuln in scan.get("Vulnerabilities", []) or []:
            if isinstance(vuln, dict) and (vuln.get("VulnerabilityID") or vuln.get("PkgName")):
                results.append(_result("trivy", "vulnerability", str(vuln.get("VulnerabilityID") or vuln.get("PkgName")),
                                       extra=str(vuln.get("PkgName", "")), metadata={"installed": vuln.get("InstalledVersion", ""),
                                                                                       "fixed": vuln.get("FixedVersion", ""), "severity": vuln.get("Severity", ""), "target": target}))
        for finding in (scan.get("Misconfigurations", []) or []) + (scan.get("Secrets", []) or []):
            if not isinstance(finding, dict):
                continue
            fid = finding.get("ID") or finding.get("RuleID") or finding.get("Title")
            if fid:
                kind = "secret" if finding in (scan.get("Secrets", []) or []) else "misconfiguration"
                results.append(_result("trivy", kind, str(fid), extra=str(finding.get("Title", "")), metadata={"target": target, "severity": finding.get("Severity", "")}))
    return results


def parse_cloudflare_audit(output_dir: str) -> list[OSINTResult]:
    data = _read_json(os.path.join(output_dir, "cloudflare_results.json")) or {}
    results: list[OSINTResult] = []
    for zone in data.get("zones", []) if isinstance(data, dict) else []:
        if not isinstance(zone, dict):
            continue
        name = str(zone.get("name", ""))
        if not name:
            continue
        results.append(_result("cloudflare_audit", "cloudflare_zone", name, provider="cloudflare", metadata={k: zone.get(k, "") for k in ("id", "status", "type", "plan", "account")}))
        for record in zone.get("records", []) or []:
            if not isinstance(record, dict) or not record.get("name"):
                continue
            results.append(_result("cloudflare_audit", "dns_record", str(record["name"]), extra=str(record.get("content", "")),
                                   provider="cloudflare", related_host=name, metadata={"record_type": record.get("type", ""), "proxied": record.get("proxied", False), "ttl": record.get("ttl", 0), "zone": name}))
    return results


def parse_oidc_probe(output_dir: str) -> list[OSINTResult]:
    data = _read_json(os.path.join(output_dir, "oidc_results.json")) or {}
    if not isinstance(data, dict) or not data.get("issuer"):
        return []
    issuer = str(data["issuer"])
    results = [_result("oidc_probe", "identity_provider", issuer, provider="oidc", metadata={"issuer_url": data.get("issuer_url", ""), "status": data.get("http_status", 0)})]
    for key in ("authorization_endpoint", "token_endpoint", "userinfo_endpoint", "jwks_uri", "introspection_endpoint", "end_session_endpoint"):
        if data.get(key):
            results.append(_result("oidc_probe", "oidc_endpoint", str(data[key]), extra=key, provider="oidc", related_host=issuer, metadata={"endpoint_type": key}))
    for value in data.get("scopes_supported", []) or []:
        results.append(_result("oidc_probe", "component", str(value), extra="scope", provider="oidc", related_host=issuer, metadata={"component_type": "scope"}))
    return results
