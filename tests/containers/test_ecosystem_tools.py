import json

from containers.parsers import PARSERS
from containers.results.models import LiveHost, OSINTResult, VulnFinding
from containers.tool_registry import TOOL_REGISTRY


def test_ecosystem_tools_are_registered_with_local_images():
    expected = {
        "asnmap": "Dockerfile.asnmap",
        "tlsx": "Dockerfile.tlsx",
        "testssl": "Dockerfile.testssl",
        "theharvester": "Dockerfile.theharvester",
        "gitleaks": "Dockerfile.gitleaks",
        "whatweb": "Dockerfile.whatweb",
        "s3scanner": "Dockerfile.s3scanner",
    }
    for key, dockerfile in expected.items():
        tool = TOOL_REGISTRY[key]
        assert tool.dockerfile.endswith(dockerfile)
        assert tool.output_types
        assert tool.relationship_types
        assert key in PARSERS


def test_ecosystem_parsers_emit_graph_usable_results(tmp_path):
    (tmp_path / "asnmap_results.jsonl").write_text(json.dumps({
        "input": "example.test",
        "as_number": "AS64500",
        "as_name": "Example Networks",
        "as_country": "ZZ",
        "as_range": ["192.0.2.0/24"],
    }) + "\n")
    (tmp_path / "tlsx_results.jsonl").write_text(json.dumps({
        "host": "api.example.test",
        "subject_cn": "api.example.test",
        "subject_an": ["api.example.test", "www.example.test"],
        "sha256": "abc123",
        "tls_version": "tls13",
    }) + "\n")
    (tmp_path / "gitleaks_results.json").write_text(json.dumps([{
        "RuleID": "generic-api-key",
        "File": "config.env",
        "StartLine": 4,
        "Secret": "must-not-be-persisted",
        "Fingerprint": "commit:config.env:generic-api-key:4",
    }]))
    (tmp_path / "whatweb_results.json").write_text(json.dumps([{
        "target": "https://www.example.test",
        "http_status": 200,
        "plugins": {"WordPress": [{"version": ["6.0"]}], "Apache": [{}]},
    }]))
    (tmp_path / "s3scanner_results.jsonl").write_text(json.dumps({
        "bucket": "example-assets", "provider": "aws", "status": "public",
    }) + "\n")

    asn = PARSERS["asnmap"](str(tmp_path))
    certs = PARSERS["tlsx"](str(tmp_path))
    secrets = PARSERS["gitleaks"](str(tmp_path))
    tech = PARSERS["whatweb"](str(tmp_path))
    buckets = PARSERS["s3scanner"](str(tmp_path))

    assert any(r.result_type == "asn" and r.value == "AS64500" for r in asn)
    assert any(r.result_type == "netblock" and r.value == "192.0.2.0/24" for r in asn)
    assert certs[0].metadata["sans"] == ["api.example.test", "www.example.test"]
    assert secrets[0].metadata["redacted"] is True
    assert secrets[0].value != "must-not-be-persisted"
    assert isinstance(tech[0], LiveHost)
    assert "WordPress 6.0" in tech[0].technologies
    assert buckets[0].result_type == "cloud_bucket"


def test_testssl_parser_maps_findings_to_vulnerabilities(tmp_path):
    (tmp_path / "testssl_results.json").write_text(json.dumps({
        "scanResult": [
            {"id": "TLS1", "finding": "TLS 1.0 enabled", "severity": "HIGH", "fqdn": "example.test"},
            {"id": "OK", "finding": "TLS 1.3", "severity": "OK", "fqdn": "example.test"},
        ]
    }))
    results = PARSERS["testssl"](str(tmp_path))
    assert len(results) == 1
    assert isinstance(results[0], VulnFinding)
    assert results[0].severity == "high"
    assert results[0].url == "https://example.test"
