import json

from containers.parsers import PARSERS
from containers.tool_registry import TOOL_REGISTRY


def test_architecture_tools_have_contracts_and_parsers():
    expected = {
        "wpscan": "Dockerfile.wpscan",
        "droopescan": "Dockerfile.droopescan",
        "prowler": "Dockerfile.prowler",
        "kubescape": "Dockerfile.kubescape",
        "trivy": "Dockerfile.trivy",
        "cloudflare_audit": "Dockerfile.cloudflare_audit",
        "oidc_probe": "Dockerfile.oidc_probe",
    }
    for key, dockerfile in expected.items():
        tool = TOOL_REGISTRY[key]
        assert tool.category == "architecture"
        assert tool.dockerfile.endswith(dockerfile)
        assert tool.output_types and tool.relationship_types
        assert key in PARSERS


def test_architecture_parsers_emit_typed_results(tmp_path):
    (tmp_path / "wpscan_results.json").write_text(json.dumps({
        "target_url": "https://blog.example.test",
        "version": {"number": "6.5"},
        "plugins": {"woocommerce": {"version": {"number": "8.0"}, "vulnerabilities": [{"title": "Example issue"}]}},
    }))
    (tmp_path / "cloudflare_results.json").write_text(json.dumps({
        "zones": [{"name": "example.test", "id": "zone-1", "records": [{"name": "www.example.test", "type": "A", "content": "192.0.2.10", "proxied": True}]}]
    }))
    (tmp_path / "oidc_results.json").write_text(json.dumps({
        "issuer": "https://login.example.test",
        "authorization_endpoint": "https://login.example.test/authorize",
        "jwks_uri": "https://login.example.test/keys",
        "scopes_supported": ["openid", "profile"],
    }))
    (tmp_path / "trivy_results.json").write_text(json.dumps({
        "Results": [{"Target": "example/app:1", "Vulnerabilities": [{"VulnerabilityID": "CVE-0000-0001", "PkgName": "openssl"}], "Misconfigurations": [{"ID": "DS001", "Title": "Root user"}]}]
    }))

    wp = PARSERS["wpscan"](str(tmp_path))
    cf = PARSERS["cloudflare_audit"](str(tmp_path))
    oidc = PARSERS["oidc_probe"](str(tmp_path))
    trivy = PARSERS["trivy"](str(tmp_path))

    assert any(item.result_type == "platform" and item.value == "WordPress" for item in wp)
    assert any(item.result_type == "vulnerability" for item in wp)
    assert any(item.result_type == "cloudflare_zone" for item in cf)
    assert any(item.result_type == "dns_record" and item.metadata["proxied"] for item in cf)
    assert any(item.result_type == "identity_provider" for item in oidc)
    assert any(item.result_type == "container_image" for item in trivy)
    assert any(item.result_type == "misconfiguration" for item in trivy)


def test_credentialed_adapters_keep_secrets_out_of_commands():
    wpscan = TOOL_REGISTRY["wpscan"]
    prowler = TOOL_REGISTRY["prowler"]
    cloudflare = TOOL_REGISTRY["cloudflare_audit"]
    assert "secret-token" not in wpscan.build_command(url="https://example.test", api_token="secret-token")
    assert wpscan.build_environment(api_token="secret-token")["WPSCAN_API_TOKEN"] == "secret-token"
    assert "secret-key" not in prowler.build_command(provider="aws", secret_key="secret-key")
    assert prowler.build_environment(secret_key="secret-key")["AWS_SECRET_ACCESS_KEY"] == "secret-key"
    assert "secret-token" not in cloudflare.build_command(api_token="secret-token")
    assert cloudflare.build_environment(api_token="secret-token")["CLOUDFLARE_API_TOKEN"] == "secret-token"
