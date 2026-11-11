"""Registry adapters for the shared AWE HTTP validation image."""
import json
import shlex
from pathlib import Path
from containers.tool_registry import ToolConfig
from config.config import RUNDIR

PROFILES = json.loads((Path(RUNDIR) / "dockerfiles/awe_validation/profiles.json").read_text())
_PEER = {"authz_horizontal", "authz_vertical", "authz_tenant", "cache_isolation", "workflow_invariants"}
_MARKER = _PEER | {"anonymous_access", "logout_replay", "jwt_signature", "jwt_none", "canary_traversal"}
_PARAMETER = {"open_redirect", "crlf", "ssti", "canary_traversal", "ssrf_callback"}


class ValidationTool(ToolConfig):
    def __init__(self, profile):
        super().__init__(key=profile["id"], display_name=profile["name"], image="awe/validation:1", description=profile["limitations"], category="vuln", dockerfile=str(Path(RUNDIR) / "dockerfiles/Dockerfile.awe_validation"), input_types=("url", "endpoint"), output_types=("vuln",), relationship_types=("has_finding",), execution_mode="active", credential_fields=("url", "request_context", "peer_context", "callback_context", "marker"), output_channels=("logs", "structured", "artifacts"), execution_timeout=180, source_metadata={"kind": "builtin-validation", "version": 1, "catalog_category": profile["family"], "cwe": profile["cwe"]})
        self.profile = profile

    def build_command(self, **kwargs):
        return "python /opt/awe_validation/cli.py --profile " + shlex.quote(self.key)

    def build_environment(self, **kwargs):
        specs = {spec["key"]: spec.get("default", "") for spec in self.param_spec()}
        config = {key: kwargs.get(key, default) for key, default in specs.items()}
        if len(json.dumps(config).encode()) > 100000:
            raise ValueError("Combined validation configuration exceeds 100 KiB")
        for key in ("allow_state_change", "insecure_tls"):
            if not isinstance(config.get(key), bool):
                raise ValueError(f"{key} must be a boolean")
        return {"AWE_VALIDATION_CONFIG": json.dumps(config)}

    def param_spec(self):
        slug = self.profile["slug"]
        specs = [
            {"key": "url", "label": "Target URL", "type": "text", "default": "", "sensitive": True},
            {"key": "request_context", "label": "Primary request context (secret JSON)", "type": "secret", "default": ""},
        ]
        if slug in _PEER:
            specs.append({"key": "peer_context", "label": "Peer / isolated workflow context (secret JSON)", "type": "secret", "default": ""})
        if slug in _MARKER:
            specs.append({"key": "marker", "label": "Private response / canary marker (8–256 characters)", "type": "secret", "default": ""})
        if slug in _PARAMETER:
            specs.append({"key": "parameter", "label": "Query parameter to validate", "type": "text", "default": ""})
        if slug == "canary_traversal":
            specs.append({"key": "canary_file", "label": "Researcher canary filename", "type": "text", "default": ""})
        if slug in {"ssrf_callback", "xxe_callback"}:
            specs.append({"key": "callback_context", "label": "Owned callback and independent monitor (secret JSON)", "type": "secret", "default": ""})
        if slug == "session_cookies":
            specs.append({"key": "cookie_names", "label": "Session cookie names", "type": "text", "default": "session,sessionid,sid,PHPSESSID,JSESSIONID"})
        return [*specs,
            {"key": "allow_state_change", "label": "Allow explicitly configured state-changing requests", "type": "check", "default": False},
            {"key": "max_requests", "label": "Maximum requests (1–32)", "type": "text", "default": "12"},
            {"key": "timeout", "label": "Per-request timeout, seconds (0.1–20)", "type": "text", "default": "10"},
            {"key": "insecure_tls", "label": "Allow untrusted TLS certificates in this test environment", "type": "check", "default": False},
        ]


def validation_tools():
    return {profile["id"]: ValidationTool(profile) for profile in PROFILES}
