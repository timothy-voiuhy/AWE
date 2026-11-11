"""Shared controls and dispatch for the HTTP validation suite."""
import json
import secrets
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from .transport import Transport, ValidationError, anonymous, parse_context
from .report import Report

PROFILES = json.loads((Path(__file__).parent / "profiles.json").read_text())


class Scan:
    def __init__(self, profile, config):
        self.config = config
        self.primary = parse_context(config.get("request_context", "{}"), config["url"])
        self.peer = parse_context(config.get("peer_context", "{}"), config["url"])
        self.url = self.primary.get("url") or config["url"]
        self.transport = Transport({**config, "url": self.url})
        self.report = Report(profile, self.transport)
        self.token = "awe" + secrets.token_hex(12)
        self._baseline = None

    def get(self, url=None, context=None, **options):
        return self.transport.request(url or self.url, self.primary if context is None else context, **options)

    @property
    def baseline(self):
        if self._baseline is None:
            self._baseline = self.get()
        return self._baseline

    def parameter(self, value, name=None):
        name = name or self.config.get("parameter", "")
        if not name or not isinstance(name, str) or len(name) > 120:
            raise ValidationError("A parameter name is required for this profile")
        url = urlsplit(self.url)
        pairs = [(key, val) for key, val in parse_qsl(url.query, keep_blank_values=True) if key != name]
        return urlunsplit((url.scheme, url.netloc, url.path, urlencode([*pairs, (name, value)]), ""))

    def marker(self):
        value = self.config.get("marker", "")
        if not isinstance(value, str) or not 8 <= len(value) <= 256:
            raise ValidationError("Provide a private/canary response marker of 8–256 characters")
        return value

    def anonymous_headers(self):
        headers = anonymous(self.primary.get("headers", {}))
        custom = self.primary.get("credential_headers", [])
        if not isinstance(custom, list):
            raise ValidationError("credential_headers must be a list of header names")
        return {key: value for key, value in headers.items() if key.lower() not in {str(name).lower() for name in custom}}

    def private_controls(self):
        marker = self.marker()
        base = self.baseline
        control = self.get(headers=self.anonymous_headers())
        if not 200 <= base.status < 300 or marker not in base.text or marker in control.text:
            raise ValidationError("Private baseline/anonymous control did not establish protected content")
        return marker, base, control


def execute(profile_id, config, output_dir):
    from . import http_checks, exposure_checks, access_checks, injection_checks
    profile = next((item for item in PROFILES if item["id"] == profile_id), None)
    if profile is None:
        raise ValidationError("Unknown validation profile")
    scan = Scan(profile, config)
    checks = {**http_checks.CHECKS, **exposure_checks.CHECKS, **access_checks.CHECKS, **injection_checks.CHECKS}
    try:
        checks[profile["slug"]](scan)
    except Exception as error:
        # Never interpolate untrusted exception text (which can include headers,
        # JSON/body fragments, URLs or token values) into logs or artifacts.
        scan.report.errors.append({"type": type(error).__name__, "message": str(error) if isinstance(error, ValidationError) else "Validation incomplete: check profile prerequisites, connectivity, and execution limits."})
    data = scan.report.save(output_dir)
    return data
