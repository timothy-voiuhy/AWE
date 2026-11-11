"""Evidence records deliberately omit response bodies and credential values."""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from .transport import safe_url


class Report:
    def __init__(self, profile, transport):
        self.profile = profile
        self.transport = transport
        self.findings = []
        self.observations = []
        self.errors = []

    def finding(self, rule, title, responses, *, severity="medium", verification="candidate", detail="", facts=None):
        self.findings.append({"rule": rule, "title": title, "severity": severity, "verification": verification, "detail": detail, "evidence_ids": [response.evidence_id for response in responses], "facts": facts or {}})

    def observe(self, message, **facts):
        self.observations.append({"message": message, "facts": facts})

    def marker(self, value):
        return hashlib.sha256(value.encode()).hexdigest()

    def document(self):
        truncated = any(record.get("truncated") for record in self.transport.records)
        return {"schema_version": 1, "profile": self.profile["id"], "name": self.profile["name"], "target_url": safe_url(self.transport.base), "cwe": self.profile["cwe"], "created_at": datetime.now(timezone.utc).isoformat(), "outcome": "inconclusive" if self.errors or truncated else "findings" if self.findings else "observations" if self.observations else "no_findings", "limitations": self.profile["limitations"], "findings": self.findings, "observations": self.observations, "errors": self.errors, "requests": self.transport.records}

    def save(self, directory):
        destination = Path(directory)
        destination.mkdir(parents=True, exist_ok=True)
        data = self.document()
        (destination / "validation-report.json").write_text(json.dumps(data, indent=2))
        (destination / "validation-evidence.jsonl").write_text("".join(json.dumps(record) + "\n" for record in self.transport.records))
        return data
