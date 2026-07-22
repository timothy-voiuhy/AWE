from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


@dataclass
class WorkerMessage:
    type: str
    job_id: str = ""
    payload: dict[str, Any] = field(default_factory=dict)

    def to_json_line(self) -> str:
        return json.dumps({
            "type": self.type,
            "job_id": self.job_id,
            "payload": self.payload,
        }, separators=(",", ":")) + "\n"

    @staticmethod
    def from_json_line(line: str) -> "WorkerMessage":
        data = json.loads(line)
        return WorkerMessage(
            type=str(data.get("type", "")),
            job_id=str(data.get("job_id", "")),
            payload=data.get("payload") or {},
        )


def encode_message(message_type: str, job_id: str = "", **payload) -> str:
    return WorkerMessage(message_type, job_id=job_id, payload=payload).to_json_line()
