"""Per-project context closed over by AI tool functions.

One AiToolContext lives per TargetWindow and is shared by every chat tab's
Agent — this dataclass carries whatever those tools need without resorting
to globals.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from database.repository import AweRepository


@dataclass
class AiToolContext:
    project_dir: str
    repo: AweRepository
    target: str
    proxy_col: Any  # pymongo Collection or None
    proxy_port: int
    mongo_uri: str = "mongodb://localhost:27017"
