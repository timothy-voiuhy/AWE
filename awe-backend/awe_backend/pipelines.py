"""Migration adapter for the existing Qt-free pipeline catalogue.

Only definitions and dataclasses are loaded. The Qt-based executor remains
outside the backend process until it is replaced by the job service.
"""

import sys
from dataclasses import asdict
from pathlib import Path

from .schemas import PipelineTemplate


class PipelineCatalog:
    def __init__(self, legacy_src_dir: Path):
        self.legacy_src_dir = legacy_src_dir.resolve()

    def list(self) -> list[PipelineTemplate]:
        if not self.legacy_src_dir.is_dir():
            raise RuntimeError(f"AWE source directory not found: {self.legacy_src_dir}")
        source = str(self.legacy_src_dir)
        if source not in sys.path:
            sys.path.insert(0, source)

        from pipeline.definitions import PIPELINE_REGISTRY

        return [
            PipelineTemplate.model_validate(asdict(template))
            for template in PIPELINE_REGISTRY.values()
        ]

    def get_legacy_template(self, pipeline_key: str):
        self.list()  # validates and adds the legacy source directory to sys.path
        from pipeline.definitions import PIPELINE_REGISTRY

        return PIPELINE_REGISTRY.get(pipeline_key)
