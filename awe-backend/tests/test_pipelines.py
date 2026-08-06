from pathlib import Path

from awe_backend.pipelines import PipelineCatalog


def test_loads_existing_pipeline_definitions():
    legacy_src = Path(__file__).resolve().parents[2] / "src"
    pipelines = PipelineCatalog(legacy_src).list()

    assert pipelines
    assert any(item.key == "quick_recon" for item in pipelines)
    assert all(item.steps for item in pipelines)
