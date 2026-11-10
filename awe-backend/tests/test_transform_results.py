from unittest.mock import Mock, patch

from awe_backend.routes import graph as api
from awe_backend.evidence_store import EvidenceStore
from awe_backend.schemas import EvidenceInput, InvestigationCreate, NetworkGraph, TransformManifest
from awe_backend.graph_store import InvestigationStore


def test_transform_outputs_are_saved_for_results_and_graph(tmp_path):
    output_dir = tmp_path / "run"
    for name, filename, content in (
        ("stage_1_subfinder", "subfinder_results.txt", "app.example.com\n"),
        ("stage_1_assetfinder", "assetfinder_results.txt", "app.example.com\napi.example.com\n"),
        ("stage_1_amass", "amass_results.txt", "mail.google.com\n"),
        ("stage_2_httpx", "httpx_results.txt", "https://app.example.com [200] [App]\n"),
    ):
        folder = output_dir / name
        folder.mkdir(parents=True)
        (folder / filename).write_text(content)
    manifest = TransformManifest(
        id="composite:enumerate_subdomains", tool_key="enumerate_subdomains",
        display_name="Enumerate subdomains", output_types=["subdomain"],
        stages=[
            {"tool_keys": ["subfinder", "assetfinder", "amass"]},
            {"tool_keys": ["httpx"], "input_source": "previous"},
        ],
    )
    repo = Mock()
    job_id = "0123456789abcdef01234567"
    investigation = InvestigationStore(tmp_path).create("project", InvestigationCreate(name="Test"), ["target:example.com"])

    result = api._complete_graph_transform(
        "project", tmp_path, "example.com", investigation.id, manifest,
        ["target:example.com"], "target:example.com", {}, job_id,
        lambda _dir: repo, api._normalise_composite_results(manifest, [{"url": "https://app.example.com", "status_code": 200}]), output_dir,
    )

    assert result["result_count"] == 3
    writes = repo._db.results.bulk_write.call_args.args[0]
    assert {(write._filter["category"], write._filter["result_key"]) for write in writes} == {
        ("subdomain", "app.example.com"), ("subdomain", "api.example.com"),
        ("http", "https://app.example.com"),
    }
    app_write = next(write for write in writes if write._filter["result_key"] == "app.example.com" and write._filter["category"] == "subdomain")
    assert {"subfinder", "assetfinder"} <= set(app_write._doc["$addToSet"]["sources"]["$each"])
    graph_store = InvestigationStore(tmp_path)
    entities = graph_store.entities(graph_store.get("project", investigation.id))
    assert {item.label for item in entities} == {"app.example.com", "api.example.com"}
    assert all(item.data.get("live") is False for item in entities if item.label == "api.example.com")
    assert result["ingested_count"] == 2
    assert EvidenceStore(tmp_path).list("project", source_id=job_id)[0].data["result_count"] == 3
    with patch.object(api, "_network_graph", return_value=NetworkGraph()):
        bundle = api._graph_bundle("project", tmp_path, "example.com", lambda _dir: repo, investigation.id)
    assert {item.label for item in bundle.entities} == {"app.example.com", "api.example.com"}


def test_transform_evidence_is_updated_on_retry(tmp_path):
    store = EvidenceStore(tmp_path)
    first = store.upsert_source("project", EvidenceInput(title="Run", source_type="transform", source_id="job", summary="1 result"))
    second = store.upsert_source("project", EvidenceInput(title="Run", source_type="transform", source_id="job", summary="2 results"))
    assert first.id == second.id
    assert len(store.list("project", source_id="job")) == 1
    assert store.list("project", source_id="job")[0].summary == "2 results"
