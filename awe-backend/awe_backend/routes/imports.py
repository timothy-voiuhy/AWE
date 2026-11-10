"""Imports API handlers and helpers."""

from ..graph_store import InvestigationNotFoundError
from ..projects import ProjectNotFoundError
from ..projects import ProjectStore
from ..repositories import LegacyRepositoryFactory
from ..schemas import EvidenceInput
from ..schemas import GraphEntity
from ..schemas import GraphRelationship
from ..schemas import ImportSubdomainsResult
from datetime import datetime
from datetime import timezone
from fastapi import Depends
from fastapi import File
from fastapi import Form
from fastapi import HTTPException
from fastapi import UploadFile
from pathlib import Path
from pymongo.errors import PyMongoError
from urllib.parse import urlsplit
from xml.etree import ElementTree
import csv
import io
import re
import secrets
import zipfile
from .dependencies import get_project_store, get_repository_factory
from .graph import _ensure_investigation
from .stores import _create_evidence_record, _graph_store
from fastapi import APIRouter

router = APIRouter()


_HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\.?$")


def _normalise_import_host(value: object) -> str:
    candidate = str(value or "").strip().strip('"').strip("'").strip()
    if not candidate:
        return ""
    candidate = candidate.split()[0].strip(",;")
    if "://" in candidate:
        candidate = urlsplit(candidate).hostname or candidate
    candidate = candidate.lstrip("*.").rstrip(".").lower()
    if ":" in candidate and not candidate.count(":") > 1:
        candidate = candidate.split(":", 1)[0]
    return candidate if _HOST_RE.fullmatch(candidate) else ""


def _xlsx_rows(raw: bytes) -> list[list[str]]:
    namespace = {"s": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            shared: list[str] = []
            try:
                root = ElementTree.fromstring(archive.read("xl/sharedStrings.xml"))
                for item in root.findall(".//s:si", namespace):
                    shared.append("".join(node.text or "" for node in item.findall(".//s:t", namespace)))
            except KeyError:
                pass
            sheet_name = next((name for name in archive.namelist() if name.startswith("xl/worksheets/sheet") and name.endswith(".xml")), "")
            if not sheet_name:
                return []
            root = ElementTree.fromstring(archive.read(sheet_name))
            rows: list[list[str]] = []
            for row in root.findall(".//s:row", namespace):
                values: list[str] = []
                for cell in row.findall("s:c", namespace):
                    value_node = cell.find("s:v", namespace)
                    inline_node = cell.find(".//s:t", namespace)
                    value = inline_node.text if inline_node is not None else value_node.text if value_node is not None else ""
                    if cell.get("t") == "s" and value.isdigit():
                        value = shared[int(value)] if int(value) < len(shared) else value
                    values.append(value or "")
                if any(item.strip() for item in values):
                    rows.append(values)
            return rows
    except (OSError, zipfile.BadZipFile, ElementTree.ParseError):
        return []


def _extract_import_subdomains(filename: str, raw: bytes) -> list[str]:
    suffix = Path(filename).suffix.lower()
    rows: list[list[str]] = []
    if suffix == ".xlsx":
        rows = _xlsx_rows(raw)
    else:
        text = raw.decode("utf-8-sig", errors="replace")
        if suffix == ".csv":
            sample = text[:4096]
            try:
                dialect = csv.Sniffer().sniff(sample)
            except csv.Error:
                dialect = csv.excel
            rows = [row for row in csv.reader(io.StringIO(text), dialect) if any(cell.strip() for cell in row)]
        else:
            rows = [re.split(r"[\s,;]+", line.strip()) for line in text.splitlines() if line.strip()]
    if not rows:
        return []
    header = [cell.strip().lower().replace(" ", "_") for cell in rows[0]]
    preferred = [index for index, name in enumerate(header) if name in {"subdomain", "domain", "host", "hostname", "url", "fqdn"}]
    data_rows = rows[1:] if preferred else rows
    candidates: list[str] = []
    for row in data_rows:
        cells = [row[index] for index in preferred if index < len(row)] if preferred else row
        candidates.extend(_normalise_import_host(cell) for cell in cells)
    seen: set[str] = set()
    values: list[str] = []
    for value in candidates:
        if value and value not in seen:
            seen.add(value); values.append(value)
    return values


@router.post("/projects/{project_id}/results/import-subdomains", response_model=ImportSubdomainsResult, tags=["results", "network"])
async def import_subdomains(
    project_id: str,
    upload: UploadFile = File(...),
    investigation_id: str = Form(default=""),
    attach_to_graph: bool = Form(default=True),
    store: ProjectStore = Depends(get_project_store),
    repositories: LegacyRepositoryFactory = Depends(get_repository_factory),
) -> ImportSubdomainsResult:
    try:
        project = store.get(project_id)
        project_dir = store.project_dir(project_id)
        raw = await upload.read()
        values = _extract_import_subdomains(upload.filename or "subdomains.txt", raw)
        if not values:
            raise HTTPException(status_code=422, detail="No valid subdomains were found in the uploaded file")
        repo = repositories(project_dir)
        session_id = repo.create_session("manual_import", "Imported Subdomains", project.target, str(project_dir / ".awe-imports"), {"filename": upload.filename})
        tool_run_id = repo.create_tool_run(session_id, "manual_import", "Manual subdomain import", "subdomain")
        from pymongo import UpdateOne
        now = datetime.now(timezone.utc).isoformat()
        ops = [
            UpdateOne(
                {"session_id": session_id, "category": "subdomain", "result_key": value},
                {"$setOnInsert": {"session_id": session_id, "tool_run_id": tool_run_id, "category": "subdomain", "result_key": value, "data": {"domain": value, "value": value, "imported": True}, "created_at": now}, "$addToSet": {"sources": "manual_import"}},
                upsert=True,
            )
            for value in values
        ]
        result = repo._db.results.bulk_write(ops, ordered=False) if ops else None
        imported = int(result.upserted_count if result else 0)
        duplicates = len(values) - imported
        graph_entities = 0
        actual_investigation_id = investigation_id
        if attach_to_graph:
            graph_store = _graph_store(project_dir)
            investigation = graph_store.get(project_id, investigation_id) if investigation_id else _ensure_investigation(project_id, project_dir, project.target, repositories)
            actual_investigation_id = investigation.id
            parent_id = f"target:{project.target}" if project.target else ""
            created_entities: list[str] = []
            created_relationships: list[str] = []
            batch_id = secrets.token_hex(8)
            for index, value in enumerate(values[:5000]):
                entity_id = f"import:{batch_id}:{index}"
                entity = GraphEntity(id=entity_id, kind="subdomain", label=value, value=value, data={"domain": value, "imported": True, "source_file": upload.filename or ""}, source="imported", provenance=[{"source": "manual_import", "session_id": session_id}])
                graph_store.add_entity(investigation, entity)
                created_entities.append(entity_id)
                if parent_id:
                    relationship = GraphRelationship(id=f"{entity_id}:edge", source_id=parent_id, target_id=entity_id, kind="has_subdomain", source="imported", provenance=[{"source": "manual_import", "session_id": session_id}])
                    graph_store.add_relationship(investigation, relationship)
                    created_relationships.append(relationship.id)
            if created_entities or created_relationships:
                graph_store.save(investigation.model_copy(update={"entity_ids": [*investigation.entity_ids, *created_entities], "relationship_ids": [*investigation.relationship_ids, *created_relationships]}), investigation.revision)
            graph_entities = len(created_entities)
        evidence = _create_evidence_record(project_id, project_dir, EvidenceInput(
            investigation_id=actual_investigation_id,
            title=f"Imported {len(values)} subdomains",
            summary=f"Imported from {upload.filename or 'uploaded file'} into Results{subdomain_import_graph_suffix(graph_entities)}.",
            kind="file",
            source_type="subdomain_import",
            source_id=session_id,
            tags=["import", "subdomain"],
            data={"filename": upload.filename, "imported": imported, "duplicates": duplicates, "total_values": len(values), "sample": values[:25]},
        ))
        repo.update_tool_run_done(tool_run_id, "completed", imported)
        repo.update_session_status(session_id, "completed")
        return ImportSubdomainsResult(session_id=session_id, imported=imported, duplicates=duplicates, graph_entities=graph_entities, evidence_id=evidence.id if evidence else "", values=values[:100])
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc
    except InvestigationNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Investigation not found") from exc
    except PyMongoError as exc:
        raise HTTPException(status_code=503, detail="Database unavailable") from exc


def subdomain_import_graph_suffix(graph_entities: int) -> str:
    return f" and attached {graph_entities} graph entities" if graph_entities else ""
