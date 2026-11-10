"""Reports API handlers and helpers."""

from ..config import Settings
from ..config import get_settings
from ..projects import ProjectNotFoundError
from ..projects import ProjectStore
from ..repositories import LegacyRepositoryFactory
from ..schemas import EvidenceRecord
from ..schemas import Project
from ..schemas import ReportGenerateRequest
from ..schemas import ReportGenerateResponse
from ..schemas import StoredResult
from fastapi import Depends
from fastapi import HTTPException
from fastapi import status
from pymongo.errors import PyMongoError
import json
import re
from .dependencies import get_project_store, get_repository_factory
from .methodology import _methodology_registry
from .results import _merged_project_results
from .stores import _evidence_store
from fastapi import APIRouter

router = APIRouter()


_REPORT_RESULT_FIELDS = (
    "url",
    "domain",
    "host",
    "name",
    "path",
    "endpoint",
    "template_id",
    "value",
    "title",
)


def _report_clean(value: object, fallback: str = "") -> str:
    if value is None:
        return fallback
    if isinstance(value, str):
        text = value.strip()
    elif isinstance(value, (list, tuple, set)):
        text = ", ".join(_report_clean(item) for item in value if _report_clean(item))
    elif isinstance(value, dict):
        text = json.dumps(value, ensure_ascii=False, default=str)
    else:
        text = str(value).strip()
    return text or fallback


def _report_first(data: dict, keys: tuple[str, ...], fallback: str = "") -> str:
    for key in keys:
        text = _report_clean(data.get(key))
        if text:
            return text
    return fallback


def _report_clip(text: str, limit: int = 220) -> str:
    compact = re.sub(r"\s+", " ", text).strip()
    return compact if len(compact) <= limit else f"{compact[:limit - 1].rstrip()}..."


def _report_title(project: Project, payload: ReportGenerateRequest) -> str:
    if payload.title.strip():
        return payload.title.strip()
    weakness = payload.vulnerability_type.strip() or payload.weakness.strip() or "Security issue"
    target = payload.affected_component.strip() or payload.asset.strip() or project.target or project.name
    if payload.template == "bugcrowd":
        impact = _report_clip(payload.impact, 90) or "impact the application"
        return f"[{weakness}] in {target} allows {payload.attacker.strip() or 'an attacker'} to {impact}"
    return f"{weakness} in {target}"


def _result_report_line(result: StoredResult) -> str:
    target = _report_first(result.data, _REPORT_RESULT_FIELDS, result.result_key)
    severity = _report_clean(result.data.get("severity"))
    status = _report_clean(result.data.get("status_code") or result.data.get("status"))
    extras = [f"category: `{result.category}`"]
    if severity:
        extras.append(f"severity: `{severity}`")
    if status:
        extras.append(f"status: `{status}`")
    if result.sources:
        extras.append(f"sources: `{', '.join(result.sources)}`")
    return f"- `{target}` ({'; '.join(extras)})"


def _evidence_report_block(evidence: EvidenceRecord) -> str:
    parts = [
        f"### {evidence.title}",
        f"- Type: `{evidence.kind}`",
    ]
    if evidence.tags:
        parts.append(f"- Tags: `{', '.join(evidence.tags)}`")
    if evidence.summary.strip():
        parts.extend(["", evidence.summary.strip()])
    if evidence.data:
        parts.extend(["", "```json", json.dumps(evidence.data, indent=2, ensure_ascii=False, default=str), "```"])
    return "\n".join(parts)


def _report_methodology_notes(settings: Settings, states: dict) -> list[str]:
    lines: list[str] = []
    for category in _methodology_registry(settings):
        for vuln in category.get("vulnerabilities", []):
            state = states.get(vuln.get("id"), {})
            if state.get("status") != "vulnerable" and not state.get("notes"):
                continue
            notes = _report_clean(state.get("notes"))
            if notes:
                lines.append(f"- **{vuln.get('name', vuln.get('id', 'Methodology check'))}**: {notes}")
    return lines


def _report_section(title: str, body: str) -> str:
    return f"## {title}\n\n{body.strip() or 'TODO: Complete this section before submission.'}"


def _raw_results_block(results: list[StoredResult]) -> str:
    if not results:
        return ""
    return "\n\n```json\n" + json.dumps([item.model_dump() for item in results], indent=2, ensure_ascii=False, default=str) + "\n```"


def _generate_report_markdown(
    project: Project,
    payload: ReportGenerateRequest,
    results: list[StoredResult],
    evidence: list[EvidenceRecord],
    project_notes: str,
    methodology_notes: list[str],
) -> tuple[str, str, list[str]]:
    title = _report_title(project, payload)
    warnings: list[str] = []
    if not payload.steps_to_reproduce.strip():
        warnings.append("Steps to reproduce are empty.")
    if not payload.impact.strip():
        warnings.append("Impact is empty.")
    if not results and not evidence:
        warnings.append("No results or evidence were attached.")

    asset = payload.asset.strip() or project.target or "TODO: Affected asset"
    weakness = payload.weakness.strip() or payload.vulnerability_type.strip() or "TODO: Weakness/CWE"
    component = payload.affected_component.strip() or asset
    impact = payload.impact.strip()
    steps = payload.steps_to_reproduce.strip()
    remediation = payload.remediation.strip()
    result_lines = "\n".join(_result_report_line(item) for item in results)
    evidence_blocks = "\n\n".join(_evidence_report_block(item) for item in evidence) if payload.include_evidence else ""
    methodology = "\n".join(methodology_notes)
    notes = project_notes.strip() if payload.include_project_notes else ""
    support_parts = [part for part in (result_lines, methodology, notes) if part]
    support = "\n\n".join(support_parts)
    if payload.include_raw:
        support += _raw_results_block(results)

    summary = (
        f"A {payload.severity} severity {payload.vulnerability_type.strip() or 'security vulnerability'} "
        f"was identified in `{component}`. The issue affects `{asset}` and should be validated "
        "against the program scope before submission."
    )

    if payload.template == "bugcrowd":
        body = [
            f"# {title}",
            _report_section("Overview of the Vulnerability", summary),
            _report_section("Business Impact", impact),
            _report_section("Steps to Reproduce", steps),
            _report_section("Proof of Concept", evidence_blocks or result_lines),
            _report_section("Affected Assets", f"- `{asset}`\n- Component: `{component}`\n- Weakness: `{weakness}`\n- Severity: `{payload.severity}`"),
            _report_section("Suggested Remediation", remediation),
            _report_section("Supporting Data", support),
        ]
    elif payload.template == "general":
        body = [
            f"# {title}",
            _report_section("Executive Summary", summary),
            _report_section("Affected Scope", f"- Asset: `{asset}`\n- Component: `{component}`\n- Weakness: `{weakness}`\n- Severity: `{payload.severity}`"),
            _report_section("Reproduction Steps", steps),
            _report_section("Evidence", evidence_blocks or result_lines),
            _report_section("Impact", impact),
            _report_section("Remediation", remediation),
            _report_section("Appendix", support),
        ]
    else:
        body = [
            f"# {title}",
            _report_section("Summary", summary),
            _report_section("Affected Asset", f"`{asset}`\n\nComponent: `{component}`"),
            _report_section("Weakness", weakness),
            _report_section("Severity", payload.severity),
            _report_section("Steps To Reproduce", steps),
            _report_section("Proof of Concept / Evidence", evidence_blocks or result_lines),
            _report_section("Impact", impact),
            _report_section("Remediation", remediation),
            _report_section("Supporting Data", support),
        ]
    return title, "\n\n".join(body).strip() + "\n", warnings


@router.post(
    "/projects/{project_id}/reports/generate",
    response_model=ReportGenerateResponse,
    tags=["reports"],
)
def generate_project_report(
    project_id: str,
    payload: ReportGenerateRequest,
    store: ProjectStore = Depends(get_project_store),
    repositories: LegacyRepositoryFactory = Depends(get_repository_factory),
    settings: Settings = Depends(get_settings),
) -> ReportGenerateResponse:
    try:
        project = store.get(project_id)
        project_dir = store.project_dir(project_id)
        repository = repositories(project_dir)
        result_index = {item.id: item for item in _merged_project_results(repository, limit=10000)}
        evidence_index = {item.id: item for item in _evidence_store(project_dir).list(project_id)}
        states = repository.load_methodology_states()
        project_notes = store.get_notes(project_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc
    except PyMongoError as exc:
        raise HTTPException(status_code=503, detail="Database unavailable") from exc

    requested_result_ids = set(payload.result_ids)
    requested_evidence_ids = set(payload.evidence_ids)
    selected_results = [result_index[item_id] for item_id in payload.result_ids if item_id in result_index]
    selected_evidence = [evidence_index[item_id] for item_id in payload.evidence_ids if item_id in evidence_index]
    title, markdown, warnings = _generate_report_markdown(
        project,
        payload,
        selected_results,
        selected_evidence,
        project_notes,
        _report_methodology_notes(settings, states) if payload.include_methodology_notes else [],
    )
    missing_results = requested_result_ids - set(result_index)
    missing_evidence = requested_evidence_ids - set(evidence_index)
    if missing_results:
        warnings.append(f"{len(missing_results)} selected result record(s) were not found.")
    if missing_evidence:
        warnings.append(f"{len(missing_evidence)} selected evidence record(s) were not found.")
    return ReportGenerateResponse(
        template=payload.template,
        title=title,
        markdown=markdown,
        warnings=warnings,
        result_count=len(selected_results),
        evidence_count=len(selected_evidence),
    )
