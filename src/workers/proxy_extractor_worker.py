from __future__ import annotations

import hashlib
import logging
import sys
import time

from workers.protocol import WorkerMessage, encode_message

log = logging.getLogger(__name__)


def _send(message_type: str, job_id: str = "", **payload) -> None:
    sys.stdout.write(encode_message(message_type, job_id, **payload))
    sys.stdout.flush()


def _proxy_collection(mongo_uri: str):
    from pymongo import MongoClient

    client = MongoClient(mongo_uri)
    return client["awe_proxy_traffic"]["traffic"]


def _write_results(
    project_dir: str,
    mongo_uri: str,
    target: str,
    results: dict,
    review_candidates: dict,
) -> dict:
    from database.repository import AweRepository

    repo = AweRepository(project_dir, mongo_uri)
    session_id = repo.get_or_create_proxy_session(target)
    run_id = repo.get_proxy_tool_run_id(session_id)

    written_by_category: dict[str, int] = {}
    for category, items in results.items():
        if items:
            written_by_category[category] = repo.upsert_results(
                session_id, run_id, category, items
            )

    review_counts = {"jwt": 0, "graphql": 0}
    for jwt_hit in review_candidates.get("jwt", []):
        token = jwt_hit["token"]
        dedup_key = hashlib.sha256(token.encode()).hexdigest()
        created = repo.create_review_item(
            queue_name="jwt",
            kind="jwt_header" if jwt_hit["header_name"] == "Authorization" else "jwt_cookie",
            summary=f"{jwt_hit['header_name']} - {jwt_hit['source_url']}",
            payload={"token": token, "source_url": jwt_hit["source_url"]},
            dedup_key=dedup_key,
        )
        if created:
            review_counts["jwt"] += 1

    for gql_hit in review_candidates.get("graphql", []):
        dedup_key = hashlib.sha256(
            f"{gql_hit['endpoint']}|{gql_hit['query']}".encode()
        ).hexdigest()
        summary = gql_hit["query"].strip().splitlines()[0][:80]
        created = repo.create_review_item(
            queue_name="graphql",
            kind="graphql_request",
            summary=f"{gql_hit['endpoint']} - {summary}",
            payload={
                "endpoint": gql_hit["endpoint"],
                "query": gql_hit["query"],
                "variables": gql_hit["variables"],
            },
            dedup_key=dedup_key,
        )
        if created:
            review_counts["graphql"] += 1

    return {
        "session_id": session_id,
        "run_id": run_id,
        "written_by_category": written_by_category,
        "review_counts": review_counts,
    }


def _run_extract(job_id: str, payload: dict) -> None:
    from database.scope import ScopeConfig
    from proxy.traffic_extractor import TrafficExtractor

    started = time.monotonic()
    project_dir = str(payload["project_dir"])
    target = str(payload.get("target") or "")
    mongo_uri = str(payload.get("mongo_uri") or "mongodb://localhost:27017")
    scope = ScopeConfig.from_dict(payload.get("scope") or {})
    batch_size = int(payload.get("batch_size") or 100)
    batch_pause_ms = int(payload.get("batch_pause_ms") or 15)
    max_request_body_scan_chars = int(payload.get("max_request_body_scan_chars") or 250_000)
    max_secret_scan_chars = int(payload.get("max_secret_scan_chars") or 250_000)

    _send("started", job_id, project_dir=project_dir, target=target)
    col = _proxy_collection(mongo_uri)
    results, review_candidates = TrafficExtractor().extract(
        col,
        scope,
        batch_size=batch_size,
        batch_pause_ms=batch_pause_ms,
        max_request_body_scan_chars=max_request_body_scan_chars,
        max_secret_scan_chars=max_secret_scan_chars,
    )
    write_summary = _write_results(
        project_dir,
        mongo_uri,
        target,
        results,
        review_candidates,
    )
    duration_ms = int((time.monotonic() - started) * 1000)
    extracted_counts = {category: len(items) for category, items in results.items()}
    review_detected = {
        queue: len(items) for queue, items in review_candidates.items()
    }
    _send(
        "done",
        job_id,
        duration_ms=duration_ms,
        extracted_counts=extracted_counts,
        review_detected=review_detected,
        **write_summary,
    )


def main() -> int:
    logging.basicConfig(level=logging.INFO, stream=sys.stderr)
    _send("ready", worker="proxy_extractor", pid=__import__("os").getpid())

    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            msg = WorkerMessage.from_json_line(line)
            if msg.type == "shutdown":
                _send("stopped", msg.job_id)
                return 0
            if msg.type == "ping":
                _send("pong", msg.job_id)
                continue
            if msg.type == "start_extract":
                _run_extract(msg.job_id, msg.payload)
                continue
            _send("error", msg.job_id, error=f"unknown command: {msg.type}")
        except Exception as exc:
            log.exception("proxy extractor worker command failed")
            try:
                _send("error", getattr(locals().get("msg", None), "job_id", ""), error=str(exc))
            except Exception:
                pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
