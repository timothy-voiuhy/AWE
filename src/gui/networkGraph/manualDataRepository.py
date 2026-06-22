# ── Manual data repository ────────────────────────────────────────────────────

class ManualDataRepository:
    """Thin wrapper around AweRepository that maintains a 'manual' session
    so the user can write arbitrary nodes directly into the database."""

    _PIPELINE_KEY = "manual"

    def __init__(self, project_dir: str, target: str):
        self._project_dir = project_dir
        self._target      = target
        self._session_id: str | None  = None
        self._run_id:     str | None  = None

    def _ensure_session(self):
        if self._session_id:
            return
        from database.repository import AweRepository
        repo = AweRepository(self._project_dir)
        # Query directly by pipeline_key — avoids list_sessions pagination limits
        doc = repo._db.scan_sessions.find_one(
            {"project_dir": repo._project_dir,
             "pipeline_key": self._PIPELINE_KEY},
            sort=[("started_at", -1)],
        )
        if doc:
            from database.repository import _str
            self._session_id = _str(doc["_id"])
        if not self._session_id:
            self._session_id = repo.create_session(
                pipeline_key=self._PIPELINE_KEY,
                pipeline_name="Manual Additions",
                target=self._target,
                output_dir="",
            )
        for run in repo.get_tool_runs(self._session_id):
            if run.get("tool_key") == "manual":
                self._run_id = run["id"]
                return
        self._run_id = repo.create_tool_run(
            self._session_id, "manual", "Manual Entry", "manual", stage=0,
        )
        repo.update_tool_run_started(self._run_id)

    def _repo(self):
        from database.repository import AweRepository
        return AweRepository(self._project_dir)

    def add_subdomain(self, domain: str, ips: list[str] = None) -> bool:
        from containers.results.models import SubdomainResult
        self._ensure_session()
        r = SubdomainResult(domain=domain, ip_addresses=[i for i in (ips or []) if i])
        r.add_source("manual")
        self._repo().upsert_results(self._session_id, self._run_id, "subdomain", [r])
        return True

    def add_port(self, host: str, port: int, protocol: str = "tcp",
                 service: str = "", version: str = "") -> bool:
        from containers.results.models import PortResult
        self._ensure_session()
        r = PortResult(host=host, port=port, protocol=protocol,
                       service=service, version=version)
        r.add_source("manual")
        self._repo().upsert_results(self._session_id, self._run_id, "portscan", [r])
        return True

    def add_tech(self, url: str, tech: str,
                 status_code: int = 0, title: str = "") -> bool:
        from containers.results.models import LiveHost
        self._ensure_session()
        r = LiveHost(url=url, technologies=[tech],
                     status_code=status_code, title=title)
        r.add_source("manual")
        self._repo().upsert_results(self._session_id, self._run_id, "http", [r])
        return True

    def add_vuln(self, name: str, severity: str, url: str,
                 description: str = "", template_id: str = "manual") -> bool:
        from containers.results.models import VulnFinding
        self._ensure_session()
        r = VulnFinding(template_id=template_id, name=name,
                        severity=severity, url=url, description=description)
        r.add_source("manual")
        self._repo().upsert_results(self._session_id, self._run_id, "vuln", [r])
        return True

    def add_endpoint(self, url: str, method: str = "GET",
                     status_code: int = 0) -> bool:
        from containers.results.models import EndpointResult
        self._ensure_session()
        r = EndpointResult(url=url, method=method, status_code=status_code)
        r.add_source("manual")
        self._repo().upsert_results(self._session_id, self._run_id, "crawl", [r])
        return True

    def add_osint(self, result_type: str, value: str,
                  extra: str = "", provider: str = "") -> bool:
        from containers.results.models import OSINTResult
        self._ensure_session()
        r = OSINTResult(result_type=result_type, value=value,
                        extra=extra, provider=provider)
        r.add_source("manual")
        self._repo().upsert_results(self._session_id, self._run_id, "osint", [r])
        return True

    def add_cdn(self, subdomain: str, provider: str,
                proxy_type: str = "CDN",
                origin_ips: list[str] = None,
                bypass_hints: list[str] = None) -> bool:
        from containers.results.models import CdnResult
        self._ensure_session()
        r = CdnResult(
            subdomain=subdomain,
            provider=provider,
            proxy_type=proxy_type,
            origin_masked=True,
            origin_ips=[ip for ip in (origin_ips or []) if ip],
            bypass_hints=[h for h in (bypass_hints or []) if h],
        )
        r.add_source("manual")
        self._repo().upsert_results(self._session_id, self._run_id, "cdn", [r])
        return True

    def save_info_note(self, parent_node_id: str, content: str) -> None:
        """Insert or replace the note attached to a graph node."""
        from datetime import datetime, timezone
        self._ensure_session()
        result_key = f"info:{parent_node_id}"
        self._repo()._db.results.update_one(
            {
                "session_id": self._session_id,
                "category":   "info",
                "result_key": result_key,
            },
            {
                "$set": {
                    "data":    {"parent_node_id": parent_node_id, "content": content},
                    "sources": ["manual"],
                },
                "$setOnInsert": {
                    "session_id":  self._session_id,
                    "tool_run_id": self._run_id,
                    "category":    "info",
                    "result_key":  result_key,
                    "created_at":  datetime.now(timezone.utc).isoformat(),
                },
            },
            upsert=True,
        )

    def get_info_note(self, parent_node_id: str) -> str:
        """Return existing note content for a node, or ''."""
        self._ensure_session()   # populate _session_id before querying
        result_key = f"info:{parent_node_id}"
        try:
            doc = self._repo()._db.results.find_one(
                {"session_id": self._session_id,
                 "category": "info", "result_key": result_key},
                {"data.content": 1},
            )
            return (doc or {}).get("data", {}).get("content", "") if doc else ""
        except Exception:
            return ""

    def add_custom_node(
        self, parent_node_id: str, label: str, description: str = ""
    ) -> None:
        from containers.results.models import CustomNode
        self._ensure_session()
        r = CustomNode(
            parent_node_id=parent_node_id,
            label=label,
            description=description,
        )
        r.add_source("manual")
        self._repo().upsert_results(self._session_id, self._run_id, "custom", [r])

    def add_origin_to_cdn(
        self, subdomain: str, provider: str, origin_ip: str
    ) -> bool:
        """Append an origin IP to an existing CDN/RP result, or create one.

        `upsert_results` uses $setOnInsert so it won't touch existing data.
        We need a targeted $addToSet on data.origin_ips for the existing doc.
        """
        if not origin_ip:
            return False
        from containers.results.models import CdnResult
        self._ensure_session()
        repo = self._repo()
        result_key = CdnResult(subdomain=subdomain, provider=provider).key

        # Try to update any existing document across all sessions
        res = repo._db.results.update_one(
            {"category": "cdn", "result_key": result_key},
            {"$addToSet": {"data.origin_ips": origin_ip}},
        )
        if res.matched_count == 0:
            # No existing record anywhere — create one in the manual session
            r = CdnResult(
                subdomain=subdomain, provider=provider,
                origin_masked=True, origin_ips=[origin_ip],
            )
            r.add_source("manual")
            repo.upsert_results(self._session_id, self._run_id, "cdn", [r])
        return True

