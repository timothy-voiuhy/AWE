"""
Pipeline execution engine.

Key design points
─────────────────
  • All Docker commands are run via  ["sh", "-c", command]  so shell pipes,
    redirects, and tee work correctly regardless of the container's entrypoint.
  • Scope filtering (in_scope / out_of_scope) is applied to input files written
    between stages — only in-scope hosts/domains feed downstream tools.
  • Settings (API keys, resolver paths, thread counts) are pulled from MongoDB
    per project and merged into tool params at runtime.
  • retry_tool_keys: if provided, only those tools are (re-)run — used by the
    "Retry Failed" button in the UI.

Signals
───────
  step_started(tool_key, display_name, stage)
  step_log(tool_key, line)
  step_done(tool_key, status, result_count)    status: completed|failed|skipped
  stage_done(stage_num)
  pipeline_done(session_id, success, message)
  progress(completed_steps, total_steps)
"""
import logging
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from PySide6.QtCore import QThread, Signal

from containers.results.parsers import PARSERS
from containers.tool_registry import TOOL_REGISTRY
from database.repository import AweRepository
from database.settings_repository import DEFAULTS, Keys, SettingsRepository
from pipeline.models import PipelineStep, PipelineTemplate
from pipeline.scope import filter_values

logger = logging.getLogger(__name__)


class PipelineExecutor(QThread):
    step_started  = Signal(str, str, int)
    step_log      = Signal(str, str)
    step_done     = Signal(str, str, int)
    stage_done    = Signal(int)
    pipeline_done = Signal(str, bool, str)
    progress      = Signal(int, int)

    def __init__(
        self,
        template: PipelineTemplate,
        project_dir: str,
        target: str,
        params: dict | None = None,
        in_scope: list[str] | None = None,
        out_of_scope: list[str] | None = None,
        retry_tool_keys: set[str] | None = None,
        mongo_uri: str = "mongodb://localhost:27017",
    ):
        super().__init__()
        self._template        = template
        self._project_dir     = project_dir
        self._target          = target
        self._params          = params or {}
        self._in_scope        = in_scope or []
        self._out_of_scope    = out_of_scope or []
        self._retry_keys      = retry_tool_keys   # None = run all
        self._mongo_uri       = mongo_uri
        self._stop_event      = threading.Event()
        self._session_id      = ""

    def stop(self):
        self._stop_event.set()

    # ── Main loop ─────────────────────────────────────────────────────────────

    def run(self):
        repo     = AweRepository(self._project_dir, self._mongo_uri)
        settings = SettingsRepository(self._project_dir, self._mongo_uri)

        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        output_dir = os.path.join(
            self._project_dir, "sessions",
            f"{self._template.key}_{ts}",
        )
        os.makedirs(output_dir, exist_ok=True)

        session_id = repo.create_session(
            pipeline_key=self._template.key,
            pipeline_name=self._template.name,
            target=self._target,
            output_dir=output_dir,
            params=self._params,
            in_scope=self._in_scope,
            out_of_scope=self._out_of_scope,
        )
        self._session_id = session_id

        steps = self._template.steps
        # If retrying, filter to only the requested tool keys
        if self._retry_keys:
            steps = [s for s in steps if s.tool_key in self._retry_keys]

        total = len(steps)
        completed_count = 0

        stages: dict[int, list[PipelineStep]] = {}
        for step in steps:
            stages.setdefault(step.stage, []).append(step)

        try:
            for stage_num in sorted(stages.keys()):
                if self._stop_event.is_set():
                    break
                stage_steps = stages[stage_num]
                with ThreadPoolExecutor(max_workers=max(1, len(stage_steps))) as pool:
                    futures = {
                        pool.submit(self._run_step, step, repo, settings, session_id, output_dir): step
                        for step in stage_steps
                    }
                    for future in as_completed(futures):
                        step = futures[future]
                        completed_count += 1
                        self.progress.emit(completed_count, total)
                        try:
                            status, count = future.result()
                            self.step_done.emit(step.tool_key, status, count)
                        except Exception as exc:
                            logger.exception("Step %s raised", step.tool_key)
                            self.step_done.emit(step.tool_key, "failed", 0)
                self.stage_done.emit(stage_num)

            final = "cancelled" if self._stop_event.is_set() else "completed"
            repo.update_session_status(session_id, final)
            summary = repo.session_summary(session_id)
            msg = "  ·  ".join(f"{c}: {n}" for c, n in summary.items()) or "No results"
            self.pipeline_done.emit(session_id, True, msg)

        except Exception as exc:
            logger.exception("Pipeline %s failed", self._template.key)
            try:
                repo.update_session_status(session_id, "failed")
            except Exception:
                pass
            self.pipeline_done.emit(session_id, False, str(exc))

    # ── Single step ───────────────────────────────────────────────────────────

    def _run_step(
        self,
        step: PipelineStep,
        repo: AweRepository,
        settings: SettingsRepository,
        session_id: str,
        output_dir: str,
    ) -> tuple[str, int]:
        tool = TOOL_REGISTRY.get(step.tool_key)
        if tool is None:
            return "failed", 0

        self.step_started.emit(step.tool_key, tool.display_name, step.stage)
        run_id = repo.create_tool_run(
            session_id, step.tool_key, tool.display_name, tool.category, step.stage
        )

        skip_reason = self._check_condition(step, repo, session_id)
        if skip_reason:
            self._emit(step.tool_key, f"⏭ Skipped: {skip_reason}")
            repo.update_tool_run_skipped(run_id, skip_reason)
            return "skipped", 0

        if self._stop_event.is_set():
            repo.update_tool_run_skipped(run_id, "pipeline stopped")
            return "skipped", 0

        repo.update_tool_run_started(run_id)

        params = self._build_params(settings, step)
        input_dir_host: str | None = None

        if step.input_category:
            input_dir_host, container_input_file = self._write_input_file(
                repo, session_id, step.input_category, output_dir
            )
            if container_input_file:
                params["input_file"] = container_input_file
            else:
                self._emit(step.tool_key, "⏭ No upstream results — skipping")
                repo.update_tool_run_skipped(run_id, "no upstream results")
                return "skipped", 0

        try:
            command = tool.build_command(**params)
            volumes = tool.get_volumes(output_dir, input_dir_host)
            self._emit(step.tool_key, f"▶ {command[:140]}")
            self._run_container(step.tool_key, tool, command, volumes)

            parser = PARSERS.get(step.tool_key)
            results = []
            if parser:
                try:
                    results = parser(output_dir)
                except Exception as exc:
                    self._emit(step.tool_key, f"⚠ Parser error: {exc}")

            count = 0
            if results:
                count = repo.upsert_results(session_id, run_id, tool.category, results)
                self._emit(step.tool_key, f"✓ {len(results)} raw  →  {count} new unique")

            repo.update_tool_run_done(run_id, "completed", len(results))
            return "completed", len(results)

        except Exception as exc:
            msg = str(exc)
            self._emit(step.tool_key, f"✗ {msg}")
            repo.update_tool_run_done(run_id, "failed", 0, msg)
            return "failed", 0

    def _run_container(self, tool_key: str, tool, command: str, volumes: dict):
        import docker
        client = docker.from_env()

        # Ensure image exists
        try:
            client.images.get(tool.image)
        except docker.errors.ImageNotFound:
            if tool.dockerfile and os.path.exists(tool.dockerfile):
                self._emit(tool_key, f"Building {tool.image}…")
                for chunk in client.api.build(
                    path=os.path.dirname(tool.dockerfile),
                    dockerfile=os.path.basename(tool.dockerfile),
                    tag=tool.image, rm=True, decode=True,
                ):
                    if "stream" in chunk:
                        self._emit(tool_key, chunk["stream"].rstrip())
            else:
                self._emit(tool_key, f"Pulling {tool.image}…")
                for chunk in client.api.pull(tool.image, stream=True, decode=True):
                    status = chunk.get("status", "")
                    prog   = chunk.get("progress", "")
                    if status:
                        self._emit(tool_key, f"{status} {prog}".strip())

        # Always wrap command in sh -c so pipes / redirects / tee work
        container = client.containers.run(
            image=tool.image,
            command=["sh", "-c", command],
            volumes=volumes,
            name=tool.container_name(),
            detach=True,
            remove=False,
        )

        try:
            for chunk in container.logs(stream=True, follow=True):
                if self._stop_event.is_set():
                    container.stop(timeout=5)
                    break
                line = chunk.decode("utf-8", errors="replace").rstrip()
                if line:
                    self._emit(tool_key, line)
        finally:
            try:
                container.wait(timeout=10)
            except Exception:
                pass
            try:
                container.remove(force=True)
            except Exception:
                pass

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _emit(self, tool_key: str, line: str):
        self.step_log.emit(tool_key, line)

    def _build_params(self, settings: SettingsRepository, step: PipelineStep) -> dict:
        all_settings = settings.get_all()

        base = {
            "domain":   self._target,
            "target":   self._target,
            "url":      f"https://{self._target}",
            "host":     self._target,
            "keywords": self._target.split(".")[0],
            "query":    self._target,
            # settings-backed defaults
            "api_key":    all_settings.get(Keys.GITHUB_TOKEN, ""),
            "resolvers":  all_settings.get(Keys.RESOLVER_PATH,  DEFAULTS[Keys.RESOLVER_PATH]),
            "wordlist":   all_settings.get(Keys.DEFAULT_WORDLIST, DEFAULTS[Keys.DEFAULT_WORDLIST]),
            "threads":    all_settings.get(Keys.DEFAULT_THREADS,  DEFAULTS[Keys.DEFAULT_THREADS]),
            "rate_limit": all_settings.get(Keys.DEFAULT_RATE_LIMIT, DEFAULTS[Keys.DEFAULT_RATE_LIMIT]),
            "concurrency": all_settings.get(Keys.DEFAULT_CONCURRENCY, DEFAULTS[Keys.DEFAULT_CONCURRENCY]),
        }
        # Pipeline-level params, then step-level overrides
        base.update(self._params)
        base.update(step.extra_params)
        return base

    def _check_condition(
        self, step: PipelineStep, repo: AweRepository, session_id: str
    ) -> str:
        cond = step.condition
        if not cond or cond == "always":
            return ""
        if cond.startswith("if:"):
            category = cond[3:]
            if repo.count_results(session_id, category) == 0:
                return f"no {category} results yet"
        return ""

    def _write_input_file(
        self,
        repo: AweRepository,
        session_id: str,
        category: str,
        output_dir: str,
    ) -> tuple[str | None, str]:
        values = repo.get_combined_values(session_id, category)
        if not values:
            return None, ""

        # Apply scope filter for domain/url categories
        if category in ("subdomain", "dns", "http", "crawl"):
            values = filter_values(values, self._in_scope, self._out_of_scope)

        if not values:
            self._emit("scope", f"⚠ All {category} results filtered out by scope rules")
            return None, ""

        input_dir = os.path.join(output_dir, "_inputs")
        os.makedirs(input_dir, exist_ok=True)
        fname = f"combined_{category}.txt"
        with open(os.path.join(input_dir, fname), "w") as f:
            for v in values:
                f.write(v + "\n")

        return input_dir, f"/input/{fname}"
