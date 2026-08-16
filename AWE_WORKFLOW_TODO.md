# AWE workflow TODO

This file tracks product-depth work that is still missing from the web-first AWE workflow. The goal is to make AWE reliable as an end-to-end assessment workspace, not just a collection of pages.

## Priority 0 — Trust and durability

- [~] Persist graph transform jobs, operation state, logs, output paths, retry metadata, and ingestion results across backend restarts. Graph transform job history is project-persisted and Docker operation snapshots now survive restarts; retry metadata is still pending.
- [~] Add first-class evidence records for entities, relationships, findings, screenshots, request/response captures, tool output, analyst notes, and timestamps. Initial evidence API, project-local store, Network Evidence page, manual records, HTTP records, and tool-output records are implemented; screenshot/file upload handling is pending.
- [~] Attach evidence records throughout Network Graph, Results, HTTP History, Site Map, Repeater, Intruder, and tool/transform output ingestion. Transform/Docker graph ingestion creates tool-output evidence, HTTP History/Site Map can promote captures to evidence, and Network Graph entities can show/create linked evidence notes; Results, Repeater, and Intruder attachment UX is still pending.
- [ ] Add audit events for analyst edits, deletes, merges, transform runs, approvals, and result ingestion.

## Priority 1 — Transform and tool reliability

- [ ] Add per-transform `timeout`, `rate_limit`, `concurrency`, `max_outputs`, `scope`, and cancellation policy.
- [ ] Enforce scope at every transform stage, including composite transform tunneled input files.
- [ ] Add parser validation with sample output, result preview, and graph-contract dry run before saving custom tools.
- [ ] Add composite-transform validation with stage compatibility checks and warnings when a tool cannot consume `/input/input.txt`.
- [ ] Unify Docker Manager and Graph Tools custom-tool editing so there is one source of truth and no duplicated form behavior.
- [ ] Add transform and Docker operation retry policies with clear handling for partial output and failed stages.

## Priority 2 — Investigation lifecycle

- [ ] Add graph snapshots, diffing, restore, and investigation branching.
- [ ] Add stale-result indicators and scheduled refresh for passive discovery.
- [ ] Add project-scoped retention and cleanup controls for graph data, traffic, screenshots, logs, and transform output directories.
- [ ] Add finding/risk rollups, impact scoring, and target-to-vulnerability prioritization.
- [ ] Add evidence timeline and change history per entity, relationship, and finding.

## Priority 3 — Interoperability

- [~] Add import/export for GraphML, CSV, Maltego-compatible mappings, and evidence bundles. Initial subdomain import supports TXT, CSV, and XLSX into Results with optional Network Graph attachment; GraphML, Maltego mappings, broader entity imports, and evidence bundle export remain pending.
- [ ] Add re-import and merge semantics for graph investigations and saved evidence.
- [ ] Add structured report export from selected findings/evidence.

## Priority 4 — Observability and scale

- [ ] Add metrics for graph build time, payload size, render time, dropped/capped nodes, transform latency, parser failures, and Docker operation failure rates.
- [ ] Add large-graph fixtures and performance testing for 10k+ nodes and dense relationships.
- [ ] Add WebGL or incremental rendering for investigations beyond the current safe render cap.
- [ ] Add entity-type-aware label priorities and collision-aware placement.

## Priority 5 — Verification and documentation

- [ ] Add API tests for composite transforms, live-subdomain filtering, focus traversal, graph limits, provenance, and revision conflicts.
- [ ] Add frontend interaction tests for graph full-workspace mode, selection tools, transform creation, transform logs, and export.
- [ ] Add accessibility coverage for keyboard navigation, tooltip behavior, color contrast, and non-color status cues.
- [ ] Expand markdown docs for parser contracts, result models, graph entity kinds, pipeline stages, auth/session handling, proxy setup, Docker lifecycle, AI approvals, and troubleshooting.
