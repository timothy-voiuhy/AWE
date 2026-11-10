# Network graph TODO

This is the remaining work from the Maltego-style graph plan. The current vertical slice already has investigation persistence, derived graph ingestion, live-only subdomains, Cytoscape rendering, large-graph safeguards, neighborhood focus, Docker transforms, provenance, JSON export, analyst entities, and manual relationships.

## Investigation navigation

- [x] Add a compact icon action bar with tooltips and an overflow menu.
- [x] Add expand-neighbors from a selected node without replacing the current graph view.
- [x] Add area/lasso selection, saved selection sets, and richer bulk actions.
- [x] Add shortest-path-to-target highlighting.
- [x] Add connected-component and “show only selected neighborhood” analysis.
- [x] Add undo/redo for graph view changes; analyst-edit history remains queued for the edit API layer.

## Rendering and readability

- [x] Add semantic layouts: radial target map, hierarchy, concentric, timeline, and force-directed modes.
- [x] Add a portrait/landscape graph orientation toggle.
- [x] Add relationship-pair collapsing for dense areas.
- [x] Add zoom-aware label policies with explicit always-show/hide modes.
- [ ] Add entity-type-aware label priorities and collision-aware placement.
- [x] Add edge visibility controls, relationship-type filters, curved/orthogonal edge modes, and optional arrowheads.
- [x] Add minimap, zoom-to-selection, overview/reset, and persistent per-investigation display/layout preferences.
- [ ] Add WebGL or incremental rendering for investigations beyond the current safe render cap.

## Entity and relationship intelligence

- [x] Add entity deduplication candidate review and merge with canonical identity rules.
- [x] Add alias tracking and confidence-aware identity resolution.
- [ ] Add relationship directionality, confidence, timestamps, expiry, and analyst/source attribution.
- [ ] Add evidence records attached to entities and relationships, including request/response links and screenshots.
- [ ] Add finding/risk rollups, impact scoring, and target-to-vulnerability prioritization.
- [ ] Add an evidence timeline and change history for each entity.

## Transform and Docker workflow

- [x] Add ecosystem-intelligence Docker tools for ASN ownership, TLS/certificates, email/person OSINT, repository secrets, technology fingerprinting, and cloud bucket exposure.
- [x] Add architecture-specific adapters for WordPress, Drupal, cloud posture, Cloudflare zones/DNS, Kubernetes, container/IaC scanning, and OIDC identity discovery.
- [ ] Add transform chaining and a visual transform pipeline builder.
- [ ] Add per-transform scope, rate-limit, timeout, cancellation, and output limits.
- [x] Add queued-job progress, recent Docker logs, retry, cancellation, and failure diagnostics in the graph UI; partial output streaming remains queued.
- [x] Add transform approval policies and a clear active/passive execution boundary.
- [x] Add custom Docker transform manifests with typed inputs/outputs and relationship contracts.
- [ ] Add scheduled refresh and stale-result indicators for passive discovery.

## Investigation management

- [x] Add local saved views with filters, layout, visible relationship types, and selected root nodes.
- [ ] Add graph snapshots, revision diffing, restore, and branching investigations.
- [ ] Add import/export for JSON, GraphML, CSV, and Maltego-compatible mappings.
- [ ] Add collaboration-safe revision conflicts, audit events, and analyst identity.
- [ ] Add project-scoped graph retention and cleanup controls.

## Verification and operations

- [ ] Add API tests for live-subdomain filtering, focus traversal, limits, provenance, and revision conflicts.
- [ ] Add frontend interaction tests for full-workspace mode, icon actions, selection, and export.
- [ ] Add performance fixtures covering 10k+ nodes and dense relationship sets.
- [ ] Add accessibility coverage for keyboard navigation, tooltips, color contrast, and non-color status cues.
- [ ] Add observability for graph build time, payload size, render time, transform latency, and dropped/capped nodes.
