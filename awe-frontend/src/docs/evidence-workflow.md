---
title: Evidence Workflow
summary: How AWE records durable evidence from transforms, Docker tools, HTTP captures, and analyst notes.
order: 20
---

# Evidence Workflow

Evidence records are project-scoped records that preserve why a graph entity, finding, request, or analyst conclusion matters.

Evidence is stored with the project, so it can survive backend restarts and travel with the workspace.

## Evidence Records

Each record contains:

- `title`: short label shown in the Evidence page.
- `summary`: analyst-readable explanation.
- `kind`: `tool_output`, `http`, `screenshot`, `note`, `finding`, `file`, or `manual`.
- `source_type`: where the evidence came from, such as `transform`, `docker_tool`, `traffic`, or `manual`.
- `source_id`: source object ID, such as a transform job ID or traffic ID.
- `investigation_id`: optional graph investigation link.
- `entity_ids`: optional graph entity IDs connected to the evidence.
- `relationship_ids`: optional graph relationship IDs connected to the evidence.
- `tags`: searchable labels.
- `data`: structured JSON payload.

## Automatic Evidence

AWE creates evidence automatically when graph-capable tool output is ingested.

Current automatic sources:

- Network transform runs.
- Composite transform runs.
- Docker tool runs that are ingested into the graph.

Those records include parser counts, graph ingestion counts, tool keys, transform IDs, output directories, redacted parameters, and stage definitions for composite transforms.

## HTTP Capture Evidence

HTTP History and Site Map can promote a captured transaction to evidence.

Use **Save evidence** on the selected request or endpoint. AWE stores the method, host, path, status code, timestamp, request, and response body under a durable evidence record.

## Manual Evidence

Use **Network > Evidence** to create manual evidence.

Manual evidence is useful for:

- notes that explain exploitability,
- external links or references,
- screenshots or file references,
- findings that are not produced by a parser yet,
- linking several graph entity IDs to one observation.

## Linking Strategy

Prefer linking evidence to the smallest meaningful graph object.

Examples:

| Situation | Link evidence to |
| --- | --- |
| One vulnerable endpoint | Endpoint entity |
| One affected host | Subdomain or IP entity |
| A relationship discovered by a transform | Relationship ID |
| A broad note about the whole investigation | Investigation ID only |

## Current Limits

The initial evidence workflow stores records and structured JSON. File and screenshot upload handling still needs to be added.

Network Graph, Results, Repeater, and Intruder still need direct evidence attachment controls. Until those controls exist, use manual records and entity IDs from the graph detail panel.
