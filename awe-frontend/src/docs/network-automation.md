---
title: Network Automation
summary: How Docker tools, graph tools, normal transforms, and composite transforms fit together.
order: 10
---

# Network Automation

AWE web has two layers of automation:

- **Tools** describe something Docker can run.
- **Transforms** describe how tool output becomes graph entities and relationships.

Use **Graph Tools** when you need to create or inspect a reusable Docker-backed tool. Use **Network Transforms** when you need to run a graph action or chain several tools together.

## The Objects

| Object | Created from | Purpose |
| --- | --- | --- |
| Docker tool | Docker Manager or Graph Tools | Runs one command in one Docker image. |
| Graph tool | Docker tool with graph contracts | Makes a Docker tool eligible for graph automation. |
| Normal transform | One graph-enabled Docker tool | Runs one tool against one selected graph entity. |
| Composite transform | Staged transform definition | Runs multiple tools and tunnels output between stages. |

## Custom Docker Tool

A custom Docker tool needs enough information for AWE to build or pull an image and run a command.

Required fields:

- `key`: stable lowercase identifier, for example `my_scanner`.
- `display_name`: human-readable name.
- `image`: Docker image tag.
- `command_template`: command that writes output into `/output`.
- `param_specs`: fields shown to the user before launch.
- `Dockerfile`: used when the image is built locally.
- `parser.py`: converts files in `/output` into typed results.

Minimal command pattern:

```text
scanner -u {url} -o /output/results.json
```

The command should write all parseable files under `/output`. The parser receives the host-side output directory and returns result objects or dictionaries.

## Graph Tool

A graph tool is a Docker tool with graph contracts.

Required graph fields:

- `input_types`: graph entity kinds the tool can accept, such as `domain`, `subdomain`, `url`, `ip`.
- `output_types`: graph entity kinds the parser produces, such as `subdomain`, `endpoint`, `tech`, `vuln`.
- `relationship_types`: relationships that connect selected input entities to output entities.
- `execution_mode`: `passive`, `safe_active`, `active`, or `high_risk`.

When a Docker tool has valid graph contracts and a parser, it appears as a **normal transform** automatically.

Example graph contract:

```json
{
  "input_types": ["domain", "subdomain"],
  "output_types": ["endpoint"],
  "relationship_types": ["has_endpoint"],
  "execution_mode": "safe_active"
}
```

## Normal Transform

A normal transform wraps one graph-enabled Docker tool.

Flow:

```text
selected graph entity -> tool parameters -> Docker tool -> parser -> graph ingest
```

Use a normal transform when:

- One tool is enough.
- The parser output should be ingested directly.
- There is no intermediate handoff between tools.

Examples:

- `httpx`: selected `domain` or `subdomain` -> live URL, port, tech data.
- `dnsx`: selected `domain` or `subdomain` -> DNS records and IPs.
- `nuclei`: selected `url` or `endpoint` -> vulnerability findings.

## Composite Transform

A composite transform is a staged tool chain.

Flow:

```text
selected graph entity
  -> stage 1 tools
  -> dedupe parsed values
  -> stage 2 tools using previous output as /input/input.txt
  -> final parser output
  -> graph ingest
```

Use a composite transform when:

- Several tools should contribute to one graph action.
- Intermediate output should not clutter the visible graph.
- A later tool should receive previous output as an input list.
- The final output should be the only result ingested.

## Multi-Tool Tunneling

For a stage with `input_source: previous`, AWE writes the deduped values from the previous stage to:

```text
/input/input.txt
```

Tools that support an input list should expose a parameter like `input_file` and use it in their command.

Example:

```text
httpx -l /input/input.txt -o /output/httpx_results.txt -status-code -title -tech-detect -silent -json
```

## Live Subdomain Enumeration

The built-in **Enumerate subdomains** transform is composite.

It is designed as:

```text
Stage 1: subfinder, assetfinder, amass, ctl
Stage 2: httpx using previous stage output
Final output: live subdomain graph entities
```

This means passive enumeration can collect broadly, but the graph receives only subdomains proven live by the probing stage. Provenance still records which tools contributed to each result.

## Choosing Where To Work

Use **Docker Manager** when you need broad Docker image and custom tool management.

Use **Graph Tools** when you are focused on making a tool graph-capable:

- defining input/output entity types,
- defining relationships,
- setting execution mode,
- creating a parser that returns graph-ready results.

Use **Network Transforms** when you are focused on graph behavior:

- running a normal transform,
- creating a composite transform,
- chaining several tools,
- controlling which stage output becomes visible graph data.

## Parser Guidelines

Parsers should return stable, typed records. Dictionaries are acceptable, but they need enough fields for graph ingestion.

Common fields:

| Output type | Useful fields |
| --- | --- |
| `subdomain` | `domain`, `value`, `sources`, `live` |
| `url` | `url`, `status_code`, `title`, `technologies` |
| `endpoint` | `url`, `method`, `parameters` |
| `ip` | `host`, `ip`, `value` |
| `vuln` | `name`, `template_id`, `severity`, `url` |

For deduplication, result models should expose a stable `key` when possible.

## Safety Modes

| Mode | Meaning |
| --- | --- |
| `passive` | Uses third-party or local data sources without touching the target directly. |
| `safe_active` | Sends limited target traffic such as HTTP probing. |
| `active` | Performs direct scanning, crawling, fuzzing, or enumeration. |
| `high_risk` | May be noisy, intrusive, or destructive if misconfigured. |

Active and high-risk work should require explicit user approval.
