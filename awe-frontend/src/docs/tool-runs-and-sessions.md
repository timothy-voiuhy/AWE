---
title: Tool runs, PoCs, and interactive sessions
summary: Inspect logs and artifacts, register PoCs, and detach from managed terminals.
order: 50
---
# Tool runs and interactive sessions

Tools can produce logs, structured results, artifacts, and an interactive session.
Graph entity output types are optional. A completed process is not automatically a
confirmed finding: add your interpretation when promoting output into evidence.

## Create a tool or PoC

From Network → Transforms, open the three-dot menu. Create a custom tool to use an
existing Docker image, or choose Register PoC to build a source archive or public
HTTPS Git repository. Git references resolve to a saved commit; archive sources
retain their SHA-256 checksum. Archives must contain regular files at the source
root, without symbolic links or parent-directory paths.

Specify a Dockerfile, command, parameters, execution kind, and output channels.
Use a batch process for unattended commands or an interactive console for prompts.
A parser is required only for structured output. Write files to `/output`; artifact
patterns are relative to that directory. PoC images use revision-specific tags.
Existing source snapshots are retained when registering an updated revision.

For a harmless interactive fixture, use an Alpine image and the command `sh`.
For a batch fixture, use `printf 'hello\n' | tee /output/report.txt`.

## Inspect a run

Open Tool runs from the Network sidebar or the Transforms options menu, or follow Full output, artifacts, and sessions from a transform log or Docker operation. Search history by tool, run ID, or message; use the status filters to find active, completed, or failed runs.
The run workspace separates execution status, logs, parsed Results, artifacts,
sessions, and evidence. Logs are paginated and searchable; download a full saved
transcript. Artifact refresh discovers new output files while a process runs.
Select a file or event range and add your interpretation to save evidence.

The default limits are 100 MiB of transcript and 1 GiB of artifact collection per
run. Truncation is recorded; the tool continues running. Limits can be configured
with `AWE_RUN_LOG_MAX_BYTES` and `AWE_RUN_ARTIFACT_MAX_BYTES`. Records remain until
project/run data is explicitly removed. Retrying a tool creates a separate run.

## Sessions

Open Interactive sessions from Terminal to attach to tool consoles, create SSH or
outbound TCP connections, or start a callback listener. Existing SSH profiles are
still available. A listener displays the advertised callback address and allocated
port and accepts one connection. An optional expected peer IP restricts acceptance.

Closing a browser tab or choosing Detach leaves the session active. One browser
connection has write control; others are read-only until they choose Take control.
Terminate closes the connection/process and releases its listener/container.
Raw TCP sessions provide a byte stream and do not support PTY resize or reliable
remote exit status. Tool-console input and resize are supported by a container PTY.

Running tool containers survive a backend restart and can be attached again.
SSH/TCP connections and pending listeners are marked disconnected after restart;
create a new connection to continue. Transcripts are retained. The default limit
is four live sessions per project and a one-hour idle timeout.

## Callback deployment

Docker Compose publishes ports 45000–45009 on loopback by default. For a reachable
lab or VPN interface, configure `AWE_CALLBACK_BIND_ADDRESS` and
`AWE_CALLBACK_ADVERTISE_HOST`. Configure the range using `AWE_CALLBACK_PORT_START`
and `AWE_CALLBACK_PORT_END`; recreate the backend after changing these settings.
Callback traffic uses these TCP ports, independently from the HTTP gateway.
