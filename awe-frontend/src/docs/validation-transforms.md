---
title: Native vulnerability validation transforms
summary: Request contexts, private markers, callback verification, workflow sequences, and evidence interpretation.
order: 56
---
# Native vulnerability validation transforms

The native suite adds 29 graph transforms backed by one `awe/validation:1` Docker
image. Open **Transforms → ⋮ → Coverage matrix** to compare tested detectors,
existing scanner adapters, and material gaps. A tested detector is not a promise
that every application vulnerability in its family will be found.

## Run a check

Select a URL/endpoint entity, find a transform through catalog search or the coverage
matrix, and open Run. Supply the profile's required parameters and approve execution.
The tool runner collects logs, structured findings, `validation-report.json`, and
`validation-evidence.jsonl`. Build the shared image from Docker Manager if necessary.

All new transforms require active-execution approval. The optional **Allow explicitly
configured state-changing requests** checkbox is also required for custom POST, PUT,
PATCH, DELETE, logout, and XML requests. The two GraphQL profiles use fixed read-only
POST queries; they do not submit mutations. No arbitrary command or system-file
retrieval payloads are included in this suite.

## Request contexts

The primary and peer contexts are secret JSON parameters. They are passed through
the container environment, omitted from the command, and redacted from stored run
parameters. They support `headers`, `method`, `body`, and a same-origin `url`.

```json
{
  "method": "GET",
  "headers": {
    "Authorization": "Bearer OWNER_TOKEN",
    "Cookie": "session=OWNER_SESSION"
  }
}
```

Captured requests can be supplied as `raw_request` inside the JSON context:

```json
{"raw_request":"GET /api/records/42 HTTP/1.1\r\nHost: lab.example\r\nAuthorization: Bearer OWNER_TOKEN\r\n\r\n"}
```

The captured path must stay on the selected origin. Host and hop-by-hop framing
headers are discarded; the transport constructs them. Redirects are not followed,
cookies are not automatically persisted, and ambient proxy settings are not used.
Keep credentials in the secret context rather than embedding them in the target URL.

## Authorization and JWT acceptance

Horizontal, vertical, and tenant-isolation checks replay the **same object URL** with
two distinct credential contexts. Supply a private marker of 8–256 characters that
identifies content the second identity must not receive. You define the identities,
roles, tenants, and ownership policy; the runner does not infer these facts.

A credentialed baseline must contain the marker and an anonymous control must not.
The peer response is only reported when it succeeds and contains the private marker.
Response length/status similarity alone is not a finding. Use `credential_headers`
in the primary context to name additional authentication headers that must be removed
from anonymous controls. Standard Authorization, Cookie, Proxy-Authorization, and
API-key headers are removed automatically.

The anonymous-access profile instead requires a `negative_control_url` in the primary
context, for example `/api/records/not-a-real-object`, that must not return the marker.
JWT profiles require a signed bearer JWT plus the private marker and anonymous
control. They test a payload mutation without resigning or `alg:none`; other credential
headers are removed from the modified-token request. Tokens and claims are not saved
in evidence. These two checks do not establish every JWT/OAuth attack class.

## Session and workflow checks

Session-cookie review evaluates only the configured cookie names. Form-token review
is a CSRF candidate detector, not a cross-site exploit demonstration: SameSite,
Origin validation and actual state-changing behavior still need review.

Logout replay requires a `logout` request in the primary context:

```json
{
  "headers": {"Authorization":"Bearer OWNER_TOKEN"},
  "logout": {"url":"/logout","method":"POST","body":""}
}
```

The workflow-invariant profile requires distinct, isolated primary and peer contexts,
one to five `valid_steps` and one to five `invalid_steps` in the primary context, and
a private success marker. Each step specifies a same-origin URL, method, optional
headers and body. A valid sequence must establish the marker before the invalid
sequence is assessed. Both contexts retain their supplied credentials independently.

```json
{
  "headers":{"Authorization":"Bearer VALID_WORKFLOW_TOKEN"},
  "valid_steps":[{"url":"/lab/start","method":"POST","body":""},{"url":"/lab/approved-result"}],
  "invalid_steps":[{"url":"/lab/approved-result"}]
}
```

The peer context supplies the separate invalid-workflow identity/session. The runner
does not harvest changing CSRF tokens, maintain login cookie jars, reset transactions,
or invent a business invariant. Reaching the success marker through both sequences is
a candidate requiring confirmation of clean starting state and business impact.
Sequential execution does not test race conditions.

## Input-validation canaries

- Redirect and CRLF checks require the query-parameter name. They inspect a canary
  redirect or custom response header without following redirects.
- SSTI requires the parameter name and checks two independent arithmetic evaluations;
  it does not test command execution.
- Traversal requires the parameter name, a researcher-controlled canary filename,
  and its private marker. Controls must not already contain the marker. Default
  system-file paths are not supplied.

## SSRF and XXE callback evidence

The callback context contains an owned HTTP callback and an independent monitor:

```json
{
  "callback_url":"https://collector.example/callback",
  "monitor_url":"https://collector.example/observations",
  "monitor_headers":{"Authorization":"Bearer MONITOR_TOKEN"},
  "poll_delay":1
}
```

The runner appends a fresh `awe_probe` query token to both URLs. Before injecting the
callback, it reads the monitor and refuses to proceed if the fresh token is already
present or reflected. After the target request, up to three monitor polls look for
that token. `poll_delay` is bounded to 0–5 seconds. Target credentials are never sent
to the monitor; only its explicitly supplied monitor headers are used.

The research environment must actually record callbacks and expose token observations.
A generic echo endpoint is not a monitor. AWE's TCP shell callback listeners are not
HTTP observation services. Missing or delayed observations are **inconclusive**, not
proof that SSRF/XXE is absent. XXE sends a harmless external-entity callback document
and requires explicit permission for its POST; it does not request local files.

## Bounds and evidence

Default budget: 12 requests, 10-second socket timeout, 1 MiB response body, 0.1-second
spacing. Budgets allow at most 32 requests, a 20-second socket timeout and 2 MiB per
response; the shared tool has a 180-second execution timeout. TLS verification is on
unless **Allow untrusted TLS certificates in this test environment** is selected.

Reports preserve methods, redacted URLs, header **names**, status codes, byte counts,
hashes and proof references. They omit request/response bodies, cookie values, bearer
tokens and raw response secrets. Response bodies exist only in process memory for
the check. Query values are redacted in evidence. Use Tool Runs to review artifacts
and attach your interpretation as evidence.

Report outcomes are `findings`, `observations`, `no_findings`, or `inconclusive`.
Inconclusive execution exits nonzero and retains its report as an artifact. Each
finding separately carries `candidate` or `verified_behavior`; verified behavior
still needs an application-policy and impact assessment. No result is a certificate
that an application is free of vulnerabilities.
