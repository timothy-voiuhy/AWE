# AWE — Penetration Testing Feature TODO

## Priority 2 — Passive Scanner
No active requests needed — analyse traffic already flowing through the proxy.

### Security Headers
- Flag missing: Content-Security-Policy, Strict-Transport-Security, X-Frame-Options,
  X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- Flag weak CSP (unsafe-inline, unsafe-eval, wildcard *)

### Cookie Flags
- Flag cookies missing: Secure, HttpOnly, SameSite
- Flag SameSite=None without Secure

### Sensitive Data in Responses
- Regex patterns for: AWS/GCP/Azure keys, private keys (-----BEGIN), JWT tokens,
  internal IP addresses (RFC 1918), stack traces, verbose error messages,
  email addresses, phone numbers, SSNs
- Mark findings in History with a warning indicator

### Software Versions
- Flag server banners / X-Powered-By / X-AspNet-Version revealing version strings


## Priority 7 — Findings Tracker
Structured vulnerability log alongside unstructured Notes.

- Fields per finding: Title, Severity (Critical/High/Medium/Low/Info),
  Endpoint, Method, Parameter, Evidence (HTTP request/response snippet),
  Description, Remediation, Status (Open/Confirmed/False Positive/Fixed)
- "Add Finding" context menu in History, SiteMap, Repeater — pre-fills endpoint + evidence
- Sortable/filterable findings table
- Export to Markdown report (one section per finding)

## Priority 8 — WebSocket Fuzzing
Intruder-style payload injection for WebSocket frames.

- Mark positions in a WebSocket message with §markers§ (same syntax as Intruder)
- Payload sources: paste list, load file, built-in wordlists
- Send payloads one at a time, log each response frame with payload + response content
- Filter results by response content / length
- Attach to an existing live WebSocket connection OR open a fresh one

## Priority 10 — OAST / Out-of-Band Interaction Server
Required for blind SSRF, blind XSS, blind SQLi, DNS exfiltration.

- Embedded HTTP + DNS listener (or integration with interactsh)
- Generate unique per-payload callback URLs / subdomains
- Log incoming interactions: DNS lookups, HTTP requests, SMTP connections
- Correlate callbacks back to the originating Intruder / Repeater payload
- Poll interactsh public server as fallback if no local listener
