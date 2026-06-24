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

## Priority 9 — GraphQL Tool
Dedicated page for GraphQL API testing.

- Introspection query builder: auto-fetch schema from /graphql endpoint
- Schema browser: explore types, fields, queries, mutations
- Query editor with schema-aware autocomplete
- Batch query attack: send multiple operations in one request to bypass rate limiting
- Field suggestion fuzzing: detect fields not exposed in schema but accepted by server
- "Send to GraphQL" from History when Content-Type is application/json and body
  contains `query` or `mutation`

## Priority 10 — OAST / Out-of-Band Interaction Server
Required for blind SSRF, blind XSS, blind SQLi, DNS exfiltration.

- Embedded HTTP + DNS listener (or integration with interactsh)
- Generate unique per-payload callback URLs / subdomains
- Log incoming interactions: DNS lookups, HTTP requests, SMTP connections
- Correlate callbacks back to the originating Intruder / Repeater payload
- Poll interactsh public server as fallback if no local listener


❯ check out https://github.com/ticarpi/jwt_tool and additional for our jwt testing do you think it can be of use.

  Ran 1 shell command

Now let me check what our native JWT page currently has to map the gaps:

  Searched for 1 pattern

Yes, very much so. Here's the honest gap analysis between what our native JWT page does and what jwt_tool covers:

We already have:
- alg:none (CVE-2015-2951)
- HS256 re-sign with known secret
- RS256→HS256 algorithm confusion
- Wordlist brute-force

jwt_tool covers that we're missing:

┌─────────────────────────────────────────────────────────────────────┬────────────────┬────────────────────────┐
│                               Attack                                │      CVE       │       Complexity       │
├─────────────────────────────────────────────────────────────────────┼────────────────┼────────────────────────┤
│ Null signature — send header.payload. with empty sig                │ CVE-2020-28042 │ trivial — one line     │
├─────────────────────────────────────────────────────────────────────┼────────────────┼────────────────────────┤
│ Blank password — HMAC sign with "" as secret                        │ CVE-2019-20933 │ trivial — HS256("")    │
├─────────────────────────────────────────────────────────────────────┼────────────────┼────────────────────────┤
│ Timestamp tamper — set exp far in future, nuke nbf                  │ —              │ trivial — edit payload │
├─────────────────────────────────────────────────────────────────────┼────────────────┼────────────────────────┤
│ kid SQL injection — ' OR 1=1-- in Key ID header                     │ —              │ trivial                │
├─────────────────────────────────────────────────────────────────────┼────────────────┼────────────────────────┤
│ kid path traversal — /dev/null or ../../../../dev/null              │ —              │ trivial                │
├─────────────────────────────────────────────────────────────────────┼────────────────┼────────────────────────┤
│ Psychic Signature (ES256) — ECDSA r=s=0 bypass                      │ CVE-2022-21449 │ needs cryptography lib │
├─────────────────────────────────────────────────────────────────────┼────────────────┼────────────────────────┤
│ jku/x5u key injection — point server to our JWKS                    │ CVE-2018-0114  │ needs OAST/hosted JWKS │
├─────────────────────────────────────────────────────────────────────┼────────────────┼────────────────────────┤
│ x5c header injection — self-signed cert in chain                    │ —              │ needs cryptography lib │
├─────────────────────────────────────────────────────────────────────┼────────────────┼────────────────────────┤
│ Playbook scan — all attacks sent to live endpoint, response-checked │ —              │ Docker only            │
├─────────────────────────────────────────────────────────────────────┼────────────────┼────────────────────────┤
│ Claim fuzzing — inject wordlist into specific claim values          │ —              │ Docker only            │
└─────────────────────────────────────────────────────────────────────┴────────────────┴────────────────────────┘

My take:

The first five (null sig, blank password, timestamp tamper, kid SQLi, kid path traversal) are pure stdlib Python — I can add them to the native JWT page in minutes. They catch real bugs and require no external dependencies or infrastructure.

The bottom four (Psychic Sig, jku injection, x5c injection, playbook scan, claim fuzzing) are better handled by the Docker jwt_tool that's already wired into the Pipeline page, because they either need the cryptography library, need an OAST listener, or are more powerful when run iteratively against a live endpoint with response checking.

One extra integration worth adding: a "Run jwt_tool Scan" button directly on the JWT page that takes the current token and fires the Docker container inline, showing output in the page's log — so the user doesn't have to switch to Pipeline to run a quick scan.

Want me to extend the native page with the five pure-Python attacks plus that "Run jwt_tool Scan" button?

✻ Churned for 1m 25s

❯ yes, go ahead and add them
Let me fix one logic issue in _run_jwt_tool — the inner mode check is redundant and uses the wrong string: