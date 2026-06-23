# AWE — Penetration Testing Feature TODO

## Priority 1 — History Search / Filter
- Add a search/filter bar to the HTTP History page
- Filter by: URL pattern (regex), method, status code range, response body content, header name/value, content-type, response length
- Highlight matching rows, hide non-matching rows
- Persist filter state while switching pages

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

## Priority 3 — Decoder / Encoder Tool
Dedicated nav page (add to _NAV between Notes and Settings).

- Input box → transformation chain → output box
- Supported transforms (chainable):
  - Base64 encode / decode
  - URL encode / decode (full + partial)
  - HTML entity encode / decode
  - Hex encode / decode
  - Unicode escape (\uXXXX) encode / decode
  - Gzip compress / decompress
  - JWT decode (all three parts, no verification needed)
  - MD5 / SHA1 / SHA256 hash
  - Reverse string
- "Smart decode" button — auto-detect and decode common formats

## Priority 4 — Finish Comparer
`src/gui/comparer.py` is a stub — implement it properly.

- Two panes side by side (left / right), each a _CodeEdit
- Diff algorithm highlights:
  - Green background: lines only in right (added)
  - Red background: lines only in left (removed)
  - Yellow background: lines present in both but changed
- "Send to Comparer" context menu item in History, SiteMap, Repeater
- Ability to compare request vs request OR response vs response
- Add Comparer to _NAV

## Priority 5 — JWT Analyzer
Dedicated tool, or panel reachable from any request/response viewer.

- Auto-detect JWT tokens in: Authorization header, Cookie, response body
- Decode and display: header JSON, payload JSON, signature (hex)
- Edit any claim value inline
- Attack modes:
  - Sign with known secret (HS256)
  - Test `alg: none` (remove signature, set alg to none)
  - RS256 → HS256 algorithm confusion (paste the server's public key as the HMAC secret)
  - Brute-force secret from a wordlist
- "Send modified JWT" — replay the request with the tampered token through the proxy

## Priority 6 — Session Manager (Multi-Account Replay)
Core workflow for IDOR and privilege escalation testing.

- Named session slots: store a session token (cookie or Authorization header) per slot
- One-click replay of any History/SiteMap request using a different session slot
- Side-by-side view of responses from two sessions for the same request
- Auto-extract session tokens from captured responses (Set-Cookie, JSON body)
- Use case: confirm that an endpoint accessible as Admin is also accessible as User

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

---

## Already Present (do not re-implement)
- Proxy: MITM, intercept, match & replace, upstream proxy chaining
- HTTP History, Site Map, Scope editor
- Repeater, Intruder (Sniper / Battering Ram / Pitchfork / Cluster Bomb)
- WebSocket inspector + live sender
- Pipeline: subdomain enum, DNS, live probe, crawl, param discovery, ffuf, nuclei, OSINT
- Docker manager, Network graph
- Notes, Settings, Browser (embedded Chromium)
