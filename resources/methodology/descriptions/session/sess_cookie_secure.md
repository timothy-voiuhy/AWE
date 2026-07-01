# Cookie Secure Flag

## Overview
The `Secure` flag on a cookie instructs the browser to transmit the cookie only over HTTPS connections, never over unencrypted HTTP. Without this flag, session cookies can be transmitted in cleartext if the user navigates to an HTTP version of the site (whether by typo, redirect manipulation, or active network attack), making them visible to any network observer. This is particularly dangerous on public Wi-Fi networks where an attacker can perform passive sniffing or active SSL-stripping attacks.

## How It Works
- A browser stores a session cookie set by the application over HTTPS.
- Without the `Secure` flag, if the browser makes any HTTP request to the same domain (even a redirect, image load, or CSS file), the cookie is included in the cleartext HTTP request.
- An attacker performing a man-in-the-middle (MITM) attack or passive sniffing on the local network captures the cookie.
- SSL stripping attacks (using tools like sslstrip) downgrade HTTPS connections to HTTP transparently, causing all cookies to flow in plaintext.
- The attacker injects the stolen cookie into their browser and hijacks the session.

## Impact
- Session cookie theft over unencrypted HTTP on any network path to the server.
- Particularly effective on public Wi-Fi (cafes, airports, hotels) where MITM attacks are trivial.
- SSL-stripping attacks can silently downgrade HTTPS to HTTP without user awareness.
- All session data (authentication tokens, CSRF tokens, preferences) exposed.
- Affects all users on the same network segment as the attacker (LAN, Wi-Fi hotspot).

## Where to Look
- All `Set-Cookie` response headers across the application — check every endpoint that sets cookies.
- Specifically check: login response, registration response, session renewal endpoints, API token issuance.
- Cookie values set by third-party integrations (analytics, CDN, chat widgets) — even tracking cookies can reveal session existence.
- Mixed-content pages: HTTPS pages that load HTTP sub-resources may trigger cookie transmission.
- HTTP Strict Transport Security (HSTS) presence/absence — absence worsens the impact.
- Check for cookies set during password reset flows, email verification links, and OAuth callbacks.

## Testing Steps
1. Log in to the application over HTTPS and intercept all responses in Burp Suite.
2. Search Proxy history for all `Set-Cookie` headers.
3. For each cookie, check whether the `; Secure` attribute is present in the header.
4. Example of a VULNERABLE cookie: `Set-Cookie: session=abc123; HttpOnly; Path=/`
5. Example of a SECURE cookie: `Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Strict; Path=/`
6. Navigate to the HTTP version of the site (`http://target.com`) and observe whether the browser sends the session cookie (check Burp Proxy for the outgoing `Cookie:` header).
7. If HSTS is not set, try an SSL-stripping test: use `sslstrip` on a local network or test whether the HTTP URL is accessible.
8. Check all cookies, not just the main session cookie — look for CSRF tokens, user preference cookies, and analytics cookies.
9. Use browser DevTools > Application > Cookies to inspect flag presence visually.
10. Automate detection across all responses: grep Burp history export for `Set-Cookie` lines without `Secure`.

## Payloads / Techniques

```bash
# Check Set-Cookie headers for Secure flag
curl -si https://target.com/login -X POST \
  -d "username=test&password=Test1234!" | grep -i "set-cookie"

# Look for cookies WITHOUT the Secure flag:
# Bad:  Set-Cookie: session=abc123; HttpOnly; Path=/
# Good: Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Strict; Path=/

# Test HTTP access with existing session cookie
curl -si http://target.com/dashboard \
  -H "Cookie: session=abc123_your_token_here"
# If response is 200 and server responds = cookie sent over HTTP

# SSL Strip simulation (on controlled lab network)
# Requires ARP poisoning to position as MITM
sudo arpspoof -i eth0 -t 192.168.1.100 192.168.1.1 &
sudo arpspoof -i eth0 -t 192.168.1.1 192.168.1.100 &
sudo sslstrip -l 8080
sudo iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080
# Monitor sslstrip.log for captured cookies
```

```python
import requests

def check_secure_flag(url):
    """Check all Set-Cookie headers for the Secure flag."""
    r = requests.get(url, allow_redirects=True)
    findings = []
    for cookie in r.cookies:
        secure = cookie.secure
        name = cookie.name
        findings.append({
            "name": name,
            "secure": secure,
            "value_preview": cookie.value[:10] + "..."
        })
        if not secure:
            print(f"[VULNERABLE] Cookie '{name}' missing Secure flag!")
        else:
            print(f"[OK] Cookie '{name}' has Secure flag")
    return findings

check_secure_flag("https://target.com")
```

```python
# Automated check across multiple endpoints
import requests

ENDPOINTS = [
    "/",
    "/login",
    "/register",
    "/api/auth/token",
    "/password-reset",
    "/oauth/callback"
]

BASE = "https://target.com"
session = requests.Session()

for ep in ENDPOINTS:
    r = session.get(f"{BASE}{ep}", allow_redirects=False)
    sc_headers = r.headers.get("Set-Cookie", "")
    if sc_headers and "Secure" not in sc_headers:
        print(f"[!] {ep}: Set-Cookie without Secure flag: {sc_headers[:80]}")
```

```bash
# Parse Burp Suite export for missing Secure flags
# Export Proxy history as XML, then:
python3 -c "
import xml.etree.ElementTree as ET
tree = ET.parse('burp_history.xml')
for item in tree.findall('.//item'):
    resp = item.find('response')
    if resp is not None and resp.text:
        import base64
        decoded = base64.b64decode(resp.text).decode('utf-8', errors='ignore')
        for line in decoded.split('\n'):
            if 'set-cookie' in line.lower() and 'secure' not in line.lower():
                url = item.find('url').text
                print(f'MISSING Secure: {url}: {line.strip()}')
"
```

## Burp Suite Tips
- **Scanner**: Burp's built-in scanner flags missing `Secure` flags automatically — run a passive scan across the sitemap.
- **Proxy Filter**: In Proxy history, use the "Filter by response header" option to filter for `Set-Cookie` headers, then visually scan for the `Secure` keyword.
- **Target > Issue Activity**: After spidering the application, check Issue Activity for "Cookie without secure flag" findings.
- **Extensions — Cookie Manager**: Burp extensions like "Cookie Manager" can list all observed cookies and their attributes, making it easy to identify those missing the Secure flag.
- **HTTPS-only Testing**: Temporarily configure Burp to also intercept HTTP requests and visit `http://target.com` — observe whether cookies are sent in cleartext HTTP requests.

## Tools
- **Burp Suite Scanner** — passive scan detects missing Secure flag automatically.
- **OWASP ZAP** — active/passive scanner with cookie security checks.
- **sslstrip** — demonstrates SSL downgrade attacks in lab environments.
- **Wireshark** — packet capture to visually confirm cookies in cleartext HTTP.
- **curl** — simple header inspection from command line.
- **testssl.sh** — comprehensive TLS/SSL configuration tester.
- **Nikto** — web server scanner that checks basic cookie security attributes.

## Remediation
- Add the `Secure` attribute to every cookie: `Set-Cookie: session=value; Secure; HttpOnly; SameSite=Strict; Path=/`.
- In frameworks:
  - **Django**: `SESSION_COOKIE_SECURE = True` in `settings.py`
  - **Express.js**: `res.cookie("session", value, { secure: true })`
  - **PHP**: `session_set_cookie_params(["secure" => true])` or `ini_set('session.cookie_secure', 1)`
  - **Spring Boot**: `server.servlet.session.cookie.secure=true`
- Implement HTTP Strict Transport Security (HSTS) with a long max-age and `includeSubDomains`: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`
- Redirect all HTTP traffic to HTTPS at the load balancer/web server level.
- Submit the domain to the HSTS preload list at https://hstspreload.org to prevent first-visit HTTP access.
- Regularly audit all `Set-Cookie` headers — including those set by third-party libraries and middleware.

## References
https://owasp.org/www-community/controls/SecureCookieAttribute
https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#restrict_access_to_cookies
https://portswigger.net/web-security/essential-skills/obfuscating-attacks-using-encodings
https://cwe.mitre.org/data/definitions/614.html
https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#secure-attribute
https://tools.ietf.org/html/rfc6265#section-4.1.2.5
