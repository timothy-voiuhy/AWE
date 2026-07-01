# Session Timeout / Inactivity Expiry

## Overview
Session timeout controls how long an authenticated session remains valid without user activity. An application without proper timeout controls allows a session to remain active indefinitely — meaning a stolen session token, a session left open on a shared computer, or a captured token from historical network traffic can be used to authenticate hours, days, or even years later. OWASP recommends idle timeouts of 15–30 minutes for standard applications and absolute session limits regardless of activity.

## How It Works
- User logs in; the server creates a session record with a creation time and last-activity timestamp.
- On each authenticated request, the server should check: (1) time since last activity (idle timeout), (2) total session age (absolute timeout).
- If idle timeout is not enforced, a captured token remains valid as long as no explicit logout occurs.
- If absolute timeout is not enforced, an active user whose session is somehow stolen exposes themselves indefinitely.
- Some applications reset the idle timer on every request, which is correct — but fail to enforce an absolute maximum.
- Long-lived sessions dramatically expand the attack window for any session theft vulnerability.

## Impact
- Stolen session tokens remain exploitable for hours, days, or indefinitely.
- Shared computers expose all users who visit without logging out (kiosk, library scenarios).
- Longer session lifetimes increase the value and impact of XSS-based cookie theft.
- Compliance failures: PCI DSS requires 15-minute idle session timeout for payment applications.
- Historical token theft (from logs, proxies, or cache) remains effective long after the fact.

## Where to Look
- Session cookie `Max-Age` or `Expires` attribute — long or absent values indicate no expiry.
- Server-side session configuration in frameworks (PHP session.gc_maxlifetime, Django SESSION_COOKIE_AGE, etc.).
- Application behavior after extended inactivity — manually wait 30+ minutes and test.
- "Remember me" features that extend session lifetime significantly.
- API token endpoints — JWT `exp` claims, OAuth token lifetimes.
- Administrative interfaces that should have shorter timeouts than regular user sessions.

## Testing Steps
1. Log in and note the session token and any `Expires`/`Max-Age` attributes on the session cookie.
2. If the cookie has no `Expires` attribute, it is a session cookie (browser-session lifetime) — still test server-side expiry.
3. Wait 30 minutes without any interaction, then attempt to access an authenticated endpoint.
4. If the request succeeds, the idle timeout is either absent or longer than 30 minutes.
5. Wait progressively longer: 1 hour, 2 hours, 24 hours — noting when the session expires.
6. Test absolute timeout: make a request every 5 minutes to keep the session active; observe whether the server enforces a maximum session age (e.g., 8 hours even with activity).
7. Test "remember me" functionality: check if it issues a separate, longer-lived token and whether that token is properly secured.
8. Test session behavior after browser restart — if the session cookie is a session cookie (no expiry), it should not persist after browser close (browser-level control, but verify server-side).
9. Verify timeout messages are informative but not verbose (avoid leaking session IDs in timeout warnings).
10. Check if the server regenerates the session token on timeout re-authentication (prevents token reuse after expiry and re-login).

## Payloads / Techniques

```python
import requests
import time

BASE = "https://target.com"

# Login
s = requests.Session()
s.post(f"{BASE}/login", data={"username": "test", "password": "Test1234!"})
token = s.cookies.get("session")
print(f"[+] Session token: {token}")

# Test idle timeout
intervals = [5, 15, 30, 60, 120, 360, 1440]  # minutes

for minutes in intervals:
    print(f"[*] Waiting {minutes} minutes...")
    time.sleep(minutes * 60)
    
    s2 = requests.Session()
    s2.cookies.set("session", token)
    r = s2.get(f"{BASE}/api/profile")
    
    if r.status_code == 200:
        print(f"[!] Session STILL VALID after {minutes} minutes idle")
    else:
        print(f"[OK] Session expired after {minutes} minutes idle (status: {r.status_code})")
        break
```

```bash
# Quick idle timeout test with curl
TOKEN="your_session_token_here"

# Baseline check
echo "[*] Baseline check:"
curl -si -H "Cookie: session=$TOKEN" https://target.com/api/profile | head -5

# Wait 30 minutes
echo "[*] Waiting 1800 seconds (30 min)..."
sleep 1800

echo "[*] Post-idle check:"
curl -si -H "Cookie: session=$TOKEN" https://target.com/api/profile | head -5
# If 200 -> No 30-min idle timeout enforced
```

```python
# Test absolute session timeout (keep session alive, check absolute max)
import requests, time

BASE = "https://target.com"
s = requests.Session()
s.post(f"{BASE}/login", data={"username": "test", "password": "Test1234!"})

start_time = time.time()
interval_min = 5

while True:
    r = s.get(f"{BASE}/api/profile")
    elapsed = (time.time() - start_time) / 60
    
    if r.status_code != 200:
        print(f"[OK] Absolute session timeout: ~{elapsed:.0f} minutes")
        break
    else:
        print(f"[*] Session alive at {elapsed:.0f} minutes")
    
    time.sleep(interval_min * 60)
    
    if elapsed > 24 * 60:
        print("[!] Session still alive after 24 hours - NO absolute timeout!")
        break
```

```bash
# Check cookie Expires / Max-Age
curl -si https://target.com/login -X POST \
  -d "username=test&password=Test1234!" | grep -i "set-cookie"

# Examples:
# Session cookie (no expiry, browser-controlled):
#   Set-Cookie: session=abc; HttpOnly; Secure; SameSite=Strict; Path=/
# Long-lived cookie (30 days - suspicious for session token):
#   Set-Cookie: session=abc; Max-Age=2592000; HttpOnly; Secure; Path=/
# Proper short-lived:
#   Set-Cookie: session=abc; Max-Age=900; HttpOnly; Secure; SameSite=Strict; Path=/
```

```python
# Check JWT expiry
import base64, json

token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMjMsImV4cCI6OTk5OTk5OTk5OX0.sig"
payload = token.split(".")[1]
payload += "=" * (4 - len(payload) % 4)  # fix padding
data = json.loads(base64.b64decode(payload))
print(f"JWT exp claim: {data.get('exp', 'NOT SET')}")

import datetime
if "exp" in data:
    exp_dt = datetime.datetime.fromtimestamp(data["exp"])
    print(f"Expires: {exp_dt}")
    delta = exp_dt - datetime.datetime.now()
    print(f"Time until expiry: {delta}")
    if delta.days > 1:
        print("[!] JWT has very long expiry - consider reducing")
```

## Burp Suite Tips
- **Repeater — Time-delayed Testing**: Send an authenticated request to Repeater and manually come back 30 minutes later to resend it — a quicker way to test idle timeout without scripting.
- **Macro + Session Handling**: Configure a Burp macro that checks whether the session is still valid by making a canary request, then compare responses over time.
- **Scanner**: Burp's scanner includes session timeout checks — run an active scan and look for "Session token not refreshed after inactivity" findings.
- **Cookie Inspector**: Check the raw `Set-Cookie` header in any response to find `Max-Age` / `Expires` values that reveal server-side timeout configuration.
- **Intruder — Long Polling**: Set up Intruder with a rate-limited payload to periodically ping an authenticated endpoint over several hours, logging when the session first fails — automates absolute timeout testing.

## Tools
- **Burp Suite** — proxy, repeater, and scanner for session timeout testing.
- **curl + sleep scripts** — simple idle timeout testing from the command line.
- **Python requests** — automated timeout duration testing with precise timing.
- **OWASP ZAP** — active scanner with session timeout rules.
- **jwt_tool** — for JWT-based applications, inspect and manipulate `exp` claims.
- **Nessus / Qualys** — enterprise scanners that check session timeout compliance.

## Remediation
- Set an idle session timeout of 15–30 minutes for standard applications; 5–10 minutes for sensitive applications (banking, healthcare).
- Set an absolute session timeout regardless of activity (e.g., 8 hours maximum for a standard work session).
- Regenerate the session token after each re-authentication following a timeout.
- Warn users with a countdown dialog before session expiry (improves UX and ensures they understand the timeout).
- Framework configurations:
  - **PHP**: `session.gc_maxlifetime = 1800` (30 min) in php.ini; `session.cookie_lifetime = 0`
  - **Django**: `SESSION_COOKIE_AGE = 1800`; `SESSION_SAVE_EVERY_REQUEST = True` for idle reset
  - **Express.js**: `express-session` with `cookie: { maxAge: 1800000 }` and rolling: true for idle reset
  - **Spring Boot**: `server.servlet.session.timeout=30m`
- For JWT: set short `exp` claims (15–60 minutes) and use refresh tokens with their own separate timeout.
- Remove "Remember Me" functionality or implement it as a separate, more restricted long-lived token (not the primary session token).

## References
https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/07-Testing_Session_Timeout
https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#session-expiration
https://cwe.mitre.org/data/definitions/613.html
https://portswigger.net/web-security/authentication/other-mechanisms
https://owasp.org/www-community/controls/Session_Expiration
