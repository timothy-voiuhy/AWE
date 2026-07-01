# Concurrent Session Handling

## Overview
Concurrent session handling refers to how an application manages multiple active sessions for the same user account simultaneously. Applications that allow unlimited concurrent sessions make it trivial for an attacker to use a stolen session token indefinitely without the legitimate user detecting the intrusion. Alternatively, applications that fail to track and limit concurrent sessions may also be vulnerable to session fixation or resource exhaustion attacks.

## How It Works
- A user logs in from a browser and receives Session Token A.
- The same user (or an attacker with stolen credentials) logs in from another device and receives Session Token B.
- If the application allows both sessions simultaneously without notification or enforcement, both remain valid.
- An attacker using a stolen credential set can maintain their own session even while the legitimate user is also active.
- Some applications handle this by invalidating the oldest session, but this causes denial-of-service if an attacker loops logins to kick the real user out.
- Proper controls require user notification (email/push) when a new session is created from an unknown device.

## Impact
- An attacker with stolen credentials can silently maintain a parallel session alongside the legitimate user.
- No detection or notification that multiple sessions are active.
- Denial of service if the attacker continually creates new sessions, forcing the victim's session to expire.
- Session flooding can exhaust server-side session storage.
- In applications like banking or email, concurrent access by attacker and victim simultaneously enables covert data exfiltration.

## Where to Look
- Login response — does the server issue a new token or reuse an existing one?
- User account settings panel — check for a "Active Sessions" or "Logged-in devices" feature.
- Session invalidation policy documentation or error messages.
- API login endpoint behavior when called multiple times with the same credentials.
- Server-side session storage (Redis, database) configuration — whether old sessions are preserved or overwritten.
- E-commerce and banking apps that enforce single-session policies.

## Testing Steps
1. Log in with test credentials in Browser A. Note Session Token A.
2. Log in with the same credentials in Browser B (incognito/private mode). Note Session Token B.
3. In Browser A, navigate to an authenticated page — confirm the session is still active.
4. In Browser B, also navigate to an authenticated page — confirm both sessions work simultaneously.
5. If both sessions are active: the application allows unlimited concurrent sessions (may or may not be a vulnerability depending on context — report as informational or risk depending on sensitivity).
6. Verify whether any notification was sent (email, SMS, push) alerting the account owner of the new login.
7. Test whether the application provides a "view/manage active sessions" feature and whether it correctly lists all sessions.
8. Test session termination: end Session A from the "Active Sessions" page — confirm Session A is invalidated and Session B remains.
9. Test the reverse: end ALL sessions — confirm both A and B are invalidated.
10. Attempt session flooding: script rapid logins 50–100 times in a loop; observe behavior for denial of service or performance degradation.

## Payloads / Techniques

```python
import requests
import threading

BASE = "https://target.com"

sessions = []

def login():
    s = requests.Session()
    r = s.post(f"{BASE}/login", data={
        "username": "victim",
        "password": "Test1234!"
    })
    token = s.cookies.get("session")
    sessions.append((s, token))
    return s, token

# Create 5 concurrent sessions
threads = [threading.Thread(target=login) for _ in range(5)]
for t in threads:
    t.start()
for t in threads:
    t.join()

print(f"[+] Created {len(sessions)} sessions")

# Test which sessions are still valid
for i, (s, token) in enumerate(sessions):
    r = s.get(f"{BASE}/api/profile")
    status = "VALID" if r.status_code == 200 else "INVALID"
    print(f"Session {i+1} ({token[:16]}...): {status}")
```

```bash
# Bash: Test concurrent sessions with curl
# Session 1
curl -c session1.txt -X POST https://target.com/login \
  -d "username=victim&password=Test1234!" -s -o /dev/null
TOKEN1=$(grep session session1.txt | awk '{print $NF}')
echo "Session 1: $TOKEN1"

# Session 2 (same credentials)
curl -c session2.txt -X POST https://target.com/login \
  -d "username=victim&password=Test1234!" -s -o /dev/null
TOKEN2=$(grep session session2.txt | awk '{print $NF}')
echo "Session 2: $TOKEN2"

# Test both sessions
echo "--- Session 1 access ---"
curl -H "Cookie: session=$TOKEN1" https://target.com/api/profile

echo "--- Session 2 access ---"
curl -H "Cookie: session=$TOKEN2" https://target.com/api/profile
```

```bash
# Session flood test (DoS via concurrent login)
for i in $(seq 1 50); do
  curl -s -X POST https://target.com/login \
    -d "username=victim&password=Test1234!" \
    -c /dev/null -b /dev/null &
done
wait
echo "Flood complete — check server stability and victim's session"
```

```python
# Check if victim is notified of new login
import requests, imaplib, time

# Login as attacker
s = requests.Session()
s.post("https://target.com/login", data={
    "username": "victim@target.com",
    "password": "Test1234!"
})
print("[+] Attacker logged in — check if victim@target.com receives an alert")
# Manually check inbox or automate via IMAP:
time.sleep(10)
mail = imaplib.IMAP4_SSL("imap.victim-email.com")
mail.login("victim@target.com", "email_pass")
mail.select("inbox")
_, msgs = mail.search(None, 'SUBJECT "new login"')
print(f"New login alert emails: {len(msgs[0].split())}")
```

## Burp Suite Tips
- **Proxy + Two Browsers**: Open Burp as the proxy for two separate browsers. Log into the same account in both, then intercept requests from each in separate Repeater tabs to test simultaneous access.
- **Extensions — Auth Analyzer**: Automatically sends the same request with multiple different session tokens and compares responses — ideal for testing concurrent session validity.
- **Session Handling Rules**: Set up two different session cookies as named credentials in Burp's session handling rules, then run a scan against authenticated endpoints to verify both are accepted.
- **Intruder — Pitchfork**: Use Intruder in Pitchfork mode to pair a list of session tokens against the same endpoint to determine which ones are still valid.

## Tools
- **Burp Suite** — proxy and repeater for multi-session comparison.
- **Auth Analyzer (Burp extension)** — automated parallel session testing.
- **OWASP ZAP** — spider and scanner with session management awareness.
- **Python threading / asyncio** — rapid concurrent session creation for load testing.
- **Hydra / Medusa** — credential stuffing tools that can be repurposed to test concurrent session creation.

## Remediation
- Define and enforce a maximum concurrent session limit per user (typically 1–3 depending on the application).
- When a new login exceeds the limit, either: (a) terminate the oldest session, (b) terminate all other sessions, or (c) require the user to explicitly select which session to terminate.
- Send real-time notification (email, push) to the registered address on each new login from an unrecognized device/IP.
- Provide users with a "Manage Active Sessions" interface showing device, IP, location, and last activity.
- Allow users to remotely invalidate any specific session.
- For high-security applications (banking, healthcare), enforce single-session-only policies with automatic logout of existing sessions on new login.
- Log all concurrent session events and alert on anomalous patterns (e.g., sessions from multiple countries simultaneously).

## References
https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#session-expiration
https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/
https://cwe.mitre.org/data/definitions/384.html
https://portswigger.net/web-security/authentication/other-mechanisms
https://owasp.org/www-community/controls/Session_Management
