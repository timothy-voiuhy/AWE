# Session Not Invalidated on Logout

## Overview
When a user logs out, the server must invalidate the session token server-side so it can no longer be used. If the application only deletes the cookie client-side without destroying the server-side session record, the token remains valid and can be replayed by anyone who captured it — including via XSS theft, network sniffing, or physical access to a shared computer. This vulnerability allows session replay attacks long after the user believes they have securely terminated their session.

## How It Works
- User logs in; server creates a session record and issues a token in a cookie.
- On logout, a poorly implemented application sends `Set-Cookie: session=; Max-Age=0` (deleting the client-side cookie) but leaves the server-side session entry intact.
- An attacker who captured the original token can inject it into their own browser and issue authenticated requests.
- The server sees a valid session token and processes the request as if the legitimate user were still logged in.
- This is especially severe in shared environments (kiosks, libraries) where the next user can read residual browser storage.

## Impact
- Session replay after logout allows continued impersonation of the victim.
- Theft of authentication state from browser history, logs, or referrer headers.
- Persistent attacker access even after victim changes password (if combined with other flaws).
- Compromise of shared device users in kiosk, library, or enterprise shared-workstation scenarios.
- Non-repudiation failures — audit logs may show the victim performing actions done by the attacker.

## Where to Look
- The logout endpoint response — check if the server sends a `Set-Cookie` to clear the token AND destroys the session server-side.
- Re-use the old session token after logout in Burp Repeater and check if it returns authenticated content.
- Check if logout is a GET request (CSRF-able) rather than a POST with a CSRF token.
- Look for single-page applications (SPAs) that clear localStorage/sessionStorage without calling a logout API.
- Mobile API backends where the `/logout` endpoint returns HTTP 200 but never invalidates the token.
- Check all token types: cookies, Bearer tokens, API keys issued at login.

## Testing Steps
1. Log in with a test account and capture the session token from the `Set-Cookie` header or Storage inspector.
2. Copy the full cookie value before logging out.
3. Perform a normal logout through the UI.
4. Open Burp Suite Repeater and send a previously authenticated request (e.g., `GET /api/profile`) with the old token injected.
5. If the response returns HTTP 200 with user data, the session is NOT properly invalidated.
6. Test all logout vectors: standard logout button, session timeout link, "log out of all devices" feature.
7. Check the logout HTTP request method — if GET, it is likely CSRF-able which means an attacker can force logout or observe token reuse.
8. After logout, attempt to navigate back using the browser's Back button and observe if protected pages load from cache with old session state.
9. Verify the server returns HTTP 401 or redirects to the login page for any authenticated endpoint after logout.
10. Test cross-tab persistence: open multiple tabs, log out in one, and verify the other tabs' sessions are also invalidated.

## Payloads / Techniques

```bash
# Step 1: Login and capture token
curl -c cookies.txt -X POST https://target.com/login \
  -d "username=testuser&password=Test1234!" \
  -D response_headers.txt -s -o /dev/null

cat cookies.txt

# Step 2: Confirm access before logout
curl -b cookies.txt https://target.com/api/profile

# Step 3: Logout
curl -b cookies.txt -c cookies_after_logout.txt \
  https://target.com/logout -s -o /dev/null

# Step 4: Replay OLD token after logout
OLD_TOKEN="abc123xyz..."
curl -H "Cookie: session=$OLD_TOKEN" \
  https://target.com/api/profile
# If this returns 200 + user data -> VULNERABLE
```

```python
import requests

LOGIN_URL = "https://target.com/login"
LOGOUT_URL = "https://target.com/logout"
PROFILE_URL = "https://target.com/api/profile"

s = requests.Session()

# Login
resp = s.post(LOGIN_URL, data={"username": "test", "password": "Test1234!"})
token = s.cookies.get("session")
print(f"[+] Token captured: {token}")

# Confirm authenticated
r = s.get(PROFILE_URL)
print(f"[+] Pre-logout response ({r.status_code}): {r.text[:100]}")

# Logout
s.get(LOGOUT_URL)
print("[*] Logged out")

# Replay old token
s2 = requests.Session()
s2.cookies.set("session", token)
r2 = s2.get(PROFILE_URL)
print(f"[!] Post-logout response ({r2.status_code}): {r2.text[:100]}")
if r2.status_code == 200 and "user" in r2.text.lower():
    print("[VULNERABLE] Session not invalidated on logout!")
else:
    print("[OK] Session correctly invalidated")
```

```javascript
// Check SPA logout — browser console
// Before logout
const token = localStorage.getItem("authToken") || sessionStorage.getItem("authToken");
console.log("Token before logout:", token);

// After clicking logout button, check if token still works:
fetch("/api/profile", {
  headers: { "Authorization": `Bearer ${token}` }
}).then(r => r.json()).then(data => {
  console.log("Post-logout response:", data);
  // If data contains user info -> VULNERABLE
});
```

## Burp Suite Tips
- **Proxy History**: After clicking logout, find the logout request and the session cookie value from a pre-logout request in the Proxy history. Use Repeater to replay authenticated requests with the old cookie.
- **Match and Replace**: Set up a match-and-replace rule in Proxy to automatically inject the old token into all requests while you browse after logout, making testing easier.
- **Session Handling Rules**: In Project Options > Sessions, add a session handling rule that uses a fixed cookie value (the pre-logout token) to test post-logout access systematically.
- **Logger++**: Use the Logger++ extension to track which requests return authenticated content vs. 401, giving a clear comparison before and after logout.

## Tools
- **Burp Suite Repeater** — replay captured requests with old session tokens.
- **curl** — simple command-line session replay testing.
- **OWASP ZAP** — active scan rules for session fixation and invalidation testing.
- **Feroxbuster / ffuf** — enumerate authenticated endpoints to check which remain accessible post-logout.
- **Browser DevTools** — inspect Application > Cookies/Storage to confirm client-side cleanup.

## Remediation
- On logout, immediately invalidate the server-side session record (delete from database/cache, call `session.invalidate()` in framework).
- Clear all session-related cookies with `Set-Cookie: session=; Max-Age=0; Path=/; HttpOnly; Secure`.
- For JWT-based sessions, maintain a server-side blocklist of invalidated tokens until their expiry time.
- Implement logout as a POST request protected by a CSRF token to prevent cross-site forced logout.
- Log and alert on requests using tokens that were previously invalidated (potential replay attack detection).
- On frameworks: use `request.session.flush()` (Django), `session_destroy()` + `session_unset()` (PHP), `req.session.destroy()` (Express).
- Implement a "log out of all devices" feature that invalidates all active sessions for the user.

## References
https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/06-Testing_for_Logout_Functionality
https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#session-expiration
https://portswigger.net/web-security/authentication/other-mechanisms
https://cwe.mitre.org/data/definitions/613.html
https://owasp.org/www-community/attacks/Session_hijacking_attack
