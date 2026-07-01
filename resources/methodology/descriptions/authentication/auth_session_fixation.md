# Session Fixation

## Overview
Session fixation is an attack where an attacker sets or predicts the victim's session token before authentication, then waits for the victim to log in with that known token. Unlike session hijacking (where the attacker steals a session token after login), session fixation exploits the application's failure to issue a new session token upon successful authentication. After the victim logs in, the attacker uses the same session token to access the authenticated session.

## How It Works
- The application creates a session token before authentication and keeps the same token after login.
- The attacker obtains a valid pre-auth session token (by visiting the login page themselves or through other means).
- The attacker delivers this token to the victim via a link (`https://target.com/login?session_id=KNOWN_TOKEN`), cookie injection, XSS, or HTTP response splitting.
- The victim clicks the link, is assigned the attacker's known session ID, and logs in.
- The application fails to invalidate the old session and issue a new one upon login — the session ID remains the same.
- The attacker, knowing the session ID, is now authenticated as the victim.

## Impact
- Session hijacking — full access to the victim's authenticated session.
- Account takeover without ever knowing the victim's password.
- Escalation to admin access if an administrator is targeted.
- Persistent access until the victim explicitly logs out (which may also not invalidate the session if logout is flawed).

## Where to Look
- Any application that sets a session cookie before the user logs in (check for `Set-Cookie` on the login page GET response).
- Applications that accept session IDs in URL parameters (`JSESSIONID`, `PHPSESSID`, `session_id` in the URL query string).
- The session cookie value before and after login — they should be different.
- Single Sign-On (SSO) implementations that pass session tokens between services.
- Password reset flows that pre-authenticate the session.
- "Remember me" flows that issue persistent tokens before full authentication.

## Testing Steps
1. Browse to the application login page and capture the session cookie set in the response (note the pre-auth session token).
2. Log in with valid credentials and capture the session cookie in the post-login response.
3. Compare the pre-auth and post-auth session tokens: if they are identical, session fixation is confirmed.
4. Test URL-based session fixation: visit `/login?PHPSESSID=attacker_controlled_value` and log in — check if the application accepts and maintains the URL-supplied session ID.
5. Test cookie injection via header manipulation: `Cookie: session_id=fixated_value` — does the server accept this as a valid session to elevate?
6. After confirming session fixation, perform the full attack: get a session token from the server, send a link to a test victim account with that session embedded, have the victim log in, then use the session token to access authenticated pages.
7. Test whether logout actually invalidates the session server-side (not just clears the client-side cookie).

## Payloads / Techniques

Check if session token changes on login:
```bash
# Step 1: Get pre-auth session token
PRE_TOKEN=$(curl -s -c /tmp/pre_cookies.txt https://target.com/login \
  -o /dev/null && grep session /tmp/pre_cookies.txt | awk '{print $NF}')
echo "Pre-auth session: $PRE_TOKEN"

# Step 2: Log in
curl -s -X POST https://target.com/login \
  -b /tmp/pre_cookies.txt \
  -c /tmp/post_cookies.txt \
  -d "username=testuser&password=TestPass123!"

# Step 3: Get post-auth session token
POST_TOKEN=$(grep session /tmp/post_cookies.txt | awk '{print $NF}')
echo "Post-auth session: $POST_TOKEN"

if [ "$PRE_TOKEN" = "$POST_TOKEN" ]; then
  echo "VULNERABLE: Session token unchanged after login"
fi
```

URL-based session fixation test (PHP):
```bash
# Visit login page with a crafted session ID
curl -L "https://target.com/login?PHPSESSID=my_fixated_session_id" \
  -c /tmp/fixed_cookies.txt -o /dev/null

# Log in with the fixed session
curl -X POST "https://target.com/login" \
  -b "PHPSESSID=my_fixated_session_id" \
  -d "username=victim@test.com&password=victimpass" \
  -c /tmp/after_login.txt

# Check if the PHPSESSID was maintained or changed
grep PHPSESSID /tmp/after_login.txt
```

Session fixation attack link construction:
```
# Attacker sends victim:
https://target.com/login?session_id=ATTACKER_KNOWN_VALUE
https://target.com/auth?JSESSIONID=ATTACKER_KNOWN_VALUE
https://target.com/login?tok=ATTACKER_KNOWN_VALUE
```

Test via cookie injection in a proxied request:
```
GET /login HTTP/1.1
Host: target.com
Cookie: session=attacker_known_session

# If server responds 200 and the session value is maintained,
# test if logging in through this session fixes the token
```

Verify logout invalidates session:
```bash
# Login and get session
curl -X POST https://target.com/login \
  -c /tmp/session.txt \
  -d "username=user&password=pass" -L

# Access protected page
curl https://target.com/profile \
  -b /tmp/session.txt | grep -i username

# Logout
curl https://target.com/logout -b /tmp/session.txt

# Try accessing protected page with old session
curl https://target.com/profile \
  -b /tmp/session.txt | grep -i username
# If still accessible, logout doesn't invalidate server-side
```

## Burp Suite Tips
- Use **Proxy** to compare the `Set-Cookie` header values in the login page GET response versus the login POST response — if the session value is the same, session fixation is present.
- In **Repeater**, manually set a `Cookie: session=fixated_value` header on the login page request, then submit credentials — observe if the response sets a new session or keeps the same one.
- The **Session Token Analyzer** in Burp (Scanner tab, Sequencer) can analyze token randomness and confirm whether pre/post-auth tokens are related.
- Use **Sequencer** to capture post-login session tokens and analyze their entropy — weak entropy makes guessing easier, compounding session fixation risk.
- **Match and Replace** can automatically inject a fixed session cookie into all login requests during testing.
- Check the **Request/Response Difference** in Comparer between a pre-auth and post-auth session-using request to confirm the session ID change (or lack thereof).

## Tools
- **Burp Suite** — Session comparison, Cookie injection testing.
- **OWASP ZAP** — Session fixation active scanner.
- **curl** — Manual multi-step session flow testing with cookie capture.
- **Nikto** — Web vulnerability scanner that checks for session fixation.
- **Browser developer tools** — Inspect `Set-Cookie` headers in network tab pre/post login.

## Remediation
- Issue a completely new, cryptographically random session token immediately after successful authentication — this is the primary defense.
- Invalidate the pre-authentication session token entirely upon login; do not "elevate" an existing session.
- Reject session tokens supplied via URL parameters — accept session tokens only via `httpOnly`, `Secure`, `SameSite=Strict` cookies.
- Invalidate session tokens server-side on logout — not just by deleting the client-side cookie.
- Set short session lifetimes and implement idle timeout.
- Use a well-tested session management library (avoid custom session handling) and ensure it generates cryptographically random tokens of at least 128 bits.

## References
https://owasp.org/www-community/attacks/Session_fixation
https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
https://portswigger.net/web-security/authentication/other-mechanisms
https://cwe.mitre.org/data/definitions/384.html
https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/03-Testing_for_Session_Fixation
