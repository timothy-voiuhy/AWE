# Session Not Invalidated After Password Change

## Overview
When a user changes their password, all previously issued session tokens should be invalidated to terminate any unauthorized sessions that may be running — for example, an attacker who has already hijacked the user's session. If the application allows existing sessions to remain valid after a password change, an attacker who obtained a session token retains access even after the victim attempts to remediate the compromise by changing their password. This is a critical gap in account recovery workflows.

## How It Works
- An attacker obtains a victim's session token (via XSS, sniffing, phishing, etc.) and uses it to access the account.
- The victim discovers suspicious activity and changes their password to lock out the attacker.
- If the application does not invalidate existing sessions on password change, the attacker's stolen token remains valid.
- The attacker continues to access the account with the old token, rendering the victim's remediation action ineffective.
- This also applies to email change, 2FA enrollment, and security question updates — any security-sensitive change should trigger session invalidation.

## Impact
- Attacker maintains persistent access despite the victim changing their password.
- Victim is given false confidence that their account is secured after a password reset.
- Enables prolonged account takeover without detection.
- Particularly devastating in combination with session hijacking via XSS — the attacker can persist indefinitely.
- May allow the attacker to lock out the legitimate user from their own account by re-changing the password.

## Where to Look
- Password change functionality (`/account/change-password`, `/settings/security`, `/profile/password`).
- Password reset flows (email link or OTP-based) — does the reset invalidate all sessions?
- Account recovery endpoints.
- Profile update endpoints that include email or username changes.
- API endpoints: `PATCH /api/user/password`, `PUT /api/account`.
- Check whether the application issues a new session token after a password change or reuses the old one.

## Testing Steps
1. Log in with a test account from Browser A; note the session token (Token A).
2. Simultaneously, log in with the same account from Browser B (or an incognito window); note the session token (Token B).
3. In Browser A, change the account password to a new value.
4. Observe whether Browser A is issued a new session token or retains Token A.
5. Switch to Browser B (still using Token B) and attempt to access an authenticated endpoint (e.g., `/api/profile`).
6. If Browser B still returns HTTP 200 with user data, the session is NOT invalidated on password change — VULNERABLE.
7. Repeat the test from Browser B's perspective, attempting actions like viewing account details, placing orders, or accessing private data.
8. Test the password reset flow (via email): complete a password reset, then replay a pre-reset session token.
9. Test whether a "log out everywhere" option exists and correctly invalidates all sessions.
10. Confirm that after password change, the old password hash no longer authenticates but old session tokens still work (demonstrates the specific bypass).

## Payloads / Techniques

```python
import requests

BASE = "https://target.com"

# Session 1: Simulate attacker who has stolen a session
s1 = requests.Session()
r1 = s1.post(f"{BASE}/login", data={"username": "victim", "password": "OldPassword1!"})
stolen_token = s1.cookies.get("session")
print(f"[+] Stolen token (attacker's copy): {stolen_token}")

# Session 2: Victim changes password
s2 = requests.Session()
s2.post(f"{BASE}/login", data={"username": "victim", "password": "OldPassword1!"})
r_change = s2.post(f"{BASE}/account/change-password", data={
    "current_password": "OldPassword1!",
    "new_password": "NewSecurePassword2!",
    "confirm_password": "NewSecurePassword2!"
})
print(f"[*] Password change response: {r_change.status_code}")

# Attacker replays stolen session
s_attacker = requests.Session()
s_attacker.cookies.set("session", stolen_token)
r_replay = s_attacker.get(f"{BASE}/api/profile")
print(f"[!] Attacker post-change access: {r_replay.status_code}")
print(r_replay.text[:200])

if r_replay.status_code == 200:
    print("[VULNERABLE] Session persists after password change!")
else:
    print("[OK] Session correctly invalidated")
```

```bash
# Manual test with curl

# Step 1: Login, capture session token
curl -c session_pre.txt -X POST https://target.com/login \
  -d "username=victim&password=OldPassword1!" -s -o /dev/null
echo "[+] Pre-change session:"
cat session_pre.txt

# Step 2: Change password (using second curl with same creds)
curl -c session_victim.txt -b session_victim.txt \
  -X POST https://target.com/account/change-password \
  -d "current_password=OldPassword1!&new_password=NewSecure2!&confirm=NewSecure2!"

# Step 3: Replay old session token
OLD_TOKEN=$(grep session session_pre.txt | awk '{print $NF}')
curl -H "Cookie: session=$OLD_TOKEN" https://target.com/api/profile
# 200 with data = VULNERABLE
```

```bash
# JWT-specific: check if JWT is invalidated
# Capture JWT before password change
JWT_OLD="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMjMsImV4cCI6MTk5OTk5OTk5OX0.signature"

# After password change, replay old JWT
curl -H "Authorization: Bearer $JWT_OLD" \
  https://target.com/api/v1/me
# If 200 -> JWTs not blocklisted after password change
```

## Burp Suite Tips
- **Proxy + Repeater Workflow**: Capture the password change request in Proxy. Before submitting, open a second Repeater tab with an authenticated request using the current token. Submit the password change, then immediately fire the Repeater request — if it returns 200, the old session is still valid.
- **Session Handling Rules**: Configure a session handling rule to use a fixed (pre-change) cookie value across all Repeater requests, making it easy to retest after password change without manually injecting the cookie each time.
- **Compare Responses**: Use Burp Comparer to diff the authenticated response before and after the password change — identical responses confirm session persistence.
- **Extensions — Auth Analyzer**: The Auth Analyzer extension can automatically test whether multiple captured sessions (pre-change and post-change) respond identically to the same requests.

## Tools
- **Burp Suite** — request replay and session comparison.
- **OWASP ZAP** — active and passive scanning for session management issues.
- **Auth Analyzer (Burp extension)** — automated multi-session comparison testing.
- **Python requests** — custom scripts for sequential login, password change, and replay testing.
- **Postman** — API-based session testing with environment variable management.

## Remediation
- After a successful password change, invalidate ALL existing session tokens for that user.
- Issue a fresh session token in the password-change response so the current (legitimate) user remains logged in.
- For JWT-based authentication: maintain a server-side blocklist of JWTs issued before the password change timestamp; reject any JWT whose `iat` (issued-at) claim predates the password change.
- Store a `password_changed_at` timestamp per user and validate it against the session's `issued_at` field on every request.
- Notify the user via email listing all sessions that were terminated, including their approximate location/device.
- Apply the same invalidation logic to email changes, 2FA enrollment, and recovery email updates.
- Implement a "sign out of all other sessions" checkbox on the password change form as both a UX feature and security control.

## References
https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/06-Testing_for_Logout_Functionality
https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
https://portswigger.net/web-security/authentication/other-mechanisms#keeping-users-logged-in
https://cwe.mitre.org/data/definitions/613.html
https://cwe.mitre.org/data/definitions/620.html
