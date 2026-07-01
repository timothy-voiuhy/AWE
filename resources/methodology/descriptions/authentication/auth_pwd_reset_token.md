# Password Reset Token Expiry / Predictability

## Overview
Password reset tokens are single-use secrets sent to a user's email or phone to authorize a password change without knowing the current password. Vulnerabilities arise when these tokens never expire, remain valid after use, are generated with weak entropy (predictable or guessable), or are transmitted insecurely. An attacker who can predict or obtain a valid reset token can take over any account without knowing the password.

## How It Works
- The application generates a token and stores it (or a hash of it) server-side, linking it to the requesting user.
- The token is sent to the user's registered email or phone and used to authenticate the password reset request.
- **No expiry**: tokens that remain valid indefinitely allow exploitation of tokens obtained from old emails, email backups, or mail logs.
- **No single-use invalidation**: tokens that remain valid after use allow replay attacks.
- **Weak entropy**: tokens generated with `rand()`, timestamps, or user-ID-based hashing are predictable.
- **Token in URL leak**: reset URLs logged in Referer headers, proxy logs, or browser history expose the token to third parties.
- **User-controlled token**: the token value is sent as a parameter that the user controls (e.g., based on their user ID), allowing token forging.

## Impact
- Account takeover by guessing or brute-forcing a weak reset token.
- Account takeover by replaying a previously used or old token.
- Mass account compromise if the token generation algorithm is deterministic and predictable.
- Privilege escalation if admin accounts use the same flawed reset mechanism.

## Where to Look
- The password reset request form (`/forgot-password`).
- The reset link in the email: examine the token format, length, and character set.
- The token as a URL parameter: `/reset-password?token=XXXX` — is it in GET (logged) or POST (safer)?
- Whether the token remains valid after the password has been reset.
- Token expiry window — 1 hour is standard; 24 hours is borderline; "never" is a critical vulnerability.
- Look for sequential or low-entropy tokens (6-digit numeric, MD5 of timestamp, base64 of user ID).
- Check if reset tokens from older emails are still valid.
- Check if a second reset request invalidates the first token.

## Testing Steps
1. Request a password reset for a test account and inspect the token in the link — note its length, character set, and format.
2. Calculate entropy: a 32-byte hex string = 128-bit entropy (secure); a 6-digit number = ~20 bits (insecure); a base64 of user ID = 0 bits (trivially forgeable).
3. Request two consecutive password resets; check if the first token is invalidated when the second is issued.
4. Use the reset link, complete the reset, then attempt to use the same link again — is the token invalidated after use?
5. Capture the reset token timestamp and attempt to use it 1 hour, 6 hours, and 24 hours later — determine the actual expiry window.
6. Request resets for multiple accounts at the same time and analyze if tokens have a sequential or time-based pattern.
7. If the token looks like a hash (MD5/SHA1), attempt to reverse it using common inputs: `MD5(user_id + timestamp)`, `SHA1(email + date)`.
8. Check the password reset page URL for Referer header leakage — if the token is in the URL and the page includes third-party resources, the token may be sent in Referer.

## Payloads / Techniques

Analyze token entropy:
```python
import base64
import hashlib
import re

token = "PASTE_RESET_TOKEN_HERE"

# Check if it's base64
try:
    decoded = base64.b64decode(token + "==")
    print(f"Base64 decoded: {decoded}")
except:
    pass

# Check if it's hex (MD5 = 32 chars, SHA1 = 40 chars, SHA256 = 64 chars)
if re.match(r'^[0-9a-f]+$', token.lower()):
    print(f"Hex string, length {len(token)}")
    if len(token) == 32:
        print("Possible MD5 hash")
    elif len(token) == 40:
        print("Possible SHA1 hash")

# Check if numeric / low entropy
if token.isdigit():
    print(f"Numeric token: {len(token)} digits = {len(token)*3.32:.0f} bits max entropy")
    print("LIKELY BRUTE-FORCEABLE")
```

Brute force 6-digit numeric token:
```bash
for code in $(seq -w 000000 999999); do
  RESP=$(curl -s -X POST https://target.com/reset-password \
    -d "token=$code&password=NewPass123!&confirm=NewPass123!")
  if echo "$RESP" | grep -qi "success\|changed\|updated"; then
    echo "VALID TOKEN: $code"
    break
  fi
done
```

Test token reuse after password reset:
```bash
# Use valid token
curl -X POST https://target.com/reset-password \
  -d "token=VALID_TOKEN&password=NewPass1!&confirm=NewPass1!"

# Immediately reuse same token
curl -X POST https://target.com/reset-password \
  -d "token=VALID_TOKEN&password=AttackerPass1!&confirm=AttackerPass1!"
```

Attempt MD5 timestamp-based token forgery:
```python
import hashlib
import time

user_id = "42"
# Try timestamps within the last 60 seconds
for offset in range(120):
    ts = int(time.time()) - offset
    for candidate in [
        hashlib.md5(f"{user_id}{ts}".encode()).hexdigest(),
        hashlib.md5(f"{ts}{user_id}".encode()).hexdigest(),
        hashlib.sha1(f"{user_id}{ts}".encode()).hexdigest(),
    ]:
        print(f"Trying: {candidate} (ts={ts})")
```

Check Referer leakage:
```bash
# Open a reset link with a third-party resource load and capture network traffic
# Or check: https://target.com/reset-password?token=XXXX has external JS/images
curl -s "https://target.com/reset-password?token=SECRET_TOKEN" | grep -E "src=|href=" | head -20
```

## Burp Suite Tips
- Intercept the password reset request and response in **Proxy** — note the token format in the request body or emailed link.
- Use **Repeater** to replay a used reset token and observe if the server rejects it (single-use enforcement).
- In the **Intruder** (Sniper mode), target the token parameter with a number sequence payload if the token is numeric and short.
- Use the **Logger** extension to capture all reset-related requests for analysis.
- Check the **Site Map** for any URLs containing reset tokens in GET parameters (these appear in Burp's passive scan results as informational findings).
- The **Collaborator** (Burp Pro) can be used to check if reset links include tracking pixels or external resources that would receive the token in the Referer header.

## Tools
- **Burp Suite** — Token interception, reuse testing, entropy analysis.
- **hashcat** — Offline cracking of hashed tokens if the hash algorithm and inputs are guessable.
- **Python scripts** — Custom entropy analysis and timing-based token forgery attempts.
- **jwt.io** — If the reset token is a JWT, decode and inspect claims.
- **CyberChef** — Decode base64/hex tokens and analyze structure visually.

## Remediation
- Generate reset tokens using a cryptographically secure random number generator (CSPRNG): at least 128 bits of entropy (32 hex characters or a UUID v4).
- Set a short, strict expiry window: 15–60 minutes maximum. Tokens should expire even if unused.
- Invalidate the token immediately after it is used to reset the password.
- Invalidate all existing reset tokens for a user when a new reset is requested.
- Never send reset tokens as GET parameters in URLs — use POST submissions where possible, or accept the token in the URL but ensure no third-party resources are loaded on that page.
- Store only the hash of the token server-side (SHA-256 of the random token), not the plaintext.
- Log reset token requests and alert on unusual patterns (many resets for the same account, resets from new geos).
- Ensure reset tokens are account-specific and cannot be used across different users.

## References
https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/09-Testing_for_Weak_Password_Change_or_Reset_Functionalities
https://portswigger.net/web-security/authentication/other-mechanisms
https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html
https://cwe.mitre.org/data/definitions/640.html
https://cwe.mitre.org/data/definitions/330.html
