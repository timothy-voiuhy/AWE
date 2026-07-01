# Brute Force / Rate Limiting

## Overview
Brute force attacks systematically try every possible password or a large dictionary of likely passwords against a login endpoint until the correct one is found. Rate limiting is the primary defense — without it, an attacker can send thousands of guesses per second. Weak or absent rate limiting combined with no account lockout is one of the most exploitable authentication weaknesses in modern web applications.

## How It Works
- Attackers submit repeated login attempts via automated tools, varying the password while keeping the username constant (or vice versa for credential stuffing).
- Credential stuffing uses leaked username:password pairs from data breaches — often more effective than random guessing because users reuse passwords.
- Password spraying tries a single common password (e.g., `Summer2024!`) against many accounts to avoid lockouts.
- Rate limiting defenses count requests per IP/account per time window; weaknesses include IP rotation bypasses, missing rate limits on alternative endpoints (API vs. web form), and headers like `X-Forwarded-For` that can spoof source IPs.
- Distributed attacks use botnets or proxy pools to spread requests across thousands of IPs, defeating simple per-IP rate limits.

## Impact
- Account takeover of any account in the application, including administrators.
- Full data breach if administrator access is obtained.
- Credential validation — confirming which accounts exist (username enumeration side effect).
- Financial fraud, data exfiltration, and persistent access.

## Where to Look
- Primary login endpoints: `/login`, `/signin`, `/api/auth`, `/api/v1/sessions`.
- Password reset forms — often have weaker rate limiting than login.
- Account unlock endpoints.
- API authentication: `/oauth/token`, `/api/token`, Basic Auth headers.
- Mobile API backends — frequently lack rate limiting implemented on the web frontend.
- Alternative login methods: magic link request forms, OTP verification endpoints.
- HTTP headers to test for rate limit bypass: `X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP`, `True-Client-IP`, `X-Originating-IP`.

## Testing Steps
1. Send 10–20 rapid login attempts with wrong passwords and observe response behavior — does the response slow down, return `429 Too Many Requests`, or show a CAPTCHA?
2. Check if rate limiting is per-IP; if so, add `X-Forwarded-For: 1.2.3.4` and increment the header value on each request to test IP spoofing bypass.
3. Test rate limiting on all authentication endpoints independently — the API endpoint may have no rate limiting even if the web form does.
4. Attempt a password spray: one common password (`Password1`, `Summer2024!`) across all enumerated usernames.
5. Test whether rate limits reset on successful login — some implementations reset the counter on success, making it exploitable.
6. Check if the CAPTCHA can be bypassed (reuse of CAPTCHA token, weak validation, or third-party solving services).
7. Test credential stuffing with a small known-breached list using a tool like Nuclei or Hydra.
8. Measure response time differences between valid and invalid usernames — timing side channels may confirm enumeration.

## Payloads / Techniques

Hydra HTTP POST brute force:
```bash
hydra -l admin@target.com -P /usr/share/wordlists/rockyou.txt \
  -t 16 -f https://target.com \
  http-post-form "/login:email=^USER^&password=^PASS^:Incorrect password"
```

Password spray (single password, many users):
```bash
hydra -L users.txt -p "Summer2024!" -t 4 \
  https://target.com \
  http-post-form "/login:username=^USER^&password=^PASS^:Invalid"
```

Rate limit bypass via X-Forwarded-For header rotation (Burp Intruder payload):
```
X-Forwarded-For: §1§.§2§.§3§.§4§
```

Ffuf credential stuffing:
```bash
ffuf -w credentials.txt:FUZZ \
  -u https://target.com/api/auth \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"FUZZ_USER","password":"FUZZ_PASS"}' \
  -fc 401
```

curl with IP spoofing header:
```bash
for i in $(seq 1 50); do
  curl -s -X POST https://target.com/api/login \
    -H "X-Forwarded-For: 192.168.$i.1" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"test123"}' &
done
```

Nuclei credential stuffing template:
```bash
nuclei -t fuzzing/credential-stuffing.yaml -u https://target.com
```

## Burp Suite Tips
- Use **Intruder** (Sniper mode for single-variable, Pitchfork for user:pass pairs from a breach list) to automate credential testing.
- Set **Resource Pool** throttle in Intruder to control request rate — use 1 concurrent request with 500ms delay to test anti-automation without triggering hard blocks.
- Add a **Macro** in Session Handling Rules to grab a fresh CSRF token or nonce before each Intruder request.
- Use the **IP Rotate** extension (BApp Store) to automatically rotate AWS API Gateway IPs, bypassing IP-based rate limiting.
- **Comparer** tool: compare responses between a failed login and a suspected successful one — look for differences in body length, headers, redirect targets, or cookies.
- Filter Intruder results by response length or status code to quickly identify successful logins among hundreds of failures.

## Tools
- **Hydra** — Classic network brute-forcer with support for HTTP forms, Basic Auth, and dozens of protocols.
- **Medusa** — Parallel, modular brute-forcer.
- **Burp Suite Intruder** — Web-focused fuzzer with fine-grained request control.
- **ffuf** — Fast web fuzzer ideal for API endpoint brute forcing.
- **Nuclei** — Template-based scanner with credential stuffing and auth bypass templates.
- **Spray** — Purpose-built password spraying tool with built-in throttling.
- **CrackStation / Hashcat** — For offline password hash cracking once hashes are obtained.

## Remediation
- Implement rate limiting on all authentication endpoints: maximum 5–10 failed attempts per account per 15-minute window.
- Enforce IP-based rate limiting as a secondary layer, but do not rely on it alone (IP spoofing and proxies bypass it).
- Validate that `X-Forwarded-For` and similar headers are only trusted from known reverse proxies, not arbitrary clients.
- Implement progressive delays (exponential backoff) after each failed attempt.
- Deploy CAPTCHA after 3–5 failed attempts; prefer server-side CAPTCHA validation.
- Alert and optionally lock accounts after a threshold of failures; send notification to account owner.
- Use multi-factor authentication to make credential theft insufficient for account access.
- Monitor login endpoints with SIEM rules for velocity anomalies.

## References
https://owasp.org/www-community/attacks/Brute_force_attack
https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
https://portswigger.net/web-security/authentication/password-based
https://owasp.org/www-community/attacks/Credential_stuffing
https://www.nist.gov/publications/digital-identity-guidelines
