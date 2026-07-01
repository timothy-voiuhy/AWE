# Account Lockout Policy

## Overview
Account lockout policies temporarily or permanently disable an account after a defined number of failed authentication attempts, preventing brute force attacks. A missing or weak lockout policy allows unlimited guessing, while an overly aggressive policy becomes a denial-of-service vector. Testing this control verifies both its existence (to prevent brute force) and its proper implementation (to prevent DoS abuse).

## How It Works
- The server tracks failed login attempts per account (or per IP) over a time window.
- After N failures, the account is locked: responses return `403 Forbidden`, `423 Locked`, or a generic "account locked" message.
- Soft lockouts reset after a timeout (e.g., 15 minutes); hard lockouts require administrator intervention.
- Flaws include: counter resets on successful login (exploitation gap), lockout only on IP not account (bypassed by distributed attack), no lockout at all, lockout threshold so high (100+) it's effectively absent, or lockout that triggers with 1 attempt (DoS risk).
- The lockout can itself be exploited as a DoS: an attacker who knows valid usernames can deliberately trigger lockouts for all users.

## Impact
- Without lockout: unlimited brute force attempts leading to account takeover.
- With DoS-exploitable lockout: attacker locks all known accounts, preventing legitimate users from logging in.
- Inconsistent lockout across endpoints (web vs. API vs. mobile) allows bypassing lockout by switching channels.
- Missing lockout on sensitive operations (password change, MFA verification) enables targeted attacks on those flows.

## Where to Look
- Primary login endpoint (web form and API).
- Password reset verification step (OTP/token entry).
- MFA/OTP verification endpoint — often has weaker lockout than the login page.
- Account unlock endpoint — recursive lockout bypass via the unlock flow itself.
- API endpoints authenticated with Basic Auth — often completely separate from web lockout logic.
- Admin login pages — sometimes have no lockout to avoid accidental admin DoS.

## Testing Steps
1. Submit 5 consecutive failed login attempts for a known account; observe whether a lockout message appears or the response changes.
2. After triggering what appears to be a lockout, immediately try the correct password — if it works, the lockout is not enforced.
3. Attempt one correct and one incorrect alternating request to see if a single success resets the failure counter.
4. Switch to the API endpoint (`/api/login`, `/api/v1/auth`) and repeat the same test — the API may lack lockout logic.
5. Test lockout persistence: wait the stated lockout duration and verify it actually resets.
6. Attempt to trigger lockout for 3–5 accounts to evaluate DoS potential.
7. Check if lockout is per-IP — adding `X-Forwarded-For` header may bypass IP-based lockout.
8. Test the password reset flow and MFA code entry flow independently for lockout enforcement.
9. Observe response differences between "account locked" and "invalid password" — inconsistency aids enumeration.

## Payloads / Techniques

Detect lockout threshold — rapid failed attempts:
```bash
for i in $(seq 1 20); do
  RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" -X POST https://target.com/login \
    -d "username=victim@target.com&password=wrongpass$i")
  echo "Attempt $i: HTTP $RESPONSE"
done
```

Test counter reset with interleaved correct attempt:
```bash
# Attempts 1-4 wrong
curl -s -X POST https://target.com/login -d "username=admin&password=wrong1"
curl -s -X POST https://target.com/login -d "username=admin&password=wrong2"
curl -s -X POST https://target.com/login -d "username=admin&password=wrong3"
curl -s -X POST https://target.com/login -d "username=admin&password=wrong4"
# Correct password attempt (does this reset the counter?)
curl -s -X POST https://target.com/login -d "username=admin&password=CorrectPass!"
# Resume wrong attempts
curl -s -X POST https://target.com/login -d "username=admin&password=wrong5"
```

Test API endpoint independently:
```bash
for i in $(seq 1 20); do
  curl -s -X POST https://target.com/api/v1/sessions \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"admin\",\"password\":\"attempt$i\"}" | jq '.error'
done
```

DoS lockout test (lock multiple accounts):
```bash
# Only run with written authorization
for user in $(cat valid_users.txt); do
  for i in 1 2 3 4 5; do
    curl -s -X POST https://target.com/login \
      -d "username=$user&password=lockout_test_$i" &
  done
done
```

X-Forwarded-For bypass test:
```bash
for i in $(seq 1 30); do
  curl -s -X POST https://target.com/login \
    -H "X-Forwarded-For: 10.0.0.$i" \
    -d "username=admin&password=wrongpass"
done
```

## Burp Suite Tips
- Use **Intruder** (Sniper mode) with a number sequence payload (1–50) in the password field: `wrongpassword§§`. Watch the response length/body for the lockout message appearing at attempt N.
- Enable **"Follow redirects"** in Intruder options; some lockout implementations redirect to a lockout page rather than returning an error inline.
- **Comparer**: compare the response at attempt 4 vs. attempt 5 — any difference in body, headers, or status code confirms the lockout threshold.
- Use **Match and Replace** in Proxy to automatically increment `X-Forwarded-For` values on every request, simulating IP rotation.
- The **Logger** extension can export all Intruder responses as a CSV with lengths and status codes for easy threshold identification.
- Test the MFA/OTP endpoint separately in **Repeater** — send the same (expired) OTP 10+ times and observe if the account locks or if unlimited attempts are allowed.

## Tools
- **Burp Suite Intruder** — Controlled automated login attempt generation with detailed response comparison.
- **Hydra** — Brute-force tool that naturally reveals lockout behavior through response analysis.
- **OWASP ZAP** — Active scanner includes authentication brute force checks.
- **Custom Python/Bash scripts** — For precise lockout threshold detection and timing analysis.

## Remediation
- Implement account lockout after 5–10 failed attempts within a 15-minute window.
- Use a soft lockout (time-based unlock) rather than a hard lockout that requires admin reset, to balance security and availability.
- Apply lockout consistently across ALL authentication surfaces: web, mobile API, REST API, admin panel, and any direct-to-service auth.
- Do NOT reset the failure counter on successful login — this creates a bypass window.
- Do NOT include account lockout state in the login error message (use generic messages to avoid enumeration).
- Implement CAPTCHA before lockout as an intermediate step to block automation without affecting human users.
- Alert account owners via email/SMS when their account is locked, allowing them to identify malicious activity.
- Monitor for distributed lockout attacks targeting many accounts (potential DoS) and block the attacking IPs at WAF/load balancer level.

## References
https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks
https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
https://portswigger.net/web-security/authentication/password-based
https://pages.nist.gov/800-63-3/sp800-63b.html
https://cwe.mitre.org/data/definitions/307.html
