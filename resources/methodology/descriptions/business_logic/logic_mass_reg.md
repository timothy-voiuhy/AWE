# Mass Account Registration / Fake Account Creation

## Overview
Mass registration (account farming) exploits missing or weak registration controls to create large numbers of accounts. Attackers use this to spam, abuse free-tier limits, manipulate review systems, conduct coordinated voting fraud, or generate referral credits. It is a business logic failure when account creation lacks adequate friction.

## How It Works
- No CAPTCHA or easily bypassed CAPTCHA allows automated sign-up scripts.
- Email verification not required before the account can act (or not required at all).
- Temporary/disposable email addresses are accepted.
- Phone number not required (or one phone number can verify many accounts).
- Rate limiting on registration endpoint is absent.
- Same device/IP can create unlimited accounts.
- Email aliasing (`user+1@gmail.com`, `user+2@gmail.com`) bypasses uniqueness checks.

## Impact
- Platform spam and abuse.
- Free-tier abuse (bypassing paid tier limits).
- Vote manipulation (review bombing, poll stuffing).
- Referral/credit farming.
- Resource exhaustion (database, storage, email credits).
- Credential stuffing laundering (testing stolen credentials without being detected).

## Where to Look
- `/register`, `/signup`, `/api/user/create`
- Free trial signup flows.
- Forum and community platform registrations.
- Any system with per-account limits (free storage, free API calls, free submissions).

## Testing Steps
1. Attempt to register multiple accounts from the same IP in quick succession.
2. Test if CAPTCHA is enforced and if it can be bypassed (hidden field, CAPTCHA bypass service).
3. Use email aliasing: `yourname+1@gmail.com`, `yourname+2@gmail.com`, etc.
4. Test with disposable email domains (mailinator.com, guerrillamail.com).
5. Check if email verification is required before account activation.
6. Try registering with the same phone number on multiple accounts.
7. Test if account creation has any rate limiting (create 20 accounts in 1 minute).
8. Check if there's a `user_count` or account limit that can be monitored and circumvented.

## Payloads / Techniques
```python
import requests
import time

base_url = "https://target.com/api/register"

# Email aliasing approach
for i in range(50):
    email = f"attacker+{i}@gmail.com"
    r = requests.post(base_url, json={
        "email": email,
        "password": "Password123!",
        "username": f"user_{i}"
    })
    print(f"[{i}] {email}: {r.status_code} - {r.json().get('message', '')}")
    time.sleep(0.1)  # Light throttle to avoid obvious detection
```

```bash
# Detect rate limiting behavior
for i in $(seq 1 20); do
  response=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST https://target.com/register \
    -d "email=test$i@example.com&password=Pass123!")
  echo "Request $i: HTTP $response"
done

# Test disposable email acceptance
curl -s -X POST https://target.com/register \
  -d "email=test@mailinator.com&password=Pass123!" | grep -i "success\|error\|invalid"
```

## Burp Suite Tips
- Use **Intruder** with email payload list to rapidly create accounts (number-based payload for `+N` aliasing).
- Intercept the CAPTCHA validation request in **Proxy** — check if it's validated server-side.
- Use **Intruder** to test the registration endpoint's rate limiting.
- Check if client-side CAPTCHA tokens are validated by the registration API.

## Tools
- Burp Suite Intruder
- Python requests for automation
- ffuf for registration endpoint fuzzing

## Remediation
- Implement CAPTCHA (Google reCAPTCHA v3, hCaptcha) with server-side validation.
- Require email verification before account activation.
- Implement IP-based rate limiting: max 3 registrations per IP per hour.
- Block or flag disposable email domains.
- Require phone number verification for high-privilege actions.
- Use device fingerprinting to detect multiple accounts from the same device.
- Implement account age requirements before accessing certain features.

## References
https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/
https://portswigger.net/web-security/logic-flaws
https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
