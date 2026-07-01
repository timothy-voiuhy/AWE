# Referral Program Abuse

## Overview
Referral programs incentivize existing users to invite new users by offering rewards (credits, discounts, cash) to both parties. Abuse occurs when an attacker creates multiple fake accounts to self-refer, manipulates referral attribution after sign-up, or exploits race conditions to earn rewards multiple times. These are business logic flaws in the reward attribution system.

## How It Works
- **Self-referral**: Create account A (referrer), then create account B (referred) using A's referral code — same person, double reward.
- **Fake account farming**: Automate creation of referral chains using disposable email addresses.
- **Referral code reuse**: A code intended for one use can be shared publicly and used by many.
- **Attribution manipulation**: Change referral code after sign-up but before the reward triggers.
- **Minimum spend bypass**: Receive the referred discount, then return items to bring spend below the minimum threshold while keeping the credit.
- **Referral + coupon stack**: Combine referral credits with coupons for compounded discount abuse.

## Impact
- Direct financial loss through fraudulent credit accumulation.
- Skewed user growth metrics (fake accounts inflate referral stats).
- Resource abuse (storage, compute) from fraudulent accounts.
- Payment fraud if credits can be withdrawn.

## Where to Look
- `/referral/generate`, `/referral/apply`, `/invite`
- Account sign-up flow that accepts referral codes.
- User dashboard showing referral credits.
- Reward credit application at checkout.

## Testing Steps
1. Generate a referral link from account A.
2. Open incognito/different browser, register account B using the same email domain but different alias (user+1@gmail.com vs user+2@gmail.com).
3. Check if referral reward is credited to account A.
4. Test if the minimum spend requirement for referred user is enforced.
5. Complete minimum spend with account B, get reward for account A, then return all items.
6. Try applying the same referral code to multiple new accounts.
7. Test if the system checks if referrer and referred share the same IP or device fingerprint.
8. Try changing the referral code in the user profile after sign-up but before the reward triggers.
9. Race condition: create multiple accounts simultaneously with the same referral code.

## Payloads / Techniques
```python
import requests

# Self-referral automation
# Step 1: Get referral code for account A
r = requests.post('https://target.com/api/referral/generate',
    headers={'Authorization': 'Bearer TOKEN_A'})
ref_code = r.json()['code']
print(f"Referral code: {ref_code}")

# Step 2: Create account B using referral code
emails = [f"victim+{i}@attacker.com" for i in range(10)]  # Email aliasing
for email in emails:
    r = requests.post('https://target.com/api/register', json={
        'email': email,
        'password': 'Password123!',
        'referral_code': ref_code
    })
    print(f"Registered {email}: {r.status_code}")

# Step 3: Check credited balance on account A
r = requests.get('https://target.com/api/wallet/balance',
    headers={'Authorization': 'Bearer TOKEN_A'})
print(f"Balance: {r.json()['credits']}")
```

```bash
# Test with temp email services
# Use mailinator, 10minutemail, guerrillamail for disposable emails
# Try email+1@domain.com, email+2@domain.com (Gmail aliasing)
```

## Burp Suite Tips
- Use **Burp Repeater** to replay the account creation request with different email addresses.
- Use **Intruder** to automate account registration with email aliasing (username§1§@gmail.com with number list).
- Check if the referral code is validated client-side only — intercept and modify in Burp Proxy.
- **Logger++** can help track the referral credit flow across multiple requests.

## Tools
- Burp Suite Intruder
- Python requests for automation
- Disposable email services (for testing only — with authorization)

## Remediation
- Implement device fingerprinting and IP-based detection to identify self-referral.
- Require email domain diversity (same domain registrations from same IP should raise flags).
- Only credit referral rewards after the referred user completes qualifying actions (non-returnable purchase).
- Implement velocity checks: same IP creating multiple new accounts using one referral code.
- Use minimum account age or account verification (phone number) for referred users.
- Monitor referral credit-to-spend ratio for fraud signals.

## References
https://portswigger.net/web-security/logic-flaws
https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/09-Test_for_Workflow_Bypass
