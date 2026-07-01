# Multi-Factor Authentication Bypass

## Overview
Multi-factor authentication (MFA) adds a second verification layer after password authentication, requiring something the user has (OTP app, SMS code, hardware token) or something they are (biometric). Despite its strength, MFA implementations frequently have critical flaws that allow attackers to bypass the second factor entirely, often by manipulating the authentication state machine, reusing codes, or exploiting backup mechanisms. An MFA bypass renders the second factor completely ineffective.

## How It Works
- **State machine bypass**: After entering the correct password, the server sets an intermediate session state (e.g., `mfa_pending=true`). If the MFA verification endpoint doesn't check this state, an attacker can skip directly to authenticated endpoints by manipulating the session.
- **Response manipulation**: The server returns `{"mfa_required": true}` in JSON. If the client controls routing logic based on this value, changing it to `false` in the proxy bypasses the MFA prompt.
- **OTP reuse**: Used OTPs are not invalidated, allowing replay within the validity window.
- **Brute-forceable OTP**: 6-digit OTPs have 1,000,000 possibilities; without rate limiting, the code can be brute-forced in minutes.
- **Backup code abuse**: Single-use backup codes stored insecurely or generated with weak entropy.
- **SIM swapping / SS7 attacks**: For SMS-based MFA, the phone number can be hijacked.
- **Account recovery bypass**: "Forgot your phone?" flows that allow MFA to be disabled via email-only reset.

## Impact
- Complete bypass of the second authentication factor.
- Account takeover even when the attacker only has the password (from a breach), not the OTP device.
- Persistent access if MFA is disabled through the recovery flow.
- Lateral movement if MFA is bypassed on an administrator account.

## Where to Look
- The intermediate state between password authentication and OTP entry.
- The HTTP response after password verification (look for flags like `mfa_required`, `next_step`, `authenticated`).
- The OTP submission endpoint — test rate limiting and code reuse.
- Session cookies/JWTs issued between the password step and MFA step — do they grant any access before MFA completion?
- Account recovery / "trusted device" flows.
- Remember-this-device functionality — how is the trusted state stored and can it be forged?
- API endpoints that bypass MFA when accessed with certain headers or parameters.
- The `redirect_uri` or `returnTo` parameter — after MFA, does it redirect to an attacker-controlled URL?

## Testing Steps
1. Log in with valid credentials and stop at the MFA prompt. Copy the session cookie and directly access authenticated pages/APIs — does the partial session grant access?
2. Intercept the MFA submission response; change `{"success": false, "mfa_required": true}` to `{"success": true}` in Burp and observe if the client proceeds.
3. Submit a valid OTP code, then immediately re-submit the same code — test if it's invalidated after use.
4. Attempt to brute-force the OTP: send 000000 through 999999 with no delay and no rate limiting.
5. Request a new OTP; check if the old OTP remains valid (OTP invalidation on new code generation).
6. Test the "trusted device" cookie/token — is it a guessable value or a cryptographically secure random token?
7. Go through the account recovery flow ("I don't have access to my authenticator") — can MFA be disabled with only the password or email?
8. Test the OTP endpoint for parameter manipulation: add `skip_mfa=true`, `mfa_bypass=1`, or change the OTP field to `null`/`undefined`.
9. Check if MFA is enforced on the API (`/api/v1/`) even when enforced on the web application (`/login`).

## Payloads / Techniques

Direct access to post-auth endpoint (skipping MFA step):
```bash
# After password step, grab the intermediate cookie
# Then directly hit authenticated resource
curl -s https://target.com/dashboard \
  -H "Cookie: session=INTERMEDIATE_SESSION_TOKEN" \
  -L | grep -i "welcome\|dashboard\|logout"
```

OTP brute force (no rate limit):
```bash
for code in $(seq -w 0 999999); do
  RESP=$(curl -s -X POST https://target.com/mfa/verify \
    -H "Cookie: session=SESS_TOKEN" \
    -d "otp=$code")
  if echo "$RESP" | grep -q "success"; then
    echo "VALID OTP: $code"
    break
  fi
done
```

Burp Intruder OTP brute force payload list (6-digit):
```
000000
000001
...
999999
# Generate with: seq -w 0 999999 > otp_payloads.txt
```

Response manipulation attempt:
```
# Intercept POST /mfa/verify response
# Original: {"authenticated":false,"mfa_required":true}
# Modified: {"authenticated":true,"mfa_required":false}
```

Skip MFA parameter injection:
```bash
curl -X POST https://target.com/mfa/verify \
  -H "Cookie: session=SESS_TOKEN" \
  -d "otp=123456&skip_mfa=true"

curl -X POST https://target.com/mfa/verify \
  -H "Cookie: session=SESS_TOKEN" \
  -d "otp=null&mfa_bypass=1"
```

OTP reuse test:
```bash
# Step 1: Get and submit valid OTP
curl -X POST https://target.com/mfa/verify \
  -H "Cookie: session=$SESS" \
  -d "otp=847291"  # valid code you have

# Step 2: Immediately resubmit same code
curl -X POST https://target.com/mfa/verify \
  -H "Cookie: session=$SESS" \
  -d "otp=847291"  # same code
```

## Burp Suite Tips
- Use **Repeater** to replay OTP codes after they should be expired — extend the time and test if old TOTPs from the previous 30s window are accepted.
- In **Proxy**, intercept the response body from the MFA check endpoint and modify `mfa_required` or `authenticated` flags to test client-side trust.
- **Intruder** (Sniper on OTP field, number payload 000000–999999): set thread count high and watch response length for the success condition — confirm no rate limiting first.
- The **Burp Match and Replace** rule can automatically strip an MFA header or change a boolean in every response.
- Install **AuthMatrix** (BApp) to systematically map which endpoints require MFA and identify those that don't.
- Use **Macro** in Session Handling to automate the first password step, letting Intruder focus solely on OTP brute force.

## Tools
- **Burp Suite** — MFA flow interception, response manipulation, OTP brute force.
- **evilginx2** — Reverse proxy phishing framework that captures MFA codes in real time (phishing attack simulation).
- **Modlishka** — Another reverse proxy for real-time MFA phishing.
- **mfa-bypass-checker** — Custom scripts to test common MFA bypass patterns.
- **Nuclei** — MFA bypass templates for common frameworks.

## Remediation
- Implement server-side session state machine — the MFA endpoint must verify the session is in `mfa_pending` state before accepting OTP codes.
- Never trust client-supplied flags (`mfa_required`, `authenticated`) — determine authentication state entirely server-side.
- Invalidate OTP codes immediately after first use (prevent replay).
- Invalidate previous TOTP codes when a new one is generated or when login is re-initiated.
- Enforce strict rate limiting on OTP submission: maximum 5 attempts per session, then force re-authentication.
- Lock the account or add significant delay after 5 failed MFA attempts.
- Require re-authentication (not just MFA) for account recovery flows that can disable MFA.
- Implement MFA enforcement consistently on all surfaces: web app, mobile API, and any direct API access.
- Use TOTP (time-based OTP) over SMS where possible; SMS is vulnerable to SIM swap and SS7 attacks.

## References
https://portswigger.net/web-security/authentication/multi-factor
https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/11-Testing_Multi-Factor_Authentication
https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html
https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
https://cwe.mitre.org/data/definitions/308.html
