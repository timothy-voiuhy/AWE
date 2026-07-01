# Password Complexity Enforcement

## Overview
Password complexity enforcement ensures users choose passwords that are resistant to guessing and brute force attacks. Weak or absent enforcement allows users (and service accounts) to set trivially guessable passwords like `password`, `123456`, or `company2024`. Modern guidance from NIST SP 800-63B emphasizes minimum length and blocklisting common passwords over complex character-class rules that users circumvent predictably.

## How It Works
- The server validates the password field during registration and password change flows against a policy (minimum length, character classes, blocklist).
- Client-side-only validation can be bypassed by intercepting the request and modifying it before it reaches the server.
- The validation may only be enforced at the UI level (JavaScript) but not at the API level, allowing direct API calls to set weak passwords.
- Common misconfigurations: minimum length of 6–8 characters, no blocklist of common passwords, maximum length limit (indicates plaintext or truncated storage), no validation on password change/reset flow.
- An overly strict policy (requiring all character classes, banning repeated characters) paradoxically weakens security by pushing users to predictable patterns like `Password1!`.

## Impact
- Users set weak, guessable passwords that fall to dictionary attacks.
- Service accounts and integration credentials set to application name + year (e.g., `AppName2023`).
- Password reset flows that allow weaker passwords than registration, creating a downgrade path.
- Administrators set passwords like `Admin1!` that meet complexity rules but are trivially guessable.

## Where to Look
- User registration form (`/register`, `/signup`).
- Password change form (profile/settings page).
- Password reset flow (after clicking reset link).
- Admin-created user flows — admins setting initial passwords for new users.
- API endpoints that accept a `password` parameter directly.
- Service account creation APIs.
- Check for maximum password length — a limit under 64–72 characters suggests truncation or plaintext storage.

## Testing Steps
1. Navigate to the registration or password change form and attempt to set obviously weak passwords: `a`, `123`, `password`, `123456`, `abc123`.
2. Intercept the registration request in Burp and modify the password field to a weak value after any client-side validation has passed — submit and observe if the server rejects it.
3. Attempt common patterns that meet typical complexity rules but are weak: `Password1`, `Password1!`, `Qwerty123!`.
4. Test the password reset flow separately — submit the same weak passwords through the reset endpoint.
5. Check if there is a maximum password length; try a 200-character password and see if it is accepted or truncated.
6. Test the API endpoint directly (bypassing the web form) with a weak password via curl or Burp Repeater.
7. Check if the current password is in a blocklist by attempting well-known leaked passwords (top 10 from HaveIBeenPwned list).
8. Attempt to set the password to the username, email address, or company name — these predictable choices should be rejected.

## Payloads / Techniques

Test server-side validation by bypassing JavaScript:
```bash
# First attempt through normal form to see what client-side blocks
# Then send directly to API to test server-side
curl -X POST https://target.com/api/users/register \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","email":"test@test.com","password":"123"}'

curl -X POST https://target.com/api/users/register \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","email":"test@test.com","password":"password"}'

curl -X POST https://target.com/api/users/register \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","email":"test@test.com","password":"abc123"}'
```

Test maximum length (truncation detection):
```bash
LONG_PASS=$(python3 -c "print('A'*200)")
curl -X POST https://target.com/api/change-password \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"new_password\":\"$LONG_PASS\"}"
# If accepted, then try first 72 chars of same pass - if also works, truncation confirmed
```

Test weak passwords that satisfy common complexity rules:
```
Password1
Password1!
Welcome1
Summer2024
Winter2024!
Company123!
Admin2024!
[companyname]2024!
[companyname]123
January2024
P@ssw0rd
Qwerty123!
```

Test password change endpoint:
```bash
curl -X PUT https://target.com/api/user/password \
  -H "Authorization: Bearer $USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"current_password":"OldPassword1!","new_password":"abc"}'
```

## Burp Suite Tips
- Use **Repeater** to test server-side validation after disabling JavaScript in the browser or intercepting the request after client-side validation passed.
- In **Proxy**, use the "Intercept" feature and modify the `password` parameter mid-flight to a weak value, then forward — this bypasses any client-side complexity meter.
- Use **Intruder** with a list of common weak passwords to test which ones are accepted by the change-password or register endpoint.
- Compare responses from the registration endpoint vs. the password reset endpoint with identical weak passwords — inconsistency indicates the reset flow lacks proper validation.
- Use the **Param Miner** extension to discover hidden parameters that might bypass complexity checks (e.g., `bypass_complexity=true`, `admin_override=1`).

## Tools
- **Burp Suite** — Request interception to bypass client-side validation.
- **curl** — Direct API testing with arbitrary password values.
- **Hydra / Hashcat** — Demonstrate impact by cracking weak passwords offline once hashes are obtained.
- **PwnedPasswordsAPI** — Check if a given password appears in known breach datasets (Have I Been Pwned API).
- **zxcvbn** — Password strength estimator used to test what score common weak passwords receive.

## Remediation
- Enforce a minimum password length of at least 12 characters (NIST recommends allowing up to 64+ characters).
- Implement a blocklist of the top 10,000–100,000 most common passwords (sources: HaveIBeenPwned, SecLists).
- Validate password complexity server-side — never rely solely on client-side JavaScript.
- Apply the same policy consistently to registration, password change, password reset, and admin-created accounts.
- Do NOT enforce maximum password lengths below 64 characters; use bcrypt (which handles length natively) to prevent hash truncation issues.
- Avoid overly strict character-class rules (at least one uppercase, lowercase, number, symbol) — these are counterproductive per NIST SP 800-63B; length and blocklisting are more effective.
- Check passwords against breach databases at registration and periodic intervals using the k-Anonymity model API from HaveIBeenPwned.
- Display a password strength meter (zxcvbn-based) to guide users toward stronger choices.

## References
https://pages.nist.gov/800-63-3/sp800-63b.html
https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks
https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
https://haveibeenpwned.com/Passwords
https://cwe.mitre.org/data/definitions/521.html
