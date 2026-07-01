# User Enumeration via Response Differences

## Overview
User enumeration allows attackers to determine whether a given email address, username, or phone number is registered with an application. Even subtle differences in server responses — different error messages, response times, status codes, or page content — reveal the existence of an account. This enables targeted attacks: phishing, credential stuffing, and social engineering against known valid accounts.

## How It Works
- **Message difference**: "Invalid email" vs "Invalid password" — the former reveals the email doesn't exist.
- **Status code difference**: 200 for known users, 404 for unknown users.
- **Timing difference**: Password hash comparison takes longer than a simple "user not found" check.
- **Password reset difference**: "If an account exists, we'll send an email" vs hard-coding a specific path that reveals whether the email was found.
- **Registration flow**: "This email is already taken" during sign-up reveals the email is registered.
- **OAuth errors**: Different error messages when linking social accounts to existing vs. non-existing accounts.

## Impact
- Building a list of valid usernames/emails for targeted attacks.
- Credential stuffing with confirmed-valid accounts (no wasted attempts).
- Targeted phishing against known account holders.
- Privacy violation (revealing who uses the service).
- Enables password spraying attacks.

## Where to Look
- Login form error messages
- Password reset flow responses
- "Forgot username" flows
- Account registration: "email already taken"
- Account verification flows (magic link, SMS)
- API: `/auth/login`, `/auth/forgot-password`, `/api/check-email`

## Testing Steps
1. **Login form**: Submit with a known-valid email + wrong password → note the error message.
2. Submit with a non-existent email + any password → compare error messages exactly.
3. **Password reset**: Submit a known-valid email, note the response (message + status code + timing).
4. Submit a non-existent email for password reset → compare response.
5. **Timing attack**: Measure response time for valid vs. invalid email (5+ requests each, average).
6. **Registration**: Try registering with an email you suspect is taken → check the error.
7. **API**: Check `/api/check-email?email=test@test.com` — some apps have explicit email-check endpoints.
8. Test OAuth/SSO: "Link with Google" flow may reveal whether the Google email is already registered.

## Payloads / Techniques
```bash
# Test login response differences
# Valid user, wrong password:
curl -s -X POST https://target.com/login \
  -d "email=known@target.com&password=wrongpassword" \
  -w "\nTime: %{time_total}s\nHTTP: %{http_code}\n"

# Invalid user:
curl -s -X POST https://target.com/login \
  -d "email=nonexistent@target.com&password=wrongpassword" \
  -w "\nTime: %{time_total}s\nHTTP: %{http_code}\n"

# Password reset enumeration
curl -s -X POST https://target.com/forgot-password \
  -d "email=known@target.com" | grep -i "email\|sent\|found\|not found"

curl -s -X POST https://target.com/forgot-password \
  -d "email=nonexistent@target.com" | grep -i "email\|sent\|found\|not found"

# Email check endpoint discovery
curl -s "https://target.com/api/check-email?email=test@gmail.com"

# Timing attack using Python
python3 -c "
import requests, time
for email in ['known@target.com', 'fake@random.com']:
    start = time.time()
    r = requests.post('https://target.com/login',
        data={'email': email, 'password': 'wrongpass123'})
    elapsed = time.time() - start
    print(f'{email}: {elapsed:.3f}s, {r.status_code}')
"
```

## Burp Suite Tips
- In **Comparer**, compare responses for valid vs. invalid email submissions — even a single character difference matters.
- Use **Intruder** with email list + constant wrong password to enumerate valid accounts (compare response length/status).
- The **Burp Active Scanner** (Pro) tests for username enumeration on login/reset forms.
- Check **response body length**, not just status code — same 200 response may have different body lengths.

## Tools
- Burp Suite Intruder + Comparer
- Hydra (with a single wrong password across usernames)
- ffuf — https://github.com/ffuf/ffuf (fast fuzzing for email check endpoints)

## Remediation
- Use identical generic messages for all error conditions: "If an account exists with this email, a reset link has been sent."
- Ensure identical response times for valid vs. invalid accounts (add a constant-time delay or hash even for non-existent users).
- Return identical HTTP status codes for both cases.
- Implement rate limiting on login and reset endpoints to prevent bulk enumeration.
- Consider CAPTCHA on password reset to deter automated enumeration.

## References
https://portswigger.net/web-security/authentication/password-based
https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account
https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
