# Username Enumeration

## Overview
Username enumeration occurs when an application reveals whether a specific username or email address is registered, allowing an attacker to build a validated list of accounts for targeted attacks. This information can be leaked through different error messages, response timing, HTTP status codes, or behavioral differences between valid and invalid accounts. Even if passwords are secure, a confirmed list of valid usernames dramatically lowers the bar for targeted phishing, credential stuffing, and brute force attacks.

## How It Works
- Different error messages: "Invalid username" vs. "Invalid password" reveals that the username exists.
- Different HTTP response codes: `200 OK` for valid user + wrong password vs. `404 Not Found` for unknown user.
- Response timing: the server hashes the password only when the username is valid — creating a measurable timing difference (typically 50–200ms) that reveals valid accounts.
- Password reset forms: "A reset email has been sent to [email]" vs. "No account with that email" directly confirms account existence.
- Registration forms: "Email already in use" error during account creation confirms the email is registered.
- Account lockout messages referencing the account state reveal its existence.
- Profile picture or user-not-found page differences when accessing `/users/username`.

## Impact
- Attacker builds a confirmed list of valid usernames/emails for targeted credential stuffing.
- Enables targeted phishing campaigns using confirmed account emails.
- Combined with brute force or default credential testing on confirmed accounts.
- Violates user privacy — reveals who uses the application.
- Enables targeted social engineering ("we know your account is registered at...").

## Where to Look
- Login error messages (compare response for valid user + wrong password vs. unknown user + any password).
- Password reset form response messages.
- User registration form — "email already taken" errors.
- User profile pages (`/profile/username`, `/user/123`) — 200 vs 404 vs 403 differences.
- API endpoints: `GET /api/users/{username}`, `GET /api/users?email=test@test.com`.
- Account lockout messages that reference the account by name or state.
- Timing differences — measure response time across multiple attempts to the same endpoint.
- HTTP response body length differences between valid and invalid users.

## Testing Steps
1. Submit a login with a known-invalid username (random string) + wrong password and record the exact response (body text, status code, response time, body length).
2. Submit a login with a likely-valid username (e.g., `admin`, `administrator`, `test`) + wrong password and compare every aspect of the response.
3. Submit the password reset form with a known-invalid email and record the response message.
4. Submit the password reset form with a known-valid email (e.g., an admin email found in public records) and compare.
5. Register a new account with an email you own; attempt to re-register the same email and observe the error message.
6. Time 50+ login requests for each condition (valid/invalid username) using Python to detect statistically significant timing differences.
7. Fuzz the `username` or `email` parameter on the login endpoint with a wordlist and sort results by response length/status to find valid accounts.
8. Check the API for user lookup endpoints: `GET /api/users/admin`, `GET /api/check-email?email=admin@target.com`.

## Payloads / Techniques

Timing-based enumeration in Python:
```python
import requests
import time

TARGET = "https://target.com/login"
KNOWN_BAD_USER = "thisuserdoesnotexist12345xyz"
TEST_USERS = ["admin", "administrator", "test", "support", "info", "user1"]

def measure(username, password="wrongpassword", n=10):
    times = []
    for _ in range(n):
        start = time.perf_counter()
        requests.post(TARGET, data={"username": username, "password": password})
        times.append(time.perf_counter() - start)
    return sum(times) / len(times)

baseline = measure(KNOWN_BAD_USER)
print(f"Baseline (invalid user): {baseline:.4f}s")
for user in TEST_USERS:
    t = measure(user)
    print(f"{user}: {t:.4f}s  delta={t-baseline:+.4f}s")
```

Ffuf username enumeration:
```bash
ffuf -w /usr/share/wordlists/usernames.txt:FUZZ \
  -X POST \
  -u https://target.com/login \
  -d "username=FUZZ&password=wrongpass" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -fr "Invalid username" \
  -mc all \
  -fs 1234
```

Password reset enumeration:
```bash
ffuf -w emails.txt:FUZZ \
  -X POST \
  -u https://target.com/forgot-password \
  -d "email=FUZZ" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -fw 12
```

API user lookup:
```bash
ffuf -w /usr/share/seclists/Usernames/Names/names.txt:FUZZ \
  -u https://target.com/api/users/FUZZ \
  -H "Authorization: Bearer $TOKEN" \
  -fc 404
```

Registration email check:
```bash
curl -s -X POST https://target.com/register \
  -d "email=admin@target.com&password=Test1234!" \
  | grep -i "already\|exist\|taken\|registered"
```

## Burp Suite Tips
- Use **Comparer**: send two login responses (valid user / invalid user) to Comparer and diff them — even single-word differences in body text are detectable.
- **Intruder** (Sniper mode): fuzz the username field with a username wordlist; sort results by **Response Length** — responses with different lengths indicate valid accounts.
- Enable **Response Timing** column in Intruder results (right-click the column header) to detect timing-based enumeration.
- The **Logger** extension records all response sizes and times for easy filtering.
- Use the **Autorize** or **Account Enumerator** extension from BApp Store to automate username enumeration checks.
- In **Repeater**, compare requests with `username=admin` vs. `username=zzzznotauser` — toggle between tabs quickly to spot message differences.

## Tools
- **ffuf** — Fast web fuzzer for enumerating usernames via response length/content filtering.
- **Burp Suite Intruder** — Response size and timing comparison during enumeration.
- **OWASP ZAP** — Active scan includes username enumeration detection rules.
- **timing-attack.py** — Custom scripts measuring statistically significant response time differences.
- **Nuclei** — Templates for username enumeration across common frameworks.

## Remediation
- Use a single, generic error message for all authentication failures: "Invalid username or password."
- Use the same error message on password reset regardless of whether the email is registered; instead, always say "If an account with that email exists, a reset link has been sent."
- Ensure the server performs the same computational work (including password hashing) regardless of whether the username is valid or not — this prevents timing side channels.
- Return the same HTTP status code (`200 OK` or `401 Unauthorized`) for all authentication failures regardless of the failure reason.
- Implement rate limiting and IP-based throttling on all authentication and user-lookup endpoints to slow down enumeration.
- Audit public API endpoints for user discovery functionality — ensure they require authentication and proper authorization.
- Remove user profile pages that return a 200 vs 404 based on whether the user exists, or require authentication to view profiles.

## References
https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account
https://portswigger.net/web-security/authentication/password-based#username-enumeration
https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
https://cwe.mitre.org/data/definitions/204.html
https://cwe.mitre.org/data/definitions/208.html
