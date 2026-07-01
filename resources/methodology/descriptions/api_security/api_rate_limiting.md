# Missing API Rate Limiting

## Overview
Rate limiting controls how many requests a client can make to an API endpoint within a given time window. Without it, attackers can brute-force credentials, enumerate resources, scrape data, submit bulk requests, or cause Denial of Service. Rate limiting is a fundamental protection layer for virtually all API endpoints, especially authentication, search, and data-heavy routes.

## How It Works
- No counter tracks how many times a client (by IP, token, or user ID) has accessed an endpoint.
- Attackers can send thousands of requests per second without being blocked or slowed.
- Brute force: test 1 million password combinations against a login endpoint.
- Data scraping: enumerate all users by cycling IDs (`/api/user/1`, `/api/user/2`, ...).
- OTP brute force: try all 1000000 combinations of a 6-digit code with no lockout.
- Bypass techniques: rotate IPs, use X-Forwarded-For header injection, or reset identifiers.

## Impact
- Account brute force and takeover via credential stuffing.
- OTP/MFA code brute force (2FA bypass).
- Large-scale data scraping/exfiltration.
- API key enumeration.
- Business denial of service (slow the system via resource exhaustion).
- Financial loss from abusive free-tier usage.

## Where to Look
- Login and authentication endpoints.
- Password reset endpoints.
- OTP/MFA verification.
- Search and autocomplete APIs.
- Email/phone/username check endpoints.
- Payment and transaction APIs.
- Account registration.

## Testing Steps
1. Send 100 rapid requests to the login endpoint — check if any are rejected (429) or slowed.
2. Test password reset: request 50 resets for the same email — do you get rate limited?
3. For OTP: try 100 different OTP codes in rapid succession — do any get blocked?
4. Check for rate limit headers in the response: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `Retry-After`.
5. Test rate limit bypass via `X-Forwarded-For: 1.2.3.4` header rotation.
6. Test if rate limiting is per-IP, per-user, or per-session (different bypass strategies).
7. Check if rate limit counter resets after a specific action (logout, new session).

## Payloads / Techniques
```bash
# Basic rate limit detection
for i in $(seq 1 100); do
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST https://target.com/api/login \
    -d '{"email":"test@test.com","password":"wrongpass"}')
  echo "Request $i: HTTP $status"
  if [ "$status" -eq "429" ]; then
    echo "Rate limit hit at request $i!"
    break
  fi
done

# Test X-Forwarded-For bypass
for i in $(seq 1 100); do
  curl -s -X POST https://target.com/api/login \
    -H "X-Forwarded-For: 10.0.0.$i" \
    -d '{"email":"victim@test.com","password":"wrongpass"}' | \
    grep -i "rate\|limit\|429\|blocked"
done

# OTP brute force test (6 digits)
for code in $(seq -w 0 999999); do
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST https://target.com/api/verify-otp \
    -H "Cookie: session=VALID_SESSION" \
    -d "{\"otp\": \"$code\"}")
  echo "OTP $code: HTTP $status"
  if [ "$status" = "200" ]; then
    echo "Valid OTP found: $code"
    break
  fi
  if [ "$status" = "429" ]; then
    echo "Rate limited at OTP $code"
    break
  fi
done
```

## Burp Suite Tips
- Use **Turbo Intruder** (BApp Store) for high-speed rate limit testing — can send thousands of requests per second.
- In **Intruder**, observe if responses change after N requests (different length, 429 status).
- Check response headers for `X-RateLimit-*` headers in **Repeater** or **Proxy**.
- Use **Intruder** with IP rotation (X-Forwarded-For payload list) to test bypass.

## Tools
- Burp Suite Turbo Intruder (BApp extension) — high-throughput testing
- Hydra — authentication brute force
- wfuzz — web fuzzer with rate limit detection
- ffuf — fast web fuzzer

## Remediation
- Implement rate limiting at the API gateway or web server level (not just application code).
- Apply different limits per endpoint sensitivity: 5 req/min for login, 100 req/min for search.
- Use token bucket or sliding window algorithms for smooth limiting.
- Rate limit by IP AND by user ID AND by API key (don't rely on a single identifier).
- Do not allow X-Forwarded-For to bypass rate limiting unless the proxy is internal and trusted.
- Return 429 with `Retry-After` header when limit is exceeded.
- Implement progressive delays (exponential backoff) as an alternative to hard blocks.
- Alert on unusual spike patterns (e.g., 1000 login attempts from one IP in 1 minute).

## References
https://owasp.org/www-project-api-security/ (API4:2023 Unrestricted Resource Consumption)
https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html
https://portswigger.net/web-security/api-testing
