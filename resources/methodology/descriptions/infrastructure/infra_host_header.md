# Host Header Injection

## Overview
The `Host` header specifies the domain of the target server and is often trusted implicitly by web applications for link generation, password reset email construction, SSRF, and cache routing. When an application uses the `Host` header in security-sensitive operations without validation, attackers can manipulate it to redirect password reset links to attacker-controlled domains, bypass access controls, or perform SSRF.

## How It Works
- Password reset flows: `"Click here: https://{Host}/reset?token=XYZ"` — injecting `evil.com` poisons the reset link.
- Cache poisoning: `Host` header change routes the request to a different back-end or poisons the cache.
- SSRF: Internal services check `Host` to route requests — injecting an internal hostname may allow SSRF.
- Access control bypass: some back-ends use `Host` to determine if a request is internal or external.
- Open redirect via `Host` if the application generates absolute URLs using it.

## Impact
- Password reset token capture → account takeover.
- Cache poisoning for all users (if Host header is reflected and cached).
- SSRF to internal services.
- Bypassing IP-based access controls.
- Web cache deception.

## Where to Look
- Password reset flows that email the user a link.
- Any functionality that generates absolute URLs from the Host header.
- `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`, `X-Original-URL` — alternative host headers.
- Admin panels that check Host for local access detection.
- Any place the Host header appears in the response (reflected).

## Testing Steps
1. Intercept a password reset request and change the `Host` header to `evil.com`.
2. Trigger the password reset and check if the email contains `evil.com` in the reset link.
3. Try `X-Forwarded-Host: evil.com` (proxy-forwarded host header).
4. Test on pages that generate absolute URLs — does the URL change?
5. For access control bypass: change `Host: localhost` or `Host: 127.0.0.1` to access admin panels.
6. Inject a port number: `Host: target.com:evil.com` (some parsers are confused by this).
7. Check responses for `Host` header reflection in HTML, Location headers, or API responses.

## Payloads / Techniques
```bash
# Password reset Host header injection
curl -s -X POST https://target.com/forgot-password \
  -H "Host: evil.com" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=victim@target.com"
# Check if victim receives reset link with evil.com

# X-Forwarded-Host injection
curl -s -X POST https://target.com/forgot-password \
  -H "Host: target.com" \
  -H "X-Forwarded-Host: evil.com" \
  -d "email=victim@target.com"

# Absolute URL injection
curl -s https://target.com/ \
  -H "Host: evil.com" \
  | grep -i "evil.com"

# localhost bypass for admin
curl -s https://target.com/admin \
  -H "Host: localhost"

# Check if Host header is reflected in response
curl -s https://target.com/ \
  -H "Host: unique-string-12345.evil.com" \
  | grep "unique-string"

# Internal port scanning via Host header SSRF
for port in 80 443 8080 8443 3000 3306 5432 6379 27017; do
  curl -s https://target.com/api/status \
    -H "Host: 127.0.0.1:$port" \
    -H "X-Forwarded-Host: 127.0.0.1:$port" \
    -w "\nPort $port: %{http_code}\n" | tail -1
done
```

## Burp Suite Tips
- In **Repeater**, modify the `Host` header to `evil.com` or `localhost` and send.
- **Active Scanner** (Pro) tests for Host header injection on password reset and URL generation paths.
- Add `X-Forwarded-Host` alongside the legitimate `Host` header — some apps prefer the forwarded header.
- In **Intruder**, use a list of hosts to test which ones are reflected: `evil.com`, `localhost`, `127.0.0.1`, internal hostnames.

## Tools
- Burp Suite Repeater
- curl — manual testing
- ffuf — fuzzing Host header variations

## Remediation
- Never trust the `Host` header for security decisions — use a hardcoded configuration value for the application's domain.
- Set an explicit `APP_URL` configuration variable for password reset links and absolute URL generation.
- Validate the `Host` header against a whitelist of allowed domains on the server.
- Strip or ignore `X-Forwarded-Host`, `X-Original-URL`, and similar headers unless they come from trusted internal proxies.
- For admin-only pages: use network-level controls (IP allowlisting), not Host header checks.

## References
https://portswigger.net/web-security/host-header
https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning
https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection
