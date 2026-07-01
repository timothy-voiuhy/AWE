# Missing HTTP Strict-Transport-Security (HSTS)

## Overview
HTTP Strict Transport Security (HSTS) is a security header that instructs browsers to only communicate with a site over HTTPS, preventing protocol downgrade attacks. Without HSTS, an attacker performing a Man-in-the-Middle (MitM) attack can force the victim's browser to use HTTP, even for an HTTPS-only site, enabling traffic interception and session hijacking.

## How It Works
- Without HSTS: a MitM attacker (on shared Wi-Fi, etc.) intercepts the initial HTTP request, strips TLS (SSL stripping), and serves plain HTTP. The browser and server communicate in cleartext.
- With HSTS: after the first HTTPS visit, the browser remembers to always use HTTPS — it refuses to connect over HTTP, even if the page returns a redirect.
- SSL stripping (sslstrip) exploits sites without HSTS by transparently downgrading HTTPS to HTTP.

## Impact
- Session token theft via SSL stripping on untrusted networks.
- Man-in-the-Middle interception of authentication credentials.
- Cookie theft for cookies not marked with `Secure` flag.
- Complete traffic interception on shared networks (coffee shops, airports).

## Where to Look
- Check the `Strict-Transport-Security` response header on HTTPS responses.
- Check its parameters: `max-age`, `includeSubDomains`, `preload`.
- A short `max-age` (< 31536000 seconds / 1 year) provides weak protection.
- Missing `includeSubDomains` leaves subdomains vulnerable.

## Testing Steps
1. Visit the site over HTTPS and capture the response headers in Burp.
2. Look for `Strict-Transport-Security` header.
3. If absent → HSTS not implemented.
4. If present but with short `max-age` (< 1 year) → weak HSTS.
5. Check if `includeSubDomains` is present — if not, subdomains are unprotected.
6. Test SSL stripping with sslstrip (on a test network you control).
7. Check https://hstspreload.org to see if the domain is in the HSTS preload list.

## Payloads / Techniques
```bash
# Check for HSTS header
curl -s -D - https://target.com/ | grep -i strict-transport

# Good HSTS header example:
# Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
#  max-age=63072000 = 2 years
#  includeSubDomains = all subdomains also enforced
#  preload = eligible for browser preload list

# SSL Stripping test (on controlled network)
sudo sslstrip -l 8080 &
sudo iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080

# Test redirect behavior without HSTS
curl -s -D - http://target.com/ | head -5
# If it returns 200 over HTTP → HSTS missing or not enforced
```

## Burp Suite Tips
- **Active Scanner** (Pro) reports missing/weak HSTS headers.
- In **Repeater**, check response headers for the HSTS directive.
- **Security Headers** check via the Response Headers panel in Proxy.

## Tools
- curl — check HSTS header presence
- Mozilla Observatory — https://observatory.mozilla.org/
- Security Headers — https://securityheaders.com/ (automated header check)
- sslstrip — SSL stripping tool (test lab only)

## Remediation
- Add the HSTS header to all HTTPS responses:
  `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`
- Set `max-age` to at least 1 year (31536000 seconds).
- Include `includeSubDomains` to protect all subdomains.
- Submit to HSTS preload list at https://hstspreload.org for maximum protection.
- Ensure all HTTP requests redirect to HTTPS before applying HSTS.
- Apply the header at the web server or reverse proxy level consistently.

## References
https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security
https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html
https://hstspreload.org/
https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning
