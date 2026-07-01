# Referrer-Policy Misconfiguration

## Overview
The `Referrer-Policy` HTTP header controls how much referrer information is sent when a user navigates from one page to another. Without a strict policy, sensitive path components, query parameters, and session tokens embedded in URLs are sent as `Referer` headers to external parties (analytics, CDN, third-party JS), leaking user data, authentication tokens, and security-sensitive URLs.

## How It Works
- By default (no `Referrer-Policy`), browsers send the full URL as `Referer` on cross-origin navigations.
- If a page includes `?token=abc123`, `?reset_token=xyz`, or `/user/12345/view` in the URL, these are sent to all third parties loaded on the page.
- Password reset links, magic login links, email confirmation tokens, and session IDs in URLs are particularly dangerous.
- Analytics platforms, advertising networks, and CDN providers receive these sensitive URL fragments.

## Impact
- Leakage of password reset tokens to third-party analytics services.
- Disclosure of internal URL structure to external parties.
- Session token theft if tokens appear in URLs (poor practice, but common).
- Leakage of PII in query parameters (name, email, search terms).
- Sensitive path disclosure (revealing internal tool paths, user IDs, content IDs).

## Where to Look
- Check `Referrer-Policy` response header.
- If absent or set to `no-referrer-when-downgrade` (default in older browsers) → full URL sent cross-origin.
- Check if the application uses tokens or sensitive data in URL query strings.
- Monitor third-party requests in browser Network tab for `Referer` headers.

## Testing Steps
1. Check `Referrer-Policy` header in response headers.
2. Navigate from a sensitive URL (e.g., password reset link) to an external resource.
3. In browser DevTools → Network tab, look for requests to third-party domains.
4. Inspect the `Referer` header on those requests — does it include sensitive path/query data?
5. Check if analytics scripts, fonts (Google Fonts), CDN resources receive the full referrer.
6. Look for password reset flows, magic links, or token-in-URL patterns that could be leaked.

## Payloads / Techniques
```bash
# Check referrer policy header
curl -s -D - https://target.com/ | grep -i referrer-policy

# Policy values and their behavior:
# no-referrer-when-downgrade  → sends full URL cross-origin HTTPS→HTTPS (insecure default)
# strict-origin               → sends only origin, not path/query
# strict-origin-when-cross-origin → RECOMMENDED: full URL same-origin, origin-only cross-origin
# no-referrer                 → sends nothing (most private, may break analytics)
# unsafe-url                  → always sends full URL (worst option)

# Test if referrer is sent to third parties
# Open browser DevTools → Network tab → Filter by "analytics|google|facebook"
# Click links on the page and check Referer header in outgoing requests
```

## Burp Suite Tips
- Check `Referrer-Policy` in response headers via the Proxy HTTP History headers panel.
- Use **Burp Collaborator** to receive Referer headers: link to a Collaborator URL and see what's sent.
- **Param Miner** can help identify query parameters that carry sensitive data.

## Tools
- Browser Developer Tools (Network tab)
- Mozilla Observatory — checks Referrer-Policy
- Security Headers — https://securityheaders.com/

## Remediation
- Set a strict Referrer-Policy header:
  `Referrer-Policy: strict-origin-when-cross-origin`
  (sends full URL for same-origin, only origin for cross-origin HTTPS, nothing for HTTPS→HTTP)
- For maximum privacy: `Referrer-Policy: no-referrer` or `same-origin`.
- Avoid placing sensitive tokens or identifiers in URLs — use POST bodies or HTTP headers instead.
- Set the policy at the web server level so all responses include it.
- Can also be set per-page: `<meta name="referrer" content="strict-origin">`.

## References
https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy
https://web.dev/referrer-best-practices/
https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/07-Test_HTTP_Strict_Transport_Security
