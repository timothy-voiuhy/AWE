# Missing / Weak Content-Security-Policy

## Overview
Content Security Policy (CSP) is an HTTP response header that tells browsers which sources of content are allowed to load on a page. A missing or weak CSP dramatically increases the exploitability of XSS vulnerabilities — without CSP, a single XSS payload can exfiltrate cookies and credentials. Even if no XSS exists today, a weak CSP provides no safety net if one is introduced.

## How It Works
- Without CSP: any injected `<script>` tag or inline event handler executes immediately.
- With a weak CSP like `default-src *` or `script-src 'unsafe-inline'`: CSP provides no protection.
- Attackers can use CSP weakness to exfiltrate data using `connect-src *` (fetch to any endpoint).
- Common misconfigurations: `unsafe-inline`, `unsafe-eval`, wildcard origins (`*`), data URIs.
- JSONP endpoints or open redirects on allowlisted domains can bypass script-src restrictions.

## Impact
- No mitigation layer for XSS attacks — any injected script executes fully.
- Data exfiltration to attacker domains via `fetch`, `XMLHttpRequest`, `WebSocket`.
- Malicious script loading from attacker CDN domains.
- Clickjacking if `frame-ancestors` directive is absent.

## Where to Look
- Check the `Content-Security-Policy` response header on all pages.
- Also check `Content-Security-Policy-Report-Only` for policy intent.
- Evaluate each directive for insecure values.
- Missing CSP = no header at all.

## Testing Steps
1. Capture any page response in Burp and check for `Content-Security-Policy` header.
2. If absent → weak by default.
3. If present, analyze each directive using CSP Evaluator.
4. Look for: `unsafe-inline`, `unsafe-eval`, wildcard `*`, `data:`, `blob:` in script-src.
5. Check if `default-src` is set (covers unlisted directives).
6. Verify `connect-src` doesn't allow `*` (data exfiltration bypass).
7. Check `frame-ancestors` — if absent, clickjacking may be possible.
8. Look for allowlisted JSONP endpoints: `script-src https://accounts.google.com` → check for JSONP on accounts.google.com.

## Payloads / Techniques
```
# Weak CSP examples (INSECURE):
Content-Security-Policy: default-src *
Content-Security-Policy: script-src 'unsafe-inline' 'unsafe-eval'
Content-Security-Policy: default-src 'self' 'unsafe-inline'
Content-Security-Policy: script-src 'self' https:
Content-Security-Policy: default-src *; script-src 'self'

# Check via curl
curl -s -D - https://target.com/ | grep -i content-security-policy

# Strong CSP example (SECURE):
Content-Security-Policy: 
  default-src 'none';
  script-src 'self' 'nonce-{random}';
  style-src 'self';
  img-src 'self' data:;
  connect-src 'self';
  frame-ancestors 'none';
  base-uri 'self';
  form-action 'self';

# Test CSP bypass via JSONP (if googleapis.com is in script-src):
<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1)"></script>

# Nonce bypass via DOM clobbering or prototype pollution (advanced)
```

## Burp Suite Tips
- The **CSP Auditor** (BApp Store) extension automatically analyzes CSP headers for weaknesses.
- In **Repeater**, manually inspect the `Content-Security-Policy` header in responses.
- **Active Scanner** (Pro) reports missing security headers including CSP.

## Tools
- CSP Evaluator — https://csp-evaluator.withgoogle.com/ (paste CSP for automated analysis)
- CSP Auditor (Burp BApp extension)
- Mozilla Observatory — https://observatory.mozilla.org/ (scans CSP and other headers)

## Remediation
- Implement a strict CSP with specific allowlists — avoid `unsafe-inline`, `unsafe-eval`, and wildcards.
- Use nonces for inline scripts: `<script nonce="{random}">` with `script-src 'nonce-{random}'`.
- Use `default-src 'none'` and explicitly allow only needed sources.
- Include `frame-ancestors 'self'` to prevent clickjacking.
- Include `base-uri 'self'` to prevent base tag injection.
- Test CSP in report-only mode first, then enforce after verifying no legitimate breakage.

## References
https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html
https://portswigger.net/web-security/cross-site-scripting/content-security-policy
https://csp-evaluator.withgoogle.com/
