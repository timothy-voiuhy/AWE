# HTTP/2 Downgrade Attack

## Overview
HTTP/2 downgrade attacks exploit discrepancies between HTTP/2 front-ends and HTTP/1.1 back-ends. When a reverse proxy accepts HTTP/2 from clients but translates to HTTP/1.1 for back-end communication, header smuggling becomes possible because HTTP/2 headers have different framing rules than HTTP/1.1. Attackers can inject `\r\n` sequences in HTTP/2 pseudo-headers to craft HTTP/1.1 request smuggling payloads that bypass the front-end.

## How It Works
- HTTP/2 uses binary framing — no concept of `Content-Length` or `Transfer-Encoding: chunked` for body delimitation.
- When a front-end downgrades HTTP/2 to HTTP/1.1 for the back-end, it must synthesize these headers.
- **H2.CL**: Attacker sends HTTP/2 with a `content-length` header that mismatches the actual body length. The front-end forwards this CL to the back-end; back-end waits for more data per the stated CL.
- **H2.TE**: Attacker injects `transfer-encoding: chunked` as an HTTP/2 header. The front-end passes it to back-end; back-end interprets chunked encoding.
- **Header injection**: HTTP/2 headers can contain CRLF (`\r\n`) in values — when translated to HTTP/1.1, this injects new header lines.

## Impact
- HTTP request smuggling with all its consequences: cache poisoning, session hijacking, bypassing WAF.
- Header injection via CRLF in HTTP/2 header values — injecting arbitrary HTTP/1.1 headers.
- Bypassing front-end security controls (authentication, WAF rules).
- Capture of other users' requests (sessions, credentials).

## Where to Look
- Sites using HTTP/2 front-end (CDN, Nginx with HTTP/2) with HTTP/1.1 back-end.
- Check: `curl -s -I --http2 https://target.com | head` — does it return HTTP/2?
- Review HTTP version in Burp's Proxy history: `HTTP/2` in response line.
- Common setups: Cloudflare → Nginx, CloudFront → Apache, Nginx → Node.js.

## Testing Steps
1. Confirm the front-end supports HTTP/2: look for `HTTP/2` in the status line.
2. Check if the back-end uses HTTP/1.1: look for `Via: 1.1` or `Upgrade` headers suggesting HTTP/1.1 back-end.
3. Use Burp Suite's HTTP/2 support to test H2.CL and H2.TE smuggling.
4. In Repeater, enable HTTP/2 mode and add a `content-length` header that doesn't match body length.
5. Test CRLF injection in HTTP/2 header values.
6. Use the **HTTP Request Smuggler** BApp which has H2-specific tests.

## Payloads / Techniques
```
# H2.CL payload (in Burp Repeater with HTTP/2 enabled)
:method POST
:path /
:authority target.com
content-length: 0

GET /admin HTTP/1.1
Host: target.com
Content-Length: 10

x=1
# The back-end sees the smuggled GET /admin request prepended to the next real request

# H2.TE payload
:method POST
:path /
:authority target.com
transfer-encoding: chunked

0

GET /admin HTTP/1.1
Host: target.com

# CRLF injection via HTTP/2 header value
# In HTTP/2, header name: foo, value: "bar\r\nX-Injected: evil"
# When translated to HTTP/1.1: foo: bar\r\nX-Injected: evil (injects a new header)
:method GET
:path /
:authority target.com
foo: bar\r\nX-Injected: evil
```

```bash
# Check HTTP/2 support
curl -s -I --http2-prior-knowledge https://target.com | head -5
# Look for HTTP/2 in response

# Using h2cSmuggler for HTTP/2 to HTTP/1.1 tunneling attacks
git clone https://github.com/BishopFox/h2cSmuggler
python3 h2cSmuggler.py --smuggle-reqs "GET /admin HTTP/1.1\r\nHost: target.com\r\n\r\n" https://target.com/
```

## Burp Suite Tips
- Enable **HTTP/2** in Project Settings → HTTP → HTTP/2.
- In **Repeater**, right-click → Change to HTTP/2 to send requests via HTTP/2.
- **HTTP Request Smuggler** (BApp) has specific H2.CL and H2.TE test modes.
- Add headers with raw CRLF values using Burp's inspector pane.
- Watch for 500 errors, timeouts, or unexpected responses that indicate successful smuggling.

## Tools
- HTTP Request Smuggler (Burp BApp) — h2-specific modes
- h2cSmuggler — https://github.com/BishopFox/h2cSmuggler
- nghttp2 — HTTP/2 client for low-level testing

## Remediation
- Upgrade back-end connections to HTTP/2 end-to-end (H2 → H2, no downgrade).
- Configure the front-end to validate and normalize HTTP/2 headers before translation.
- Reject HTTP/2 requests with malformed or duplicate pseudo-headers.
- Keep front-end proxy software updated (patches for H2 smuggling variants are regularly released).
- Use strict HTTP/2 parsing that rejects CRLF in header values.

## References
https://portswigger.net/research/http2
https://portswigger.net/web-security/request-smuggling/advanced
https://bishopfox.com/blog/h2c-smuggling-request
