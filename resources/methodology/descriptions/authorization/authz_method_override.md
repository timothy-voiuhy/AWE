# HTTP Method Override

## Overview
Some frameworks and proxies support HTTP method override headers (`X-HTTP-Method-Override`, `X-Method-Override`, `_method`) that allow a client to submit a POST request but declare it should be treated as PUT, DELETE, or PATCH. If a server honors these headers without enforcing the same authorization checks as the real HTTP method, an attacker can perform restricted operations through an apparently innocuous POST.

## How It Works
- The server reads `X-HTTP-Method-Override: DELETE` in a POST request and routes it to the DELETE handler.
- The DELETE handler may have access controls, but the POST route (which the request actually arrived on) may have looser or no controls.
- Some legacy firewall rules or WAFs only inspect the actual HTTP method, not override headers, allowing bypass.
- Similar to `_method=DELETE` in HTML form submissions (used by Rails, Laravel, etc.).

## Impact
- Delete resources as a user who only has read access.
- Perform PATCH/PUT modifications via a bypass of write-restricted controls.
- Trigger internal state changes in APIs that distinguish behavior by HTTP method.
- Bypass WAF rules that are method-specific.

## Where to Look
- APIs that use RESTful HTTP verbs (POST/PUT/DELETE/PATCH) with method-based authorization.
- Endpoints that respond differently to different HTTP methods.
- Ruby on Rails, Laravel, Express.js apps (built-in `_method` support).
- Any proxy or load balancer layer that rewrites or passes override headers.

## Testing Steps
1. Find a resource you can read (GET) but not modify (DELETE/PUT).
2. Send a POST request to the same endpoint with `X-HTTP-Method-Override: DELETE`.
3. Also try `X-Method-Override: DELETE` and `X-HTTP-Method: DELETE`.
4. Try the query parameter form: `POST /resource/123?_method=DELETE`.
5. Try form body field: `POST /resource/123` with body `_method=DELETE`.
6. Observe if the resource is deleted or modified despite your lack of DELETE permission.
7. Test TRACE method via override: `X-HTTP-Method-Override: TRACE`.
8. Test if PUT/PATCH is triggered via `X-HTTP-Method-Override: PUT` on a POST endpoint.

## Payloads / Techniques
```http
# Override to DELETE
POST /api/users/456 HTTP/1.1
Host: target.com
Authorization: Bearer <limited_user_token>
X-HTTP-Method-Override: DELETE
Content-Length: 0

# Override to PUT
POST /api/admin/config HTTP/1.1
Host: target.com
Authorization: Bearer <limited_user_token>
X-HTTP-Method-Override: PUT
Content-Type: application/json

{"setting": "debug", "value": true}

# Query parameter form
POST /api/posts/789?_method=DELETE HTTP/1.1
Host: target.com
Authorization: Bearer <limited_user_token>

# Form body (Rails/Laravel style)
POST /posts/789 HTTP/1.1
Content-Type: application/x-www-form-urlencoded

_method=DELETE&authenticity_token=...
```

```bash
curl -X POST https://target.com/api/users/456 \
  -H "Authorization: Bearer <user_token>" \
  -H "X-HTTP-Method-Override: DELETE"
```

## Burp Suite Tips
- In **Repeater**, change the HTTP method to POST and add the override header to test restriction bypasses.
- Use **Intruder** to try multiple override headers and values in a single run.
- **Match and Replace** rule: automatically inject `X-HTTP-Method-Override` into all POST requests during testing.

## Tools
- Burp Suite Repeater / Intruder
- curl for quick manual testing

## Remediation
- Disable HTTP method override headers if not required for your application.
- If needed, apply the same authorization checks for the overridden method as for the real method.
- Use an allowlist for which methods can be overridden and on which endpoints.
- Configure WAF/reverse proxy to strip override headers from external traffic.
- Prefer explicit HTTP verbs via AJAX/fetch in modern apps instead of form-based method override.

## References
https://portswigger.net/web-security/request-smuggling/exploiting
https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods
https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html
