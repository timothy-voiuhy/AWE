# Missing Authorization on API Endpoints

## Overview
Many applications correctly enforce authorization in UI-driven flows but neglect to apply the same checks on underlying API endpoints. Attackers can bypass UI restrictions by crafting direct API calls, accessing functions that the interface never exposes to lower-privileged users but that the backend executes without enforcement.

## How It Works
- The frontend hides admin controls from non-admin users, but the API endpoint (`DELETE /api/users/{id}`, `POST /api/admin/config`) exists and responds to any authenticated request.
- Mobile apps, JS bundles, or Swagger docs may reveal endpoints not linked from the UI.
- Version changes: `/v2/admin/users` added authorization, but the older `/v1/admin/users` was forgotten.
- Internal microservices assumed to be unreachable directly but exposed through gateway misconfig.

## Impact
- Complete admin takeover without admin credentials.
- Mass data deletion, modification, or exfiltration.
- Enabling/disabling features, toggling feature flags.
- Accessing other users' private data at scale.

## Where to Look
- JavaScript bundles — search for `/api/`, `fetch(`, `axios.` calls referencing admin paths.
- Swagger/OpenAPI spec at `/swagger.json`, `/api-docs`, `/openapi.yaml`.
- Network traffic during admin functions while logged in as a privileged user — then replay those requests as a non-privileged user.
- Mobile app decompilation: extract API endpoint strings from APK/IPA.
- Paths like `/api/admin/`, `/api/internal/`, `/api/v1/management/`.
- Endpoints referenced in error messages or HTTP headers (`X-Endpoint`).

## Testing Steps
1. Create two accounts: User (low privilege) and Admin (high privilege).
2. As Admin, perform all available admin actions and capture every API request in Burp.
3. Export the captured requests to a file or note the endpoints.
4. Switch to the User session and replay each Admin request with User credentials.
5. Note any that return 200/201 instead of 401/403.
6. Spider/crawl JS bundles for API paths and test each one for authorization.
7. Check common admin endpoints: `/api/admin`, `/api/users` (all users), `/api/settings`.
8. Test REST verbs that may lack checks: DELETE and PATCH on resources you own vs. global ones.
9. Check if removing the `Authorization` header entirely (unauthenticated) reveals any data.

## Payloads / Techniques
```bash
# Test admin endpoint as regular user
curl -X GET https://target.com/api/admin/users \
  -H "Authorization: Bearer <regular_user_token>"

# Test user list endpoint
curl -X GET https://target.com/api/users \
  -H "Authorization: Bearer <regular_user_token>"

# Test delete endpoint
curl -X DELETE https://target.com/api/admin/users/999 \
  -H "Authorization: Bearer <regular_user_token>"

# Test without auth at all
curl -X GET https://target.com/api/admin/config

# Extract endpoints from JS bundle
curl -s https://target.com/static/app.js | grep -oP '"/api/[^"]+' | sort -u
```

## Burp Suite Tips
- Use **Burp Comparer** to diff responses between admin and regular user on the same endpoint.
- The **Authorize** extension (BApp Store) automatically retests every captured request with a second session's token — essential for this test.
- Use **Target > Site map** to browse all discovered endpoints and mark which ones need authorization testing.
- **Intruder** with an endpoint wordlist to brute-force undocumented API paths.

## Tools
- Burp Suite Authorize extension — automates cross-role testing
- ffuf / gobuster for API endpoint discovery
- Kiterunner — https://github.com/assetnote/kiterunner (API-aware path brute-forcing)
- js-beautify + grep for JS bundle endpoint extraction

## Remediation
- Enforce authorization checks at the API layer, not just in the UI — defense in depth.
- Use a centralized policy enforcement middleware (e.g., OPA, Casbin) rather than per-controller checks.
- Apply the principle of least privilege: default to deny, explicitly allow.
- Audit every API endpoint against a role matrix to confirm authorization coverage.
- Remove or disable legacy API versions that lack modern access controls.

## References
https://owasp.org/www-project-top-ten/2021/A01_2021-Broken_Access_Control
https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/
https://portswigger.net/web-security/access-control
https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
