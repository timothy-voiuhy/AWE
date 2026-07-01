# API Versioning Bypass

## Overview
When an API is versioned (e.g., `/v1/`, `/v2/`), security improvements — such as access controls, input validation, or rate limiting — are often applied only to the latest version. Older API versions may still be accessible and lack the security fixes, allowing attackers to bypass protections by simply downgrading their requests to a legacy version.

## How It Works
- Developer fixes an authorization bug in `/v2/users/{id}` but forgets to remove or fix `/v1/users/{id}`.
- Rate limiting was added in v3 but v1 and v2 endpoints still respond without it.
- Admin functionality hidden from the v2 UI exists in v1 with no UI but remains accessible via direct HTTP calls.
- Mobile apps often pin to older API versions, keeping legacy endpoints alive for longer.

## Impact
- Bypass authentication, authorization, or input validation enforced only in newer versions.
- Access administrative functions removed from the UI but not the backend.
- Exploit known vulnerabilities (SQLi, IDOR, etc.) patched in v2 but present in v1.
- Circumvent rate limiting, CAPTCHA, or other abuse controls.

## Where to Look
- URL path versioning: `/api/v1/`, `/api/v2/`, `/api/v3/`.
- Header versioning: `API-Version: 1`, `Accept: application/vnd.api+json;version=1`.
- Subdomain versioning: `v1.api.example.com`.
- Query param versioning: `?version=1`, `?v=1`, `?api-version=2020-01-01`.
- Mobile app API calls — decompile APK/IPA for hardcoded older API version strings.
- JavaScript bundles referencing old version constants.

## Testing Steps
1. Identify the current API version from the base URL or request headers.
2. Manually decrement the version number: if using `/v2/`, try `/v1/` and `/v0/`.
3. Try common version aliases: `/api/old/`, `/api/legacy/`, `/api/beta/`, `/api/dev/`.
4. For admin endpoints that return 403 in v2, try the same path under v1.
5. Compare responses between versions — identical 200 responses in an older version indicate missing controls.
6. Try header-based versioning: send `API-Version: 1` or `X-API-Version: 2019-01-01`.
7. If GraphQL: try field aliases or deprecated fields removed from the latest schema.
8. Check if documented deprecated endpoints still respond.

## Payloads / Techniques
```bash
# Test previous versions
curl -s https://target.com/api/v1/admin/users -H "Authorization: Bearer <user_token>"
curl -s https://target.com/api/v2/admin/users -H "Authorization: Bearer <user_token>"
# if v2 returns 403 but v1 returns 200 → bypass confirmed

# Header-based versioning
curl -s https://target.com/api/users/456 \
  -H "Authorization: Bearer <user_token>" \
  -H "API-Version: 2020-01-01"

# Try date-based Azure/AWS style versioning
curl "https://target.com/api/users/456?api-version=2019-01-01"

# Try other naming conventions
/api/old/admin/users
/api/beta/admin/users
/api/internal/admin/users
/api/legacy/admin/users
```

## Burp Suite Tips
- Use **Intruder** to fuzz the version number in the path: replace `v2` with a payload list of `v0`, `v1`, `v3`, `beta`, `legacy`, `old`, `internal`.
- **Match and Replace** rule: automatically change `v2` to `v1` in all requests to quickly compare behavior.
- In **Repeater**, duplicate a tab and change only the version to compare responses side-by-side.

## Tools
- Burp Suite Intruder — version number enumeration
- ffuf — fuzz version segments in API paths
- Kiterunner — API-aware path brute-forcing with version-aware wordlists

## Remediation
- Maintain consistent security controls across all active API versions.
- Sunset and remove old API versions rather than keeping them live indefinitely.
- Apply centralized middleware/gateway-level authorization that applies regardless of version.
- Maintain an inventory of all live API versions and audit each one for security parity.
- Log usage of deprecated API versions and alert on unexpected access.

## References
https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/
https://portswigger.net/web-security/api-testing
https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/12-API_Testing
