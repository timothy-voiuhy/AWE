# Broken Function Level Authorization

## Overview
Broken Function Level Authorization (BFLA) is OWASP API Security #5. It occurs when an API allows lower-privileged users to access or invoke functions or endpoints intended only for higher-privileged users (admins, managers). Unlike BOLA which is object-level, BFLA is about entire operations — a regular user calling an admin API method to list all users, delete accounts, or modify system settings.

## How It Works
- Admin endpoints exist at predictable paths (`/api/admin/`, `/api/v1/admin/users`).
- Access control is only enforced on the frontend (hidden buttons) but not in the backend API.
- A regular user can directly call the admin endpoint via Burp or curl.
- Horizontal privilege escalation: a user at one role level accesses functions for another role (e.g., user can call manager-level endpoints).
- Some endpoints check authentication (is the user logged in?) but not authorization (is the user an admin?).

## Impact
- Full administrative control over the application.
- Accessing all user data (admin user list).
- Deleting other users' accounts.
- Modifying system configuration.
- Approving or rejecting pending items (business process bypass).
- Accessing financial records, audit logs, and compliance data.

## Where to Look
- `/api/admin/`, `/admin-api/`, `/internal/`, `/management/`
- Admin-specific verbs: list all users, change another user's role, approve content.
- Endpoints used by admin panels — inspect the admin UI's network traffic.
- HTTP methods: a `PUT /api/user/{id}/role` that should be admin-only.
- Version-based bypass: admin endpoint at `/api/v1/admin/` may not be protected if `/api/v2/` is the documented version.

## Testing Steps
1. Log in as a regular user and note your authentication token.
2. Identify admin endpoints from:
   - JavaScript source code (API calls in admin-facing JS bundles)
   - Swagger/OpenAPI documentation
   - Brute-forcing `/api/admin/`, `/api/v1/admin/`, `/internal/`
   - Watching network traffic if you can access an admin panel with another account
3. Call each admin endpoint with your regular user token.
4. Test: list all users, delete a user, change another user's role, approve pending requests.
5. Compare HTTP method accessibility: can a regular user make `DELETE /api/users/5`?
6. Test role escalation: can a user modify their own role via the API?

## Payloads / Techniques
```bash
REGULAR_TOKEN="your_regular_user_token"
ADMIN_ENDPOINTS=(
  "/api/admin/users"
  "/api/admin/users/1"
  "/api/admin/settings"
  "/api/admin/stats"
  "/api/v1/admin/users"
  "/internal/users"
  "/management/users"
  "/api/user/1/role"
)

for endpoint in "${ADMIN_ENDPOINTS[@]}"; do
  echo "=== Testing $endpoint ==="
  curl -s -X GET "https://api.target.com$endpoint" \
    -H "Authorization: Bearer $REGULAR_TOKEN" \
    -w "\nHTTP: %{http_code}\n"
done

# Try to change another user's role
curl -s -X PUT "https://api.target.com/api/users/2/role" \
  -H "Authorization: Bearer $REGULAR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role": "admin"}'

# Try to change your own role via the update profile endpoint
curl -s -X PUT "https://api.target.com/api/user/profile" \
  -H "Authorization: Bearer $REGULAR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "Attacker", "role": "admin"}'

# Try admin actions on non-admin endpoints
curl -s -X DELETE "https://api.target.com/api/users/5" \
  -H "Authorization: Bearer $REGULAR_TOKEN"

# List all users (should be admin only)
curl -s "https://api.target.com/api/users" \
  -H "Authorization: Bearer $REGULAR_TOKEN" | python3 -m json.tool
```

## Burp Suite Tips
- **Autorize** (BApp Store) extension automatically replays requests with a lower-privileged token to detect BFLA.
- In **Repeater**, swap from an admin session cookie to a regular user cookie and retest admin requests.
- Use **Intruder** to enumerate admin endpoint paths.
- Compare responses: 403 vs 200 vs different data length between admin and regular user tokens.
- In **Target → Site Map**, look for `/admin/`, `/internal/` paths.

## Tools
- Burp Suite Autorize (BApp Store) — automated BFLA/BOLA detection
- ffuf — endpoint enumeration
- Burp Suite Intruder — admin path brute force

## Remediation
- Implement role-based access control (RBAC) at the API level — not just the frontend.
- Apply middleware that checks user role before executing any admin endpoint handler.
- Use an authorization framework (OPA, Casbin, AWS IAM policies) for systematic enforcement.
- Never rely on "security through obscurity" (hidden admin URLs) as the only protection.
- Conduct authorization matrix testing: define which roles can access which endpoints, and test all combinations.
- Log all access to sensitive/admin endpoints for audit purposes.

## References
https://owasp.org/www-project-api-security/ (API5:2023 Broken Function Level Authorization)
https://portswigger.net/web-security/access-control
https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
