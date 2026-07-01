# Excessive Data Exposure (API Over-fetching)

## Overview
Excessive data exposure occurs when an API returns more data than the client needs, relying on the client to filter what's displayed. This is OWASP API Security #3. The server sends entire objects (including sensitive fields) and the client silently discards what it doesn't render — but the sensitive data travels across the network and is visible in browser DevTools or Burp Suite.

## How It Works
- A `/api/user/profile` endpoint returns the full database row including `password_hash`, `api_key`, `phone_number`, `2fa_secret`, `admin_flag`.
- The frontend JavaScript only renders `name` and `email`, so developers don't notice the extras.
- An attacker intercepts the response and reads the hidden fields.
- Common in APIs built by developers who query full objects and let the frontend decide what to show.
- Often found in search results, user listings, and object detail endpoints.

## Impact
- Exposure of password hashes, API keys, and secrets.
- Disclosure of internal system identifiers.
- PII leakage (phone, address, SSN, DOB).
- Admin flags or privilege levels exposed to non-admins.
- Internal implementation details (IDs, foreign keys, system paths).

## Where to Look
- Any API endpoint returning user objects.
- Search and list endpoints (e.g., `/api/users?search=john`).
- Object detail endpoints (`/api/products/123`, `/api/orders/456`).
- Admin data accessible to regular users.
- Mobile app API traffic (inspect via proxy).

## Testing Steps
1. Intercept API responses in Burp and compare what the UI shows vs. what the API returned.
2. Look for extra fields in the JSON response: `password`, `hash`, `secret`, `token`, `key`, `admin`, `role`, `internal`.
3. For list endpoints, check if items include fields not shown in the list view.
4. Test search endpoints: `/api/users?search=admin` — do results include sensitive fields?
5. Test pagination and check if each page response includes excess data.
6. Compare what a regular user's response includes vs. what an admin's response includes.
7. Look at object endpoints for other users: `/api/user/OTHER_ID/profile`.

## Payloads / Techniques
```bash
# Check what the user endpoint returns
curl -s https://api.target.com/user/profile \
  -H "Authorization: Bearer YOUR_TOKEN" | python3 -m json.tool

# Search endpoint — check all fields in results
curl -s "https://api.target.com/users?search=admin" \
  -H "Authorization: Bearer YOUR_TOKEN" | python3 -m json.tool

# Check if other users' data is exposed
curl -s "https://api.target.com/users/2/profile" \
  -H "Authorization: Bearer YOUR_TOKEN" | python3 -m json.tool

# GraphQL: request all fields to see what exists
# (see graphql_introspect description for field enumeration)

# Compare response fields with what's rendered in UI
# Open browser DevTools → Network tab → XHR → find API calls
# Compare JSON keys with what's visible on screen
```

```python
# Script to find "hidden" fields in API responses
import requests
import json

TOKEN = "your_token"
r = requests.get("https://api.target.com/api/profile",
    headers={"Authorization": f"Bearer {TOKEN}"})
data = r.json()

# Fields rendered by UI (grep from page source)
ui_fields = ["name", "email", "avatar"]

# All fields in API response
api_fields = list(data.keys())

# Hidden fields — in API but not in UI
hidden = [f for f in api_fields if f not in ui_fields]
print("Hidden fields:", hidden)
for f in hidden:
    print(f"  {f}: {data[f]}")
```

## Burp Suite Tips
- In **Proxy HTTP History**, look at XHR/API responses and note fields not visible in the UI.
- Use **Burp Search** (`Ctrl+F` in any response) for keywords: `password`, `secret`, `key`, `token`, `hash`.
- Compare responses across different user roles — fields visible to regular users but not shown.

## Tools
- Burp Suite Proxy
- Browser Developer Tools → Network tab
- jq — JSON processor for field analysis: `curl ... | jq 'keys'`

## Remediation
- Implement DTO (Data Transfer Objects) / view models — only serialize fields explicitly whitelisted for the client.
- Never expose internal database models directly via API.
- Apply field-level authorization: users should only receive fields they are permitted to see.
- Use API response filtering libraries (e.g., Marshmallow in Python, Jackson views in Java).
- Conduct API response audits: compare what each endpoint returns vs. what each user role needs.

## References
https://owasp.org/www-project-api-security/ (API3:2023 Excessive Data Exposure)
https://portswigger.net/web-security/api-testing
https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html
