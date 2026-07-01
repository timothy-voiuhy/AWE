# Mass Assignment (Auto-binding Attack)

## Overview
Mass assignment occurs when an API automatically binds client-supplied input to internal object properties without a whitelist. An attacker can supply extra parameters — like `role`, `admin`, `verified`, `balance`, `is_active` — that the API silently applies to the object. This can escalate privileges, bypass verification requirements, or manipulate account state.

## How It Works
- The API accepts a JSON body and passes it directly to an ORM model (`User.update(request.body)`).
- The developer only intended the client to update `name` and `email`, but the endpoint binds all provided fields.
- An attacker adds `"role": "admin"` or `"is_verified": true` or `"balance": 10000` to the JSON.
- The ORM applies these to the database record without validation.
- Common in Ruby on Rails (before `permit()`), Laravel, Django REST Framework, Node.js (Mongoose without schema validation).

## Impact
- Privilege escalation: adding `"admin": true` gives admin access.
- Account verification bypass: adding `"email_verified": true` skips email confirmation.
- Balance manipulation: adding `"wallet_balance": 99999`.
- Role escalation in multi-tenant apps.
- Bypassing account restrictions or flags (`"is_banned": false`).

## Where to Look
- User profile update endpoints (`PUT /api/user/profile`).
- Registration endpoints.
- Account settings update.
- Any endpoint that accepts partial or full object updates.
- Endpoints with `PATCH` requests (partial updates).
- Admin endpoints that may expose extra fields to regular users.

## Testing Steps
1. Identify update endpoints: profile update, settings update, registration.
2. Note what fields the UI sends normally (e.g., `name`, `email`, `bio`).
3. Add extra fields to the request body: `"admin": true`, `"role": "admin"`, `"is_verified": true`, `"balance": 99999`, `"permission_level": 5`.
4. Submit and check the response — does it echo back the extra field?
5. Fetch your profile again — did the extra field persist?
6. Try common sensitive field names: `admin`, `is_admin`, `role`, `group`, `verified`, `active`, `banned`, `credits`, `plan`, `subscription`.
7. Inspect error messages — they may reveal available model fields.
8. Read JavaScript source or API docs for object schema hints.

## Payloads / Techniques
```bash
# Normal profile update
curl -s -X PUT https://api.target.com/user/profile \
  -H "Authorization: Bearer USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "John", "email": "john@example.com"}'

# Mass assignment attack — add extra fields
curl -s -X PUT https://api.target.com/user/profile \
  -H "Authorization: Bearer USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "John",
    "email": "john@example.com",
    "role": "admin",
    "admin": true,
    "is_verified": true,
    "wallet_balance": 99999,
    "plan": "enterprise",
    "email_confirmed": true,
    "is_banned": false,
    "permission_level": 9
  }'

# Verify if any field was applied
curl -s https://api.target.com/user/profile \
  -H "Authorization: Bearer USER_TOKEN" | python3 -m json.tool

# Check for new privileges
curl -s https://api.target.com/admin/users \
  -H "Authorization: Bearer USER_TOKEN"
```

## Burp Suite Tips
- In **Repeater**, add extra JSON fields to any PUT/PATCH/POST request body.
- Use **Param Miner** (BApp Store) to discover hidden parameters — it tests common parameter names.
- Compare the request body with the response body: if the API echoes back added fields, they may be stored.
- Check **API documentation** links in Burp's target site map for field names.

## Tools
- Burp Suite Repeater + Param Miner
- Arjun — https://github.com/s0md3v/Arjun (parameter discovery, including JSON body params)

## Remediation
- Use explicit allowlists for which fields can be mass-assigned (`attr_accessible` in Rails, `permit()` in strong parameters, serializer `fields` in DRF).
- Never pass `request.body` or the equivalent directly to an ORM model.
- Use separate input DTOs (Data Transfer Objects) that only contain fields users are allowed to set.
- Apply field-level authorization — the set of writable fields differs by user role.
- Log all write operations and flag requests that include unexpected fields.

## References
https://owasp.org/www-project-api-security/ (API6:2023 Unrestricted Access to Sensitive Business Flows)
https://portswigger.net/web-security/api-testing
https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html
https://cwe.mitre.org/data/definitions/915.html
