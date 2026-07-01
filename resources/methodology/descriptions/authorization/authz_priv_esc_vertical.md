# Privilege Escalation (Vertical)

## Overview
Vertical privilege escalation occurs when a lower-privileged user gains the abilities of a higher-privileged user — typically a regular user elevating to administrator. This is distinct from horizontal escalation (accessing another user's data at the same privilege level). Vertical escalation exploits missing or bypassable authorization checks, parameter manipulation, mass assignment vulnerabilities, or logic flaws that allow a user to assign themselves elevated roles or access administrative functions.

## How It Works
- **Direct admin function access**: Regular user directly calls admin API endpoints (function-level access control failure).
- **Role parameter manipulation**: The user's role is included in the request body or JWT payload and not validated server-side — changing `"role":"user"` to `"role":"admin"` in the request elevates the account.
- **Mass assignment**: Updating user profile and including undocumented `role` or `is_admin` fields that the server accepts and writes to the database.
- **Privilege escalation via reference**: Creating an object with a reference to an admin-only resource, or assigning oneself to an admin-level group/team.
- **JWT claim manipulation**: Modifying role/scope claims in a JWT token (see JWT vulnerabilities).
- **Race condition**: Simultaneously upgrading an account and exploiting a window where the new privileges are checked against stale cached data.

## Impact
- Full administrative access to the application.
- Access to all users' data, system configuration, and audit logs.
- Ability to create new administrator accounts for persistence.
- System-level access if administrative functions include server management features.
- Regulatory and compliance implications (unauthorized access to controlled data).

## Where to Look
- User registration and profile update endpoints — any field that could be a role indicator.
- Admin panel endpoints directly requested by regular users.
- JWT payload — `role`, `permissions`, `scope`, `is_admin`, `access_level` claims.
- Request body parameters in account update calls.
- Group/team membership management endpoints.
- Invitation/referral flows that may assign elevated roles.
- Parameters named: `role`, `userType`, `accountType`, `permission`, `admin`, `isAdmin`, `is_admin`, `privilege`, `access_level`.

## Testing Steps
1. Register a regular user account and explore all available functions.
2. Attempt to access known admin endpoints directly (see Broken Function-Level Access Control).
3. Intercept account creation/update requests; inject `role=admin`, `is_admin=true`, `userType=administrator` into the body.
4. Inspect the JWT payload — modify role/admin claims and resubmit (requires weak secret or alg:none vulnerability).
5. Check if the invite/referral flow allows specifying a role for the new account.
6. Test all group/team creation or membership endpoints — can you add yourself to an admin group?
7. Look for admin-specific object IDs in responses (e.g., `admin_group_id: 1`) and attempt to join that group.
8. Test account upgrade flows (e.g., free → premium) for parameter injection that might also accept `is_admin=true`.
9. Check the API response body for undocumented fields (like `role`, `permissions`) that may be writable via the same endpoint.

## Payloads / Techniques

Inject role into profile update:
```bash
# Test various role field names
for field in role userType accountType user_type isAdmin is_admin admin privilege; do
  echo "Testing field: $field"
  curl -X PUT https://target.com/api/user/profile \
    -H "Authorization: Bearer $USER_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"Test User\",\"$field\":\"admin\"}" | python3 -m json.tool
done
```

Test registration with role injection:
```bash
curl -X POST https://target.com/api/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "attackeruser",
    "email": "attacker@test.com",
    "password": "TestPass123!",
    "role": "administrator",
    "is_admin": true,
    "userType": "admin",
    "access_level": 99
  }'
```

Admin group membership escalation:
```bash
# Try adding yourself to group ID 1 (likely admin group)
curl -X POST https://target.com/api/groups/1/members \
  -H "Authorization: Bearer $USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"user_id": "SELF_USER_ID"}'

# Or change your own group membership
curl -X PUT https://target.com/api/user/profile \
  -H "Authorization: Bearer $USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"group_id": 1}'
```

JWT role manipulation (if weak secret or alg:none):
```python
import jwt, json, base64

# Decode existing token
token = "EXISTING_JWT_TOKEN"
payload_b64 = token.split('.')[1]
# Add padding
payload = json.loads(base64.urlsafe_b64decode(payload_b64 + '=='))

# Modify role
payload['role'] = 'administrator'
payload['is_admin'] = True
payload['permissions'] = ['admin:read', 'admin:write', 'admin:delete']

# Resign (requires weak secret knowledge)
WEAK_SECRET = "secret"
new_token = jwt.encode(payload, WEAK_SECRET, algorithm='HS256')
print(f"Escalated token: {new_token}")
```

Test invitation flow role parameter:
```bash
curl -X POST https://target.com/api/invitations \
  -H "Authorization: Bearer $USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "newadmin@test.com",
    "role": "administrator",
    "permissions": ["*"]
  }'
```

Escalate via account type upgrade:
```bash
curl -X POST https://target.com/api/upgrade \
  -H "Authorization: Bearer $USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "plan": "premium",
    "role": "administrator",
    "is_admin": true
  }'
```

## Burp Suite Tips
- In **Proxy**, intercept all POST/PUT/PATCH requests; use **Param Miner** extension to discover hidden parameters like `role`, `is_admin` that are not in the request but may be accepted.
- **Autorize** (BApp): configure admin session and user session; browse as admin — Autorize highlights which admin functions a regular user can access.
- In **Repeater**, add role-related parameters to profile update requests one at a time and observe if the response changes (returning a new role value, or if admin features become visible).
- Use the **JSON Beautifier** extension to see all fields in API responses — some APIs return the user's role in the profile response, confirming successful escalation.
- **Intruder** (Sniper): fuzz the value of a `role` parameter with an admin role wordlist: `user`, `admin`, `administrator`, `superuser`, `root`, `staff`, `moderator`, `operator`.
- Check the **Scanner** results for "Input returned in response" findings — if a role parameter you inject appears in the response, it was processed.

## Tools
- **Autorize** (Burp Extension) — Cross-privilege request replay.
- **Param Miner** (Burp Extension) — Discover hidden writable parameters.
- **Burp Intruder** — Role value fuzzing.
- **jwt_tool** — JWT claim manipulation for role escalation.
- **OWASP ZAP** — Access control testing scanner.
- **Arjun** — HTTP parameter discovery.

## Remediation
- Server-side authorization must verify the requesting user's actual stored role — never trust user-supplied role values in the request body.
- Use an allowlist approach: define exactly which fields a user can update and reject any additional fields.
- Implement a strict type and value validation for role fields — the role value should only be settable by an administrator via a dedicated, secured endpoint.
- Separate the user update endpoint from the admin user management endpoint; the user's self-service endpoint must not accept role changes.
- Implement comprehensive authorization testing: create integration tests that verify a regular user cannot grant themselves elevated privileges through any endpoint.
- Apply principle of least privilege: new accounts start with minimal permissions; elevation requires explicit admin approval.
- Log and alert on any attempt to set privileged attributes via user-facing endpoints.

## References
https://portswigger.net/web-security/access-control
https://owasp.org/Top10/A01_2021-Broken_Access_Control/
https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html
https://cwe.mitre.org/data/definitions/269.html
https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/03-Testing_for_Privilege_Escalation
