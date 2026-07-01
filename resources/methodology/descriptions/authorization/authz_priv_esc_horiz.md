# Privilege Escalation (Horizontal)

## Overview
Horizontal privilege escalation occurs when a user can access or modify resources belonging to another user with the same privilege level — without gaining higher permissions. It is fundamentally an access-control failure where user identity is trusted based on attacker-controlled input (IDs, tokens, parameters) rather than server-side session binding.

## How It Works
- Application uses a user-supplied ID (URL param, body field, cookie) to fetch resources without verifying the session matches that ID.
- Attacker is authenticated as User A but modifies the identifier to reference User B's data.
- Unlike vertical escalation, no admin-level access is needed — the attacker stays at the same role tier.
- Often overlaps with IDOR; the distinction is same-privilege vs. elevated-privilege access.

## Impact
- Read another user's private data (messages, orders, profile, medical records).
- Modify another user's data (change email, address, password reset email).
- Delete another user's content or account.
- Mass data exfiltration by iterating over predictable IDs.
- Privacy violations leading to legal and regulatory consequences.

## Where to Look
- Any URL or body parameter that contains a numeric or UUID user/resource identifier.
- `/api/users/{id}/profile`, `/account?uid=`, `/messages/{otherUserId}`.
- Endpoints that accept `userId`, `accountId`, `customerId` in POST bodies.
- Profile photo, document, and file download endpoints.
- Export/report endpoints that scope data by a user ID parameter.
- Password change, email change flows that rely on a submitted user ID.

## Testing Steps
1. Log in as User A — note your user ID from the URL, response, or profile page.
2. Create/register User B in a separate browser/session.
3. As User A, visit an endpoint referencing your own ID (e.g., `/api/profile/123`).
4. Change the ID to User B's (e.g., `/api/profile/456`) — observe if User B's data is returned.
5. Attempt write operations (PUT/PATCH/POST) substituting User B's ID to modify their data.
6. Try delete operations on User B's resources.
7. If IDs are GUIDs, use Burp's Intruder to fuzz sequential numeric IDs if other users have them.
8. Check indirect object references in hidden form fields, cookies, and JWT claims.
9. Test multi-step workflows (checkout, password reset) for ID parameter leakage between steps.

## Payloads / Techniques
```
# Typical vulnerable request (User A's session, changing to User B's ID)
GET /api/users/1002/orders HTTP/1.1
Authorization: Bearer <UserA_token>

# Attempt with User B's ID
GET /api/users/1003/orders HTTP/1.1
Authorization: Bearer <UserA_token>

# POST body substitution
POST /api/profile/update
{"userId": 1003, "email": "attacker@evil.com"}

# GraphQL field substitution
{"query": "{ user(id: 1003) { email phone address } }"}
```

## Burp Suite Tips
- Use **Burp Comparer** to diff User A vs User B responses to confirm data isolation.
- Run **Intruder** with a numeric payload on user ID parameters to enumerate accessible accounts.
- **Match-and-Replace** rules: automatically swap your known user ID for a range of others in all requests.
- The **Authorize** extension (BApp Store) can auto-test every request with another user's token.
- Use **Logger++** to capture all API calls and quickly spot user-ID parameters.

## Tools
- Burp Suite Authorize extension — automated horizontal privilege testing across all requests
- OWASP ZAP Access Control Testing addon
- ffuf / wfuzz — enumerate numeric user IDs at scale
- Custom Python scripts for API-level ID enumeration

## Remediation
- Bind resource access to the authenticated session's user ID on the server side — never trust client-supplied user IDs.
- Use UUID v4 (random) resource identifiers to make enumeration infeasible.
- Implement ownership checks: `if resource.owner_id != session.user_id: raise 403`.
- Centralize access control in a policy layer / middleware, not scattered across controllers.
- Log and alert on access-denied events — repeated 403s on different user IDs indicate enumeration.

## References
https://portswigger.net/web-security/access-control/horizontal-privilege-escalation
https://owasp.org/www-project-top-ten/2021/A01_2021-Broken_Access_Control
https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References
