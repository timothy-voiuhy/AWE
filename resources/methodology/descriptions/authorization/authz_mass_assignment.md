# Mass Assignment

## Overview
Mass assignment (also called auto-binding or over-posting) occurs when a web framework automatically binds HTTP request parameters to object/model properties, and the application fails to restrict which properties are allowed to be set. An attacker can inject unexpected fields — such as `isAdmin`, `role`, or `accountBalance` — in a request body that get persisted to the database.

## How It Works
- Frameworks like Rails, Spring, Laravel, ASP.NET MVC, Django, and Express can bind request bodies to model objects automatically.
- If no whitelist (strong parameters / allow-list) is enforced, any JSON/form field that matches a model attribute is accepted and saved.
- Attacker inspects client-side code, API docs, or response bodies to discover hidden attributes, then adds them to a write request.

## Impact
- Privilege escalation by setting `role=admin` or `isAdmin=true`.
- Unlocking locked/disabled accounts via `active=true`, `verified=true`.
- Bypassing subscription gates: `subscriptionPlan=premium`.
- Financial manipulation: `balance=999999`, `discount=100`.
- Account takeover by overwriting `email` or `passwordResetToken`.

## Where to Look
- User registration (`POST /register`) — try injecting `role`, `isAdmin`, `emailVerified`.
- Profile update (`PUT /profile`) — try injecting `subscription`, `credits`, `plan`.
- Order creation — try injecting `price`, `discount`, `status=paid`.
- Any JSON endpoint that persists data — inspect the response object for fields not in your request.
- API endpoints where request body schema differs from the response schema (extra fields in response = candidate).

## Testing Steps
1. Browse the application normally and capture all write requests in Burp.
2. For each request body, note the existing fields.
3. Inspect response bodies and any JS source/API docs for additional model properties.
4. Add candidate privileged fields to the request body and observe server response.
5. Create two accounts: test `isAdmin=true` on registration, then log in and check if admin access is granted.
6. On a profile update, try `{"email": "new@email.com", "role": "admin", "verified": true}`.
7. On an order API, try adding `price=0.01` or `discount=100` to the request body.
8. Check if the unexpected field appears in the response (confirming it was accepted).

## Payloads / Techniques
```json
// Registration — privilege escalation
POST /api/register
{
  "username": "attacker",
  "password": "Password1!",
  "email": "attacker@evil.com",
  "role": "admin",
  "isAdmin": true,
  "emailVerified": true,
  "active": true
}

// Profile update — account privilege boost
PUT /api/users/me
{
  "name": "Attacker",
  "subscriptionPlan": "enterprise",
  "credits": 9999,
  "banned": false
}

// Order — price manipulation
POST /api/orders
{
  "productId": 42,
  "quantity": 1,
  "price": 0.01,
  "status": "paid",
  "discount": 100
}
```

```bash
# Quick test with curl
curl -X POST https://target.com/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"Test1234","role":"admin","isAdmin":true}'
```

## Burp Suite Tips
- Use **Burp Repeater** to manually add fields to request bodies and compare responses.
- **Param Miner** extension can help discover undiscovered parameters in APIs.
- Enable **"Show response for new parameters"** in Repeater to spot accepted but hidden fields.
- Look for fields in GET responses that don't appear in POST/PUT request templates.

## Tools
- Burp Suite Param Miner (BApp Store) — discovers hidden parameters
- Arjun — https://github.com/s0md3v/Arjun (discovers HTTP parameters)
- ffuf with parameter wordlists

## Remediation
- Implement explicit allow-listing of accepted fields (Rails: `permit`, Laravel: `fillable`, Spring: `@ModelAttribute` with binding restrictions).
- Never auto-bind request parameters to privileged model attributes.
- Use separate DTOs (Data Transfer Objects) for input vs. database models.
- Apply role-based checks before persisting any privilege-related fields.
- Log and alert when unexpected request fields are received.

## References
https://owasp.org/www-project-top-ten/2021/A08_2021-Software_and_Data_Integrity_Failures
https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html
https://portswigger.net/web-security/api-testing
https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/20-Testing_for_Mass_Assignment
