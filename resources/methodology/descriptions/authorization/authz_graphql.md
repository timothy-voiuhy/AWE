# GraphQL Authorization Issues

## Overview
GraphQL's flexible query model introduces unique authorization challenges. Unlike REST, a single `/graphql` endpoint handles all operations, and field-level authorization is often missing or inconsistently applied. Attackers can query fields, types, and relationships that should be restricted, or perform mutations that bypass business-level access controls.

## How It Works
- Resolvers may lack per-field authorization checks, assuming the top-level query was authorized.
- Batching allows multiple operations in one request, potentially bypassing per-request rate limits.
- Introspection reveals the full schema — types, fields, mutations — helping attackers craft targeted queries.
- Nested queries can access objects via relationships that bypass direct endpoint authorization.
- Alias abuse: calling the same mutation multiple times in one request with different aliases.

## Impact
- Access to other users' data via unprotected resolvers.
- Privilege escalation via unprotected mutation fields.
- Schema enumeration to discover internal types and admin operations.
- Bypassing rate limits via batched mutation abuse.
- Accessing sensitive nested fields (e.g., `user { passwordHash }`) not shown in UI.

## Where to Look
- `/graphql`, `/api/graphql`, `/v1/graphql` — the GraphQL endpoint.
- Any field on User, Order, Admin, Config, or internal types.
- Mutations related to account management, privilege changes, payment operations.
- Subscriptions — real-time data streams that may bypass access controls.
- Nested object queries: `{order {user {email passwordHash balance}}}`.

## Testing Steps
1. Find the GraphQL endpoint (check JS bundles, network tab, common paths).
2. Run introspection to enumerate all types, fields, and mutations.
3. Check if introspection is enabled in production (it often is).
4. For each query/mutation, test as an unauthenticated user, a regular user, and an admin user.
5. Test nested object access: query `{me {orders {user {email}}}}` to see if you can walk to other users' data.
6. Test mutations for missing authorization: `deleteUser`, `updateUserRole`, `createAdmin`.
7. Try querying fields that appear in the schema but shouldn't be exposed: `passwordHash`, `internalNotes`.
8. Test batching: send multiple mutations in a single request to bypass rate limiting.
9. Use aliases to call the same sensitive mutation multiple times.

## Payloads / Techniques
```graphql
# Introspection query (detect schema)
{
  __schema {
    types { name fields { name } }
  }
}

# Access other user's data by ID (IDOR via GraphQL)
{
  user(id: "456") {
    email
    phone
    address
    paymentMethods { cardLast4 }
  }
}

# Access sensitive nested fields
{
  me {
    username
    passwordHash
    twoFactorSecret
    sessions { token ipAddress lastUsed }
  }
}

# Unauthorized mutation
mutation {
  updateUserRole(userId: "456", role: "ADMIN") {
    success
  }
}

# Batch mutation abuse (10 operations in 1 request)
mutation {
  a1: sendOtp(phone: "+1555000001") { status }
  a2: sendOtp(phone: "+1555000001") { status }
  a3: sendOtp(phone: "+1555000001") { status }
  ...
}
```

```bash
# Run introspection with curl
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <user_token>" \
  -d '{"query": "{ __schema { types { name } } }"}'
```

## Burp Suite Tips
- Use **InQL** Burp extension (BApp Store) to automatically run introspection and enumerate the schema visually.
- Send introspection via Repeater and analyze the response for sensitive types.
- Use **GraphQL Raider** extension for batching and mutation testing.
- Intercept GraphQL requests and modify field arguments or add unauthorized fields.

## Tools
- InQL (Burp Extension) — GraphQL introspection and security testing
- GraphQL Voyager — visual schema explorer
- Clairvoyance — https://github.com/nikitastupin/clairvoyance (blind introspection bypass)
- graphql-cop — https://github.com/dolevf/graphql-cop (security audit tool)

## Remediation
- Implement field-level authorization checks in every resolver — never trust that the parent query was authorized.
- Disable introspection in production environments.
- Implement query depth limiting and complexity analysis to prevent resource abuse.
- Disable or strictly rate-limit query batching.
- Use a dedicated GraphQL authorization library (e.g., graphql-shield for Node.js).
- Maintain an explicit allow-list of fields each role can access.

## References
https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
https://portswigger.net/web-security/graphql
https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL
