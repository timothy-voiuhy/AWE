# Swagger / OpenAPI Spec Exposure

## Overview
Swagger (OpenAPI) specification files describe an API's endpoints, parameters, request/response schemas, and authentication mechanisms. When these files are publicly accessible in production environments, they hand attackers a complete map of the API — including hidden endpoints, internal parameters, debug operations, and data schemas — dramatically accelerating reconnaissance and attack planning.

## How It Works
- Development tools like Swagger UI, Redoc, and Spring Fox auto-generate and serve API documentation at common paths.
- If not disabled in production, these paths serve the full OpenAPI spec as JSON or YAML.
- The spec reveals endpoint paths, HTTP methods, parameter names and types, authentication requirements (or lack thereof), and sometimes example requests with real data.
- Internal/admin endpoints marked as `deprecated` or with `x-internal: true` annotations may still be accessible.

## Impact
- Complete API attack surface mapping without brute-force enumeration.
- Discovery of admin endpoints, debug routes, and undocumented internal APIs.
- Understanding parameter names for targeted injection testing.
- Discovering authentication bypass points (endpoints with `security: []`).
- Revealing internal data model structure for mass assignment and IDOR testing.

## Where to Look
```
/swagger.json
/swagger.yaml
/swagger/v1/swagger.json
/api-docs
/api-docs.json
/api/swagger.json
/api/swagger-ui.html
/swagger-ui.html
/swagger-ui/index.html
/v1/swagger.json
/v2/api-docs
/v3/api-docs
/openapi.json
/openapi.yaml
/spec/swagger.json
/docs/
/redoc
/api/spec
/.well-known/openapi.json
```

## Testing Steps
1. Request each common Swagger/OpenAPI path and observe responses.
2. If Swagger UI loads, click through all endpoints including any marked "internal" or "deprecated".
3. Download the raw JSON/YAML spec file for offline analysis.
4. Search the spec for: endpoints with no `security` requirements, admin/internal paths, debug endpoints.
5. Identify parameters of interest: file paths, user IDs, admin flags, format specifiers.
6. Cross-reference spec with your own authenticated session to find unlisted endpoints accessible via API.
7. Look for schema definitions with sensitive fields (password, token, secretKey) — indicates those fields exist in the data model.

## Payloads / Techniques
```bash
# Check common paths
for path in swagger.json swagger.yaml api-docs v2/api-docs v3/api-docs openapi.json; do
  echo "Testing: /$path"
  curl -s -o /dev/null -w "%{http_code}" "https://target.com/$path"
  echo
done

# Download spec
curl -s https://target.com/v2/api-docs -o api_spec.json
curl -s https://target.com/openapi.yaml -o api_spec.yaml

# Parse with Python to list all endpoints
python3 -c "
import json, sys
spec = json.load(open('api_spec.json'))
for path, methods in spec.get('paths', {}).items():
    for method in methods:
        print(f'{method.upper()} {path}')
"

# Look for unauthenticated endpoints (no security)
python3 -c "
import json
spec = json.load(open('api_spec.json'))
for path, methods in spec.get('paths', {}).items():
    for method, detail in methods.items():
        if 'security' not in detail or detail['security'] == []:
            print(f'UNAUTH: {method.upper()} {path}')
"
```

## Burp Suite Tips
- After finding the Swagger spec, import it into **Burp Scanner** via "Import OpenAPI specification" to auto-populate the site map with all API endpoints.
- Use **Target > Site map** to compare endpoints in the spec vs. those you've actually seen in traffic.
- The **OpenAPI Parser** extension (BApp) enables importing specs directly into Burp.

## Tools
- Burp Suite OpenAPI/Swagger import feature
- swagger-cli — for validating and parsing specs
- Postman — import OpenAPI specs for organized testing
- APIKit (Burp BApp) — API discovery and testing from spec

## Remediation
- Disable Swagger UI and API docs in production environments.
- If API docs are needed for partners, protect them behind authentication.
- Remove internal/admin endpoints from the public-facing spec.
- Use API gateway rate limiting and authentication before docs endpoints.
- In Spring Boot: `springfox.documentation.enabled=false` in production profile.
- In Django REST Framework: remove `DEFAULT_SCHEMA_CLASS` from production settings.

## References
https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/
https://portswigger.net/web-security/api-testing
https://swagger.io/specification/
https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html
