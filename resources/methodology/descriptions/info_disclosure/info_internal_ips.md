# Internal IP Addresses in Responses

## Overview
Applications frequently disclose internal IP addresses (RFC1918 ranges: 10.x.x.x, 172.16-31.x.x, 192.168.x.x) and hostnames in HTTP responses, headers, error messages, and API payloads. These disclosures reveal the private network topology behind load balancers and reverse proxies, exposing information that aids in SSRF exploitation, internal network scanning, and targeted attacks on infrastructure that is otherwise invisible from the public internet.

## How It Works
Internal IPs leak through multiple channels: backend servers set `X-Forwarded-For` or custom headers that include their internal addresses; application errors expose database server hostnames; API responses include the `hostname` field of backend services; email headers in automated emails contain internal mail relay IPs; XML/JSON payloads from internal microservices include `host` metadata. Proxy configurations like Nginx or Apache may inadvertently pass through headers from upstream backend servers.

## Impact
- Map the internal network topology behind a CDN or load balancer
- Discover hostnames and IPs of database servers, cache servers, and microservices
- Enable more precise SSRF targeting (send requests to specific internal IPs)
- Aid in pivoting after an initial foothold
- Reveal the number and type of backend servers (useful for targeting specific instances)
- Bypass WAF/CDN by discovering the real origin server IP

## Where to Look
- HTTP response headers: `X-Real-IP`, `X-Forwarded-For`, `X-Forwarded-Host`, `X-Backend-Server`, `X-Powered-By`, `Via`, `Server`
- Stack traces and error messages (database connection strings, hostnames)
- API JSON/XML responses containing `host`, `server`, `node`, `instance` fields
- HTML comments in page source
- Redirect `Location` headers (may contain internal hostname)
- Cookie `Domain` attributes
- TLS certificate Subject Alternative Names (SAN) — may include internal hostnames
- Email headers in forgot-password or notification emails
- CORS error messages
- WebSocket upgrade responses

## Testing Steps
1. Inspect all HTTP response headers using Burp Proxy for internal IP patterns.
2. Check `X-Forwarded-For`, `Via`, `Server`, and custom headers in every response.
3. Trigger error conditions (invalid input, missing parameters) and check error message bodies for IP addresses.
4. Inspect JSON API responses for fields named `host`, `server`, `node`, `backend`, `origin`, `ip`.
5. View page source for HTML comments containing IP addresses or hostnames.
6. Check TLS certificate SANs (click the padlock > certificate details or `openssl s_client`).
7. Send yourself a password reset email and check the `Received:` headers chain.
8. Look for redirect Location headers that expose internal hostnames.
9. If GraphQL is present, introspect the schema for potential internal endpoint fields.
10. Try HTTP/0.9 or malformed requests to potentially get more verbose server info.

## Payloads / Techniques

```bash
# Check all response headers for internal IPs
curl -s -I "https://target.com/" | grep -iE "(x-forwarded|x-real|via|x-backend|x-server|x-node|x-host)"

# Trigger error and look for IPs
curl -s "https://target.com/api/nonexistent" | \
  grep -oP '\b(10|172\.(1[6-9]|2[0-9]|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b'

# Extract IPs from full response
curl -s "https://target.com/" | \
  grep -oP '\b((10|172\.(1[6-9]|2[0-9]|3[01])|192\.168)\.\d{1,3}\.\d{1,3})\b'

# Check for internal hostnames in responses
curl -s "https://target.com/api/info" | \
  grep -iE '"(host|hostname|server|node|backend|origin|address)"\s*:\s*"[^"]+"'

# TLS certificate SAN inspection
echo | openssl s_client -connect target.com:443 2>/dev/null | \
  openssl x509 -noout -text | grep -A1 "Subject Alternative"

# Check email headers (from a forgot-password email):
# Received: from internal-mail.corp.internal (10.0.1.5) by mail.target.com

# Test various endpoints for server identification
for path in /api/health /api/status /api/info /api/version /api/ping; do
  echo "=== $path ==="
  curl -s "https://target.com$path" | python3 -m json.tool 2>/dev/null | \
    grep -iE '"(host|ip|address|server|node|instance)"'
done
```

```
# Headers to inspect for internal IPs:
X-Forwarded-For: 10.0.1.42
X-Real-IP: 172.16.4.23
X-Backend-Server: app01.internal:8080
X-Served-By: 10.10.0.55
Via: 1.1 10.0.0.1 (squid)
X-Host: backend-01.prod.internal
X-Originating-IP: 192.168.1.100
X-Remote-Addr: 10.5.2.11
X-Cluster-Client-IP: 172.31.0.8
X-Node: node-3.cluster.internal

# JSON fields that may contain internal IPs:
{
  "server": "10.0.1.42",
  "node": "worker-03",
  "hostname": "api-server-02.internal",
  "backend": "192.168.10.5:8080",
  "debugInfo": {
    "dbHost": "db-primary.internal",
    "dbPort": 5432,
    "cacheHost": "10.0.2.10"
  }
}

# Error message examples exposing internal IPs:
# Django
OperationalError at /api/data
could not connect to server: Connection refused
    Is the server running on host "10.0.1.50" and accepting
    TCP/IP connections on port 5432?

# Java
com.mysql.jdbc.exceptions.jdbc4.CommunicationsException: Communications link failure
Last packet sent to the server was 0 ms ago. Server: 192.168.5.22, Port: 3306
```

```bash
# Automated scan with nuclei
nuclei -u "https://target.com" \
  -t "exposures/configs/" \
  -t "miscellaneous/internal-ip-disclosure.yaml"

# Search Burp history programmatically (export and grep)
# In Burp: Project > Save copy > as XML
grep -oP '\b(10|172\.(1[6-9]|2[0-9]|3[01])|192\.168)\.\d+\.\d+\b' burp_export.xml | sort -u

# Check SPF/DMARC records for internal mail server IPs
dig TXT target.com | grep spf
# May reveal: "ip4:10.0.1.5 ip4:192.168.1.0/24 ..."

# Common internal hostname patterns to look for in responses
grep -iE "(\.internal|\.local|\.corp|\.intranet|\.lan|\.private|\.home)" response.txt
```

## Burp Suite Tips
- Use **Burp > Search** (Ctrl+Shift+F) across all responses with the regex `\b(10|172\.(1[6-9]|2[0-9]|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b` to find all internal IPs in the session history.
- Check **Proxy > HTTP History** and enable the "Response Headers" column — look for custom headers with server names or IPs.
- **Logger++** extension can be configured to flag responses containing RFC1918 ranges automatically.
- After finding an internal IP via header disclosure, try it directly as an SSRF target — cross-reference with SSRF testing.
- Use **Target > Site Map** annotations to mark endpoints that disclosed internal IPs for the final report.

## Tools
- Burp Suite Pro (Search, Logger++ extension)
- nuclei with exposure templates
- curl / grep — quick header inspection
- Shodan — find the real origin IP by scanning for server certificates (bypass CDN)
- crtsh / censys — TLS certificate transparency for internal hostname discovery
- dig / nslookup — DNS and SPF record enumeration

## Remediation
- Configure reverse proxies and load balancers (Nginx, HAProxy, Cloudflare) to strip backend-identifying headers before forwarding responses.
- Remove or sanitize all internal IP addresses and hostnames from API response bodies and error messages.
- Configure the web framework to return generic error messages without connection details.
- Set up a strict header allowlist for what the backend is permitted to return to clients.
- Audit `X-Forwarded-*` header handling — ensure the application does not echo these headers back in responses.
- Review TLS certificate SANs and do not include internal hostnames if the certificate is publicly visible.

## References
https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/01-Information_Gathering/
https://portswigger.net/web-security/information-disclosure
https://cwe.mitre.org/data/definitions/200.html
https://owasp.org/www-community/vulnerabilities/Information_exposure_through_an_error_message
https://www.rfc-editor.org/rfc/rfc1918
