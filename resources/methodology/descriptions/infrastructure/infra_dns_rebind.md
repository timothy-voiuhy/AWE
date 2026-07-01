# DNS Rebinding

## Overview
DNS rebinding bypasses the Same-Origin Policy (SOP) by exploiting the DNS resolution process. An attacker controls a domain that initially resolves to their server (for the initial JavaScript delivery) and then resolves to an internal IP address on subsequent lookups. The victim's browser, already trusting the attacker's domain, uses the JavaScript to make requests that now go to internal services — effectively using the victim's browser as a proxy to access internal network resources.

## How It Works
1. Victim visits `evil.com` — DNS returns `1.2.3.4` (attacker's server), browser loads JavaScript.
2. Attacker's DNS drops the TTL to 0 and re-binds `evil.com` to `192.168.1.1` (internal router/service).
3. When the JavaScript makes a fetch to `https://evil.com/api/data`, the browser resolves `evil.com` again → gets `192.168.1.1`.
4. The browser sends the request to the internal network, thinking it's still talking to the attacker's server.
5. SOP allows the JavaScript to read the response because same origin (`evil.com`) — but now it's an internal service.

## Impact
- Reading data from internal web services (router admin panels, IoT devices, local APIs).
- CSRF against internal services without CSRF protections.
- Port scanning internal networks from the victim's browser.
- Accessing internal admin panels protected only by network location.
- Exfiltrating data from `localhost` services (e.g., local ML APIs, developer tools, Elasticsearch on 9200).

## Where to Look
- Internal services without authentication relying on network position for security.
- Development/staging applications accessible internally.
- IoT devices and smart home hubs on the local network.
- Developer tools running on localhost (Elasticsearch 9200, Redis 6379, Jupyter 8888, React dev server 3000).
- Any internal API without `Host` header validation.

## Testing Steps
1. Determine if the target has internal services accessible only on the local network.
2. Test if internal services validate the `Host` header (if not, they're vulnerable to DNS rebinding).
3. Use Singularity to demonstrate DNS rebinding in a controlled test environment.
4. Check if critical internal services have proper authentication and Host header validation.
5. Test browser-based internal network scanning using `fetch('http://192.168.1.1/')`.

## Payloads / Techniques
```javascript
// Browser-based internal port scanner (simulates DNS rebind capability)
// Run from victim's browser console (with permission)
const ports = [80, 443, 3000, 8080, 8443, 8888, 9200, 9300, 6379, 27017];
const ips = ["192.168.1.1", "10.0.0.1", "172.16.0.1", "127.0.0.1"];

for (const ip of ips) {
  for (const port of ports) {
    const img = new Image();
    img.onerror = () => console.log(`${ip}:${port} - responded`);
    img.onload = () => console.log(`${ip}:${port} - OPEN`);
    img.src = `http://${ip}:${port}/favicon.ico`;
  }
}

// Timing-based port scan (service likely open if response is fast)
async function scanPort(ip, port) {
  const start = Date.now();
  try {
    await fetch(`http://${ip}:${port}/`, {signal: AbortSignal.timeout(1000)});
  } catch(e) {}
  const elapsed = Date.now() - start;
  if (elapsed < 500) console.log(`${ip}:${port} likely OPEN (${elapsed}ms)`);
}
```

```bash
# Set up DNS rebinding test using Singularity
git clone https://github.com/nccgroup/singularity
cd singularity
go build -o singularity cmd/main.go

# Run manager (requires DNS control)
./singularity -dnsl 0.0.0.0 -http 0.0.0.0 -rbi 192.168.1.1 -rbd 8080 -d attacker-domain.com

# Alternatively, use rebinder.net (online tool) for demo purposes

# Test Host header validation on internal service
curl -H "Host: evil.com" http://192.168.1.1/admin
# If responds → service doesn't validate Host → vulnerable to DNS rebinding
```

## Burp Suite Tips
- DNS rebinding testing is primarily done with dedicated tools (Singularity), not Burp.
- Use Burp to proxy requests from a test page loaded in the browser to observe internal service responses.
- **Burp Collaborator** can detect DNS rebinding attempts (logs DNS queries with short TTL responses).

## Tools
- Singularity — https://github.com/nccgroup/singularity (DNS rebinding framework)
- Rebinder — https://lock.cmpxchg8b.com/rebinder.html (online DNS rebinding tool)
- Custom JS for internal network scanning

## Remediation
- Implement DNS rebinding protection: validate `Host` header matches the expected internal hostname, not just any domain.
- Use `Private Network Access` (Chrome's feature that blocks public websites from accessing private network resources).
- Require authentication on all internal services — don't rely on network position as the only protection.
- Set DNS TTL to a reasonable minimum (30-60 seconds) to slow rebinding attacks.
- Browser vendors implement DNS rebinding mitigations — keep browsers updated.
- Bind services to `localhost` (127.0.0.1) only, not all interfaces, when network access is not needed.

## References
https://portswigger.net/web-security/ssrf
https://owasp.org/www-project-web-security-testing-guide/
https://github.com/nccgroup/singularity
https://en.wikipedia.org/wiki/DNS_rebinding
