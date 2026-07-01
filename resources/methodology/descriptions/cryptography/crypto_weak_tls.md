# Weak TLS/SSL Versions (SSLv3, TLS 1.0/1.1)

## Overview
Secure Sockets Layer (SSL) and Transport Layer Security (TLS) are cryptographic protocols designed to provide secure communication over a network. Older protocol versions — SSLv2, SSLv3, TLS 1.0, and TLS 1.1 — contain well-documented cryptographic weaknesses and design flaws that make them susceptible to protocol-level attacks. Servers that still accept these legacy versions expose users and session data to interception and decryption by network attackers.

## How It Works
Older TLS/SSL versions suffer from multiple attack vectors:

- **SSLv3 - POODLE (CVE-2014-3566):** SSLv3's CBC mode padding is not authenticated. An attacker performing a man-in-the-middle (MITM) attack can force a TLS downgrade to SSLv3, then exploit the unauthenticated padding to decrypt one byte of the plaintext per 256 requests. This effectively breaks confidentiality of session cookies.
- **TLS 1.0 - BEAST (CVE-2011-3389):** TLS 1.0 uses predictable IV chaining in CBC mode. An attacker with a MITM position can inject chosen plaintext before the target secret and use a blockwise-adaptive chosen-boundary attack to decrypt the secret (e.g., session cookie).
- **TLS 1.0/1.1 - CRIME / BREACH:** If TLS-level compression is enabled alongside older versions, attackers can exploit compression oracles to recover secrets from compressed request bodies.
- **General downgrade attacks:** Even if a server supports TLS 1.3, an attacker can tamper with the ClientHello to force negotiation of a weaker protocol version unless the server enforces a minimum version and implements downgrade protection (TLS_FALLBACK_SCSV).

Modern browsers have dropped support for TLS 1.0 and 1.1, but legacy server configurations and non-browser clients (APIs, IoT, embedded systems) may still negotiate these versions.

## Impact
- Decryption of HTTPS traffic (session cookies, credentials, sensitive data) by network attackers.
- Session hijacking via decrypted session tokens.
- Man-in-the-middle attacks made feasible due to weakened cipher requirements.
- Compliance failures: PCI DSS, HIPAA, NIST SP 800-52r2 all prohibit TLS versions below 1.2.
- Regulatory fines and audit failures for organisations handling payment card or health data.

## Where to Look
- Any externally facing HTTPS endpoint (web app, API gateway, mail server, VPN endpoint).
- Load balancers and reverse proxies (nginx, Apache httpd, HAProxy, AWS ALB, Cloudflare).
- Legacy admin panels, internal tools, or staging environments that may not receive the same hardening as production.
- Non-HTTP services that use TLS: SMTP, IMAP, LDAPS, RDP, FTP over TLS.
- ServerHello packets in Wireshark captures when doing MITM on a test network.
- The `Server` response header may hint at old software versions that default to weak TLS.

## Testing Steps
1. Identify all TLS-enabled hostnames and IP addresses in scope. Include subdomains discovered during recon.
2. Run `testssl.sh` against each target to enumerate supported protocol versions, cipher suites, and known vulnerabilities.
3. Run `sslscan` as a second opinion to confirm findings.
4. Attempt manual connections using `openssl s_client` with explicit protocol flags to verify server accepts the deprecated versions.
5. Check whether the server sends the `TLS_FALLBACK_SCSV` extension during downgrade attempts (testssl.sh reports this).
6. Verify the server's certificate chain while you have the connection open.
7. If SSLv3 is supported, confirm POODLE exploitability with testssl.sh's `-P` flag.
8. Check HSTS headers in the HTTP response — absence of HSTS facilitates downgrade attacks at the network level.
9. Document the exact protocol version and cipher suite negotiated in each test case.
10. Cross-reference findings against PCI DSS requirements if the target handles payment data.

## Payloads / Techniques

```bash
# Full testssl.sh scan — tests all protocol versions, ciphers, and known CVEs
testssl.sh --full https://target.example.com

# Test only protocol support
testssl.sh --protocols https://target.example.com

# Test specifically for POODLE (SSLv3)
testssl.sh -P https://target.example.com

# Test for BEAST (TLS 1.0 CBC)
testssl.sh -B https://target.example.com

# sslscan — alternate protocol/cipher enumeration
sslscan --no-failed target.example.com:443

# Manual check: attempt SSLv3 connection
openssl s_client -connect target.example.com:443 -ssl3

# Manual check: attempt TLS 1.0 connection
openssl s_client -connect target.example.com:443 -tls1

# Manual check: attempt TLS 1.1 connection
openssl s_client -connect target.example.com:443 -tls1_1

# Manual check: attempt TLS 1.2 connection (should succeed on modern servers)
openssl s_client -connect target.example.com:443 -tls1_2

# nmap NSE script for SSL/TLS enumeration
nmap --script ssl-enum-ciphers -p 443 target.example.com

# Check if FALLBACK_SCSV is supported (downgrade protection)
openssl s_client -connect target.example.com:443 -tls1 -fallback_scsv

# sslyze — Python-based TLS scanner
sslyze --regular target.example.com:443

# Check HSTS header in HTTP response
curl -sI https://target.example.com | grep -i strict-transport
```

```python
# sslyze programmatic scan for TLS version support
from sslyze import Scanner, ServerNetworkLocation, ServerScanRequest
from sslyze.plugins.scan_commands import ScanCommand

location = ServerNetworkLocation("target.example.com", 443)
request = ServerScanRequest(
    server_location=location,
    scan_commands={ScanCommand.SSL_2_0_CIPHER_SUITES,
                   ScanCommand.SSL_3_0_CIPHER_SUITES,
                   ScanCommand.TLS_1_0_CIPHER_SUITES,
                   ScanCommand.TLS_1_1_CIPHER_SUITES,
                   ScanCommand.TLS_1_2_CIPHER_SUITES,
                   ScanCommand.TLS_1_3_CIPHER_SUITES}
)
scanner = Scanner()
scanner.queue_scans([request])
for result in scanner.get_results():
    for scan_command, scan_result in result.scan_results.items():
        print(f"{scan_command}: {[c.name for c in scan_result.accepted_cipher_suites]}")
```

## Burp Suite Tips
- Burp Suite Pro includes a TLS negotiation scanner under **Scanner > Active Scan**. Run it against your target and look for "TLS/SSL protocol version" issues in the findings.
- In Burp's **Proxy > Options > TLS Pass Through**, add the target domain if Burp is dropping the connection — some targets need TLS pass-through for initial recon.
- Use Burp's **Repeater** with a captured HTTPS request. In **Project Options > SSL**, set the client TLS version to TLS 1.0 and resend — if it succeeds, the server accepts TLS 1.0.
- The **Collaborator** feature can be used indirectly: if the app makes SSRF-reachable connections, you can test whether Collaborator's endpoint negotiates weak TLS.
- Install the **TLS-Scanner** Burp extension (available in BApp Store) for automated TLS version and cipher checks integrated directly into the Burp UI.
- Check the **Target > Site Map** SSL certificate icon — Burp shows the negotiated protocol version in the request detail pane.

## Tools
- testssl.sh — https://testssl.sh (comprehensive TLS scanner)
- sslscan — https://github.com/rbsec/sslscan
- sslyze — https://github.com/nabla-c0d3/sslyze
- nmap with ssl-enum-ciphers NSE script
- openssl (s_client for manual protocol testing)
- Qualys SSL Labs — https://www.ssllabs.com/ssltest/ (online scanner, good for external targets)
- ImmuniWeb SSL Security Test — https://www.immuniweb.com/ssl/
- Burp Suite Pro (TLS-Scanner BApp)
- Wireshark (protocol-level analysis)
- OWASP O-Saft (SSL/TLS audit tool)

## Remediation
- Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1 at the server level. Support only TLS 1.2 and TLS 1.3.
- For nginx: `ssl_protocols TLSv1.2 TLSv1.3;`
- For Apache: `SSLProtocol -all +TLSv1.2 +TLSv1.3`
- For IIS: Use the registry keys under `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols` or the IIS Crypto tool.
- Enable TLS_FALLBACK_SCSV to prevent protocol downgrade attacks.
- Configure HSTS with a long `max-age` (minimum 1 year) to enforce HTTPS at the browser level: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`
- Disable TLS compression to prevent CRIME attacks.
- Rotate to ECDHE key exchange to achieve Perfect Forward Secrecy (PFS).
- Test configuration after every change with testssl.sh or SSL Labs.

## References
https://owasp.org/www-project-transport-layer-protection-cheat-sheet/
https://portswigger.net/web-security/transport-layer-security
https://nvd.nist.gov/vuln/detail/CVE-2014-3566
https://nvd.nist.gov/vuln/detail/CVE-2011-3389
https://www.pcisecuritystandards.org/documents/Migrating-from-SSL-Early-TLS-Info-Supp-v1_1.pdf
https://testssl.sh
https://www.ssllabs.com/projects/best-practices/
https://cheatsheetseries.owasp.org/cheatsheets/TLS_Cipher_String_Cheat_Sheet.html
