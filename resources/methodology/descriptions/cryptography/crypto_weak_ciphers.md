# Weak Cipher Suites

## Overview
A cipher suite defines the combination of algorithms used for key exchange, authentication, bulk encryption, and message authentication in a TLS connection. Weak cipher suites use outdated or broken cryptographic algorithms — such as RC4, DES, 3DES, NULL encryption, or EXPORT-grade ciphers — that can be exploited by attackers to decrypt traffic, forge messages, or downgrade connections. Even if a modern TLS version is in use, a single weak cipher suite in the server's accepted list can be leveraged to attack the session.

## How It Works
During TLS negotiation, the client sends a list of cipher suites it supports in the ClientHello. The server selects one from that list. If the server does not enforce a strong preference order and disallow weak suites, an attacker performing MITM can manipulate the ClientHello to present only weak suites, forcing the server to accept one.

Key weaknesses by cipher component:

- **Key Exchange — NULL/ANON:** No authentication of the server, trivially enabling MITM.
- **Key Exchange — EXPORT RSA/DH:** 40-bit or 512-bit key material mandated by old US export laws. Vulnerable to FREAK (CVE-2015-0204) and Logjam (CVE-2015-4000) attacks, where an attacker downgrades the key exchange to EXPORT strength and factors the short key.
- **Key Exchange — Static RSA (no DHE/ECDHE):** Lacks Perfect Forward Secrecy (PFS). If the server's private key is ever compromised, all past captured sessions can be decrypted.
- **Bulk Encryption — RC4:** RC4 has statistical biases in the keystream. Exploitable via the RC4 NOMORE and BEAST-style attacks. RFC 7465 prohibits RC4 in TLS.
- **Bulk Encryption — DES/3DES:** DES is a 56-bit cipher, trivially brute-forced. 3DES (Triple-DES) is vulnerable to SWEET32 (CVE-2016-2183) — birthday attacks against 64-bit block ciphers in long-lived sessions allow plaintext recovery after roughly 785 GB of traffic.
- **Bulk Encryption — NULL:** No encryption at all. Traffic is sent in plaintext.
- **Bulk Encryption — EXPORT ciphers:** 40-bit or 56-bit strength, breakable in seconds on modern hardware.
- **MAC — MD5/SHA1 in HMAC (in older suites):** Not immediately catastrophic but indicates legacy configuration.

## Impact
- Decryption of encrypted TLS traffic by network-positioned attackers.
- Session token theft and account takeover.
- Factoring of short export-grade keys (FREAK, Logjam) in hours to minutes using cloud compute.
- SWEET32 birthday attacks decrypt cookie values after sustained traffic capture.
- Compliance failure: PCI DSS 4.0, NIST SP 800-52r2, and SOC2 prohibit weak ciphers.
- Regulatory penalties and failed security audits.

## Where to Look
- All TLS-enabled services in scope: HTTPS, SMTP/TLS, LDAPS, IMAPS, FTPS, RDP.
- Server configuration files: `nginx.conf` (`ssl_ciphers`), Apache `httpd.conf` (`SSLCipherSuite`), IIS crypto settings.
- Load balancers, CDNs, and API gateways — these terminate TLS and may have different configs from origin servers.
- Intermediate/staging environments that mirror production but lag in hardening.
- Cipher suites listed in TLS ServerHello captured in Wireshark.
- Cloud provider TLS policy settings (AWS ALB security policies, Cloudflare minimum TLS version).

## Testing Steps
1. Enumerate all TLS endpoints in scope (web server, API, admin panel, mail server).
2. Run `testssl.sh` with `--cipher-per-proto` to list every accepted cipher suite per protocol version.
3. Run `sslscan` as confirmation; it highlights weak ciphers in color.
4. Use `nmap --script ssl-enum-ciphers` to get cipher grades per protocol.
5. Manually test for NULL ciphers and ANON key exchange using `openssl s_client`.
6. Test for EXPORT ciphers (FREAK): use `openssl s_client -cipher EXPORT` and observe whether the connection succeeds.
7. Test for Logjam: check if DH key size is 1024-bit or smaller (testssl.sh flags this).
8. Test for SWEET32: verify 3DES is disabled or has a cipher suite grade of "C" or lower in scan output.
9. Test for RC4: `openssl s_client -cipher RC4 -connect target:443`.
10. Check server cipher preference order — the server should enforce preference, not the client.
11. Verify PFS: all accepted cipher suites should use ECDHE or DHE key exchange.

## Payloads / Techniques

```bash
# testssl.sh — enumerate all ciphers and grade them
testssl.sh --cipher-per-proto https://target.example.com

# testssl.sh — check for FREAK (EXPORT RSA)
testssl.sh -E https://target.example.com

# testssl.sh — check for Logjam (weak DH)
testssl.sh -J https://target.example.com

# testssl.sh — check for SWEET32 (3DES)
testssl.sh -W https://target.example.com

# sslscan — full cipher enumeration with color-coded grading
sslscan --no-failed target.example.com:443

# nmap cipher enumeration with grade
nmap --script ssl-enum-ciphers -p 443 target.example.com

# Manual: test if server accepts NULL cipher (no encryption)
openssl s_client -cipher NULL -connect target.example.com:443

# Manual: test if server accepts anonymous DH (no authentication)
openssl s_client -cipher aNULL -connect target.example.com:443

# Manual: test EXPORT cipher acceptance (FREAK)
openssl s_client -cipher EXPORT -connect target.example.com:443

# Manual: test RC4 acceptance
openssl s_client -cipher RC4 -connect target.example.com:443

# Manual: test 3DES (SWEET32)
openssl s_client -cipher 3DES -connect target.example.com:443

# Check DH key size (Logjam)
openssl s_client -connect target.example.com:443 -cipher DHE 2>/dev/null | grep "Server Temp Key"

# sslyze — scan for weak cipher suites
sslyze --regular --certinfo target.example.com:443

# Check cipher order preference (server vs client preference)
# If server uses client preference and client offers weak cipher first, server accepts it
testssl.sh --server-preference https://target.example.com
```

```bash
# One-liner to check for all major weak cipher categories
for cipher in NULL aNULL EXPORT RC4 DES 3DES MD5; do
  result=$(openssl s_client -cipher $cipher -connect target.example.com:443 2>&1 | grep -E "Cipher|handshake failure")
  echo "$cipher: $result"
done
```

## Burp Suite Tips
- In Burp Suite Pro, run an **Active Scan** against the target. Look for "SSL cipher suite" issues in the scan results pane.
- Use **Project Options > TLS** to configure Burp's TLS settings. Set Burp to use a specific cipher and observe if the server accepts it.
- Install the **SSL Scanner** BApp from the BApp Store — it scans for weak ciphers, protocol versions, and common SSL/TLS CVEs from within Burp.
- In **Repeater**, change the TLS protocol version and cipher in project options, then resend a captured request to validate server acceptance.
- Use **Burp Collaborator** combined with a server-side request: if the app makes outbound TLS connections (SSRF, webhook, etc.), test whether those connections accept weak ciphers.
- Check the **Target > Site Map** pane — selecting a host and looking at its SSL certificate details shows the negotiated cipher for that connection.

## Tools
- testssl.sh — https://testssl.sh
- sslscan — https://github.com/rbsec/sslscan
- sslyze — https://github.com/nabla-c0d3/sslyze
- nmap (ssl-enum-ciphers NSE script)
- openssl s_client (manual cipher testing)
- Qualys SSL Labs — https://www.ssllabs.com/ssltest/
- CryptoLyzer — https://github.com/c0r3dump3d/cryptolyzer
- Burp Suite Pro (SSL Scanner BApp)
- Wireshark (ServerHello inspection)
- IIS Crypto (Windows server cipher management GUI) — https://www.nartac.com/Products/IISCrypto

## Remediation
- Allow only strong cipher suites. Recommended order (nginx example):
  `ssl_ciphers 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256';`
- Explicitly disable RC4, DES, 3DES, NULL, EXPORT, and ANON cipher suites.
- Enforce server-side cipher preference order: nginx `ssl_prefer_server_ciphers on;`, Apache `SSLHonorCipherOrder on`.
- Use only cipher suites with ECDHE or DHE key exchange to achieve Perfect Forward Secrecy.
- Use DH parameters of at least 2048 bits: `openssl dhparam -out /etc/ssl/dhparam.pem 4096`.
- Prefer AES-GCM (AEAD) over CBC mode to eliminate padding oracle risk.
- Reference the Mozilla SSL Configuration Generator for up-to-date recommended settings: https://ssl-config.mozilla.org/
- After changes, retest with testssl.sh and SSL Labs to confirm all weak suites are disabled.

## References
https://owasp.org/www-community/vulnerabilities/Insecure_Transport_Layer_Protection
https://portswigger.net/web-security/transport-layer-security
https://cheatsheetseries.owasp.org/cheatsheets/TLS_Cipher_String_Cheat_Sheet.html
https://nvd.nist.gov/vuln/detail/CVE-2015-0204
https://nvd.nist.gov/vuln/detail/CVE-2015-4000
https://nvd.nist.gov/vuln/detail/CVE-2016-2183
https://sweet32.info/
https://freak.attack.cc/
https://weakdh.org/
https://ssl-config.mozilla.org/
https://www.rfc-editor.org/rfc/rfc7465
