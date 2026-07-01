# Certificate Validation Issues

## Overview
TLS certificates serve two purposes: encrypting traffic and authenticating the server's identity. When an application fails to properly validate certificates — or when certificates themselves have weaknesses — the confidentiality and authenticity guarantees of TLS break down. Vulnerabilities include expired certificates, self-signed certificates, mismatched hostnames, weak signature algorithms, broken certificate chains, and client-side code that explicitly disables certificate validation. These issues are especially common in mobile apps, thick clients, IoT firmware, and internal tooling.

## How It Works
Certificate validation involves several checks that a TLS client must perform:

1. **Chain of trust:** The certificate must chain up to a trusted root CA in the client's trust store. If the chain is broken or self-signed, the client should reject the connection.
2. **Hostname verification:** The certificate's Common Name (CN) or Subject Alternative Name (SAN) must match the hostname being connected to. A wildcard (`*.example.com`) matches one subdomain level.
3. **Validity period:** The certificate must not be expired or used before its `Not Before` date.
4. **Revocation status:** The certificate must not appear on a Certificate Revocation List (CRL) or return a bad status via OCSP.
5. **Signature algorithm:** The certificate must be signed with a strong algorithm. MD5 and SHA-1 signatures are considered broken — MD5 collisions have been demonstrated against CA certificates.
6. **Key usage extensions:** The certificate's `Key Usage` and `Extended Key Usage` fields must be appropriate for its role (e.g., `serverAuth` for TLS servers).

When application code disables certificate validation (common in development and testing code that makes it to production), all of the above checks are bypassed, making MITM trivial.

## Impact
- Full man-in-the-middle attack: attacker intercepts and decrypts all HTTPS traffic.
- Credential theft: usernames and passwords sent over a "secure" connection are captured in plaintext.
- Session hijacking via intercepted session tokens.
- Malware delivery over trusted HTTPS connections.
- Data manipulation in transit.
- In mobile apps, bypassed pinning + disabled validation = complete API traffic visibility.

## Where to Look
- Mobile application network code (Java/Kotlin for Android, Swift/Obj-C for iOS).
- Backend services making outbound HTTPS calls (HTTP clients, SDK integrations, webhook senders).
- Python: `requests.get(url, verify=False)`, `ssl._create_unverified_context()`.
- Java: custom `TrustManager` that accepts all certificates (`X509TrustManager` with empty `checkServerTrusted`).
- Node.js: `process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'`, `https.request({rejectUnauthorized: false})`.
- PHP: `CURLOPT_SSL_VERIFYPEER => false`, `CURLOPT_SSL_VERIFYHOST => false`.
- Go: `tls.Config{InsecureSkipVerify: true}`.
- The server's certificate itself: hostname mismatch, expired dates, self-signed, SHA1/MD5 signature.
- Internal APIs and microservices that use self-signed certs without proper CA distribution.

## Testing Steps
1. Open the target URL in a browser and check for certificate warnings. Record certificate details: issuer, validity dates, SANs, signature algorithm.
2. Use `openssl s_client` to retrieve and inspect the certificate chain.
3. Run `testssl.sh` to check for certificate issues: expiry, hostname match, chain completeness, signature algorithm.
4. Check revocation: OCSP stapling and CRL distribution points.
5. For mobile apps: install Burp Suite's CA certificate on the test device. If the app communicates normally, certificate validation is absent or bypassable.
6. Test certificate pinning bypass: use Frida or objection to hook SSL validation functions and disable pinning.
7. Search application source code or decompiled mobile code for the patterns listed in "Where to Look."
8. Test subdomains: `openssl s_client -connect sub.target.example.com:443 | openssl x509 -noout -text` — verify each subdomain has a matching SAN.
9. Check HPKP headers (deprecated but worth noting if present) and HSTS preload status.
10. Verify OCSP stapling: `openssl s_client -connect target.example.com:443 -status` — look for "OCSP Response Status: successful."

## Payloads / Techniques

```bash
# Retrieve and display the full certificate chain
openssl s_client -connect target.example.com:443 -showcerts 2>/dev/null

# Display certificate details (expiry, CN, SAN, issuer, signature alg)
openssl s_client -connect target.example.com:443 2>/dev/null | openssl x509 -noout -text

# Check certificate expiry date only
openssl s_client -connect target.example.com:443 2>/dev/null | openssl x509 -noout -dates

# Check SANs (Subject Alternative Names)
openssl s_client -connect target.example.com:443 2>/dev/null | openssl x509 -noout -ext subjectAltName

# Check signature algorithm (look for md5WithRSAEncryption or sha1WithRSAEncryption)
openssl s_client -connect target.example.com:443 2>/dev/null | openssl x509 -noout -text | grep "Signature Algorithm"

# Check OCSP stapling
openssl s_client -connect target.example.com:443 -status 2>/dev/null | grep -A5 "OCSP"

# testssl.sh — comprehensive certificate checks
testssl.sh --certificate https://target.example.com

# Check for hostname mismatch
# If CN/SAN does not match the host, openssl reports: "verify error:num=62:Hostname mismatch"
openssl s_client -connect target.example.com:443 -verify_hostname target.example.com

# Check certificate chain for completeness
openssl verify -untrusted /tmp/chain.pem /tmp/leaf.pem

# Certificate transparency log search (find all certs issued for a domain)
curl -s "https://crt.sh/?q=%.example.com&output=json" | python3 -m json.tool | grep name_value

# Nmap certificate check
nmap --script ssl-cert -p 443 target.example.com

# Check if app/code disables SSL verification (Python grep)
grep -rn "verify=False\|verify = False\|CERT_NONE\|_create_unverified_context" /path/to/source/

# Node.js insecure flag
grep -rn "rejectUnauthorized.*false\|NODE_TLS_REJECT_UNAUTHORIZED" /path/to/source/

# Java insecure TrustManager pattern
grep -rn "checkServerTrusted\|X509TrustManager\|TrustAllCerts" /path/to/source/

# PHP insecure curl options
grep -rn "CURLOPT_SSL_VERIFYPEER\|CURLOPT_SSL_VERIFYHOST" /path/to/source/

# Go insecure TLS config
grep -rn "InsecureSkipVerify" /path/to/source/
```

```bash
# Frida script to bypass Android certificate pinning (via objection)
objection -g com.target.app explore
# Then inside objection:
# android sslpinning disable

# Frida standalone SSL pinning bypass
frida --codeshare akabe1/frida-multiple-unpinning -f com.target.app -U

# Install Burp CA on Android device (for MITM testing)
adb push burp_ca.der /sdcard/
# Then import via Settings > Security > Install from storage
```

## Burp Suite Tips
- Burp acts as a TLS MITM proxy. If the app validates certificates properly, it will refuse connections through Burp — which itself indicates validation is working.
- Install Burp's CA certificate (`http://burp/cert`) in the OS/browser trust store to intercept traffic without certificate errors.
- For mobile apps: install the Burp CA certificate on the mobile device (Android: Settings > Security; iOS: Settings > Profile > Trust). If the app still refuses to connect after this, it likely uses certificate pinning.
- Use the **Mobile Assistant** (Burp BApp) for Android to help bypass pinning.
- Check the **Target > Site Map** certificate details by clicking the padlock icon on any HTTPS host — Burp displays the negotiated cert, chain, and validation status.
- The **Proxy > HTTP History** pane shows CONNECT requests. If they fail, inspect the TLS error for clues about pinning or strict validation.
- For internal/self-signed certs: use **Project Options > SSL > Server Certificates** to add custom CA trust for specific hosts in Burp.

## Tools
- openssl s_client (certificate inspection)
- testssl.sh — https://testssl.sh
- sslscan — https://github.com/rbsec/sslscan
- Burp Suite (MITM proxy)
- Frida — https://frida.re
- objection — https://github.com/sensepost/objection
- SSL Labs — https://www.ssllabs.com/ssltest/
- crt.sh — https://crt.sh (certificate transparency search)
- mitmproxy — https://mitmproxy.org
- Wireshark (TLS handshake analysis)
- certigo — https://github.com/square/certigo (Go-based cert tool)

## Remediation
- Use certificates from a trusted, publicly trusted CA (Let's Encrypt, DigiCert, etc.) in production.
- Ensure certificate chains are complete — include all intermediate certificates.
- Monitor expiry and automate renewal (Let's Encrypt certbot with auto-renewal cron/systemd).
- Use certificates signed with SHA-256 or stronger. Replace any MD5/SHA-1 certificates immediately.
- Ensure all SANs are correct for every hostname the certificate serves; never rely solely on CN.
- Never disable certificate validation in production code. Remove `verify=False`, `InsecureSkipVerify`, and similar patterns before shipping.
- Enable OCSP stapling to provide fast revocation status.
- Enable HSTS to prevent protocol downgrade: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`
- Implement certificate pinning in high-value mobile apps (pin to the public key hash, not the leaf certificate, to survive CA re-issuance).
- Subscribe to certificate transparency monitoring (e.g., Facebook CT Monitor, Cert Spotter) to detect unauthorized certificate issuance.

## References
https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning
https://portswigger.net/web-security/transport-layer-security
https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html
https://letsencrypt.org/docs/
https://crt.sh/
https://nvd.nist.gov/vuln/detail/CVE-2014-7911
https://developer.android.com/training/articles/security-ssl
https://developer.apple.com/documentation/foundation/url_loading_system/handling_an_authentication_challenge
https://www.rfc-editor.org/rfc/rfc6962
