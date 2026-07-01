# Default Credentials

## Overview
Default credentials are factory-set username and password combinations shipped with software, hardware, or services that administrators fail to change before deployment. They exist because vendors need a known initial access method, but leaving them unchanged creates a trivially exploitable entry point. An attacker who gains access via default credentials immediately has authenticated access, often with administrative privileges.

## How It Works
- Vendors ship products with well-known credentials (e.g., `admin:admin`, `admin:password`, `root:root`).
- These credentials are publicly documented in manuals, GitHub repos, and databases like DefaultCreds-cheat-sheet.
- Attackers enumerate the application/device type through version banners, headers, or error messages, then look up known default credentials.
- If the application offers multiple roles (admin, operator, guest), all default credentials for all roles should be tested.
- Network devices, IoT, CMS platforms (WordPress, Drupal, Joomla), monitoring tools (Grafana, Zabbix, Nagios), and Java application servers (Tomcat, JBoss, WebLogic) are especially common targets.

## Impact
- Full administrative takeover of the application or underlying system.
- Access to sensitive data, configuration files, user records, and secrets.
- Ability to pivot laterally if the account has access to internal services.
- Persistent backdoor establishment via account creation or SSH key injection.
- Reputation and compliance damage (PCI-DSS, HIPAA, SOC2 require credential hygiene).

## Where to Look
- Login pages (`/admin`, `/login`, `/wp-admin`, `/manager`, `/console`, `/dashboard`, `/phpmyadmin`).
- Embedded device admin panels (routers, printers, IP cameras).
- Monitoring platforms: Grafana (`admin:admin`), Zabbix (`Admin:zabbix`), Kibana (no auth by default in older versions).
- Java application servers: Tomcat (`tomcat:tomcat`, `admin:admin`), JBoss, WebLogic (`weblogic:weblogic1`).
- Database admin interfaces: phpMyAdmin, Adminer, pgAdmin.
- CI/CD tools: Jenkins (no password by default, or `admin:admin`), GitLab (`root:5iveL!fe` on first setup).
- `robots.txt`, `sitemap.xml`, or JS source for hidden admin paths.

## Testing Steps
1. Identify the technology stack via HTTP headers (`Server`, `X-Powered-By`), cookies (e.g., `JSESSIONID`), error pages, or tools like Wappalyzer.
2. Search DefaultCreds-cheat-sheet, CIRT.net, or vendor documentation for known default credentials for the identified product and version.
3. Attempt manual login with the top 5–10 most common credentials for the platform.
4. Check all login endpoints — the main app login, admin panel, API, and any management interfaces on alternate ports.
5. Use a targeted wordlist (not a generic brute-force list) to keep noise low and avoid lockouts.
6. If successful, document the credential, access level, and any sensitive data immediately visible.
7. Test all user role variants (admin, operator, guest, service accounts) with their respective defaults.
8. Check if the credential is also valid on adjacent services (SSH, FTP, database) due to credential reuse.

## Payloads / Techniques

Common default credential pairs to try:
```
admin:admin
admin:password
admin:1234
admin:admin123
administrator:administrator
root:root
root:toor
guest:guest
user:user
test:test
```

Hydra targeted attack (low thread count to avoid lockout):
```bash
hydra -l admin -P /usr/share/wordlists/default_creds.txt -t 4 -f https://target.com http-post-form "/login:username=^USER^&password=^PASS^:Invalid credentials"
```

curl test for specific credential:
```bash
curl -s -o /dev/null -w "%{http_code}" -X POST https://target.com/admin/login \
  -d "username=admin&password=admin" \
  -c /tmp/cookies.txt
```

Apache Tomcat manager:
```bash
curl -u tomcat:tomcat http://target.com:8080/manager/html
curl -u admin:admin http://target.com:8080/manager/html
```

Grafana default:
```bash
curl -X POST http://target.com:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"user":"admin","password":"admin"}'
```

## Burp Suite Tips
- Use **Intruder** (Cluster Bomb mode) with a small list of known default usernames and passwords — keep thread count at 1–2 to avoid lockouts.
- The **Logger** tab captures all requests; filter by response code to identify `200` or redirect responses that indicate successful login.
- Install the **Software Vulnerability Scanner** or **Retire.js** extension to identify technology versions that can then be cross-referenced against default credential databases.
- Use **Repeater** to manually replay a successful login, inspect the session token issued, and verify access level.
- Enable **Proxy** and walk through the login manually with default credentials; Burp captures the full request for later replay.

## Tools
- **DefaultCreds-cheat-sheet** — Comprehensive searchable database of default credentials by vendor/product.
- **Hydra** — Network login brute-forcer supporting HTTP, SSH, FTP, and dozens of other protocols.
- **Medusa** — Parallel network login auditor, similar to Hydra.
- **Nmap NSE scripts** — Scripts like `http-default-accounts` automate default credential checks for common services.
- **Metasploit** — Auxiliary modules (e.g., `auxiliary/scanner/http/tomcat_mgr_login`) for targeted default cred testing.
- **Wappalyzer / WhatWeb** — Technology fingerprinting to identify the platform before looking up credentials.

## Remediation
- Force credential change on first login; block the application from functioning until the default password is replaced.
- Remove or disable all default accounts that are not required for operation.
- Implement a password complexity policy that rejects well-known weak passwords via a blocklist (NIST SP 800-63B).
- Audit all service accounts, API keys, and database credentials for default or weak values as part of deployment checklists.
- Use secret management tools (HashiCorp Vault, AWS Secrets Manager) to inject credentials at runtime rather than hardcoding defaults.
- Include default credential checks in CI/CD pipeline security scanning.

## References
https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication
https://github.com/ihebski/DefaultCreds-cheat-sheet
https://cirt.net/passwords
https://www.cisa.gov/news-events/alerts/2016/06/30/securing-network-infrastructure-devices
https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
