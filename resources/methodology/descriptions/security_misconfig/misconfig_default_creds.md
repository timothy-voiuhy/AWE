# Default Credentials on Admin Panels

## Overview
Many applications, frameworks, and infrastructure components ship with well-known default credentials that administrators fail to change before deployment. Admin panels accessible with default username/password combinations represent one of the easiest paths to full application compromise — requiring no exploitation technique, just a credential lookup.

## How It Works
- Software ships with documented default credentials for initial setup (`admin/admin`, `admin/password`, `root/root`).
- Administrators deploy the software and either forget to change defaults or assume the panel is not internet-facing.
- Attackers identify the software (version disclosure, UI fingerprinting) and look up default credentials from known lists.
- Credential stuffing tools can test hundreds of default combos in seconds.

## Impact
- Full administrative control of the application.
- Access to all user data, configurations, and secrets.
- Ability to deploy backdoors, escalate to OS access, or pivot to internal systems.
- Complete data breach with single credential pair.

## Where to Look
- `/admin`, `/administrator`, `/admin/login`, `/wp-admin`, `/phpmyadmin`
- `/manager` (Tomcat), `/console` (JBoss/WildFly), `/jmx-console`
- `/jenkins`, `/grafana`, `/kibana`, `/elastic`, `/portainer`
- `/nagios`, `/zabbix`, `/cacti`, `/prtg`
- Router/printer management interfaces
- Database admin panels: `/phpmyadmin`, `/adminer`, `/db-admin`
- IoT device web interfaces

## Testing Steps
1. Identify the software stack and version (from headers, error pages, UI elements, favicon hash).
2. Look up default credentials for the identified software.
3. Attempt login with each default credential pair.
4. Check `admin/admin`, `admin/password`, `admin/123456`, `root/root`, `root/toor`.
5. Try the software name as username/password: `jenkins/jenkins`, `grafana/grafana`.
6. Try blank password: `admin:` (empty password).
7. Check if setup/install wizards are accessible (may still be active).
8. Test common paths for admin panels not linked from the main site.

## Payloads / Techniques
**Common default credential pairs:**
```
admin / admin
admin / password
admin / 123456
admin / (empty)
root / root
root / toor
root / password
administrator / administrator
user / user
guest / guest
test / test
demo / demo
# Software-specific defaults
jenkins / jenkins
grafana / admin
kibana / changeme
tomcat / tomcat
manager / manager
nagios / nagios
zabbix / zabbix
prtg / prtgadmin
weblogic / weblogic1
websphere / websphere
jboss / jboss
```

```bash
# Test with curl
curl -s -X POST https://target.com/admin/login \
  -d "username=admin&password=admin" -c cookies.txt -L

# Hydra credential stuffing
hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt \
      -P /usr/share/seclists/Passwords/Default-Credentials/default-passwords.txt \
      https-post-form://target.com/admin/login:username=^USER^&password=^PASS^:Invalid
```

## Burp Suite Tips
- Use **Intruder** (Cluster Bomb) to test username × password combinations from default credential lists.
- **Active Scanner** (Pro) tests for default credentials on some common panels.
- Check the **Burp Target** site map for admin paths discovered during spidering.

## Tools
- Hydra — https://github.com/vanhauser-thc/thc-hydra (credential testing)
- Medusa — password spraying
- DefaultCreds-cheat-sheet — https://github.com/ihebski/DefaultCreds-cheat-sheet
- SecLists Default Credentials: `/usr/share/seclists/Passwords/Default-Credentials/`

## Remediation
- Change all default credentials immediately after deployment.
- Require credential change on first login via setup wizard.
- Restrict admin panel access by IP whitelist or VPN.
- Implement account lockout after failed authentication attempts.
- Audit all deployed components for unchanged default credentials.
- Implement MFA on all administrative interfaces.

## References
https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration
https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
https://github.com/ihebski/DefaultCreds-cheat-sheet
