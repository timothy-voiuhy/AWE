# .env / Config File Exposure

## Overview
`.env` files and other configuration files (`.env.local`, `.env.production`, `config.php`, `database.yml`, `settings.py`, `appsettings.json`) contain credentials, API keys, database connection strings, and secrets. When these files are accidentally committed to a public repository, left in a web-accessible directory, or exposed via misconfigured web servers, attackers gain direct access to all secrets needed to compromise the application and its data.

## How It Works
- Developers store secrets in `.env` files and rely on `.gitignore` to exclude them — but sometimes forget, mistype the rule, or commit before adding the rule.
- Web servers misconfigured to serve files from the project root can serve `.env` directly at `https://target.com/.env`.
- Backup files: `.env.bak`, `.env.old`, `.env~`, `config.php.bak` may be served when the original is protected.
- CI/CD pipeline logs may print environment variables including secrets.

## Impact
- Database credentials → complete data exfiltration.
- AWS/cloud service keys → takeover of cloud infrastructure.
- JWT signing secrets → token forgery.
- Email SMTP credentials → send phishing emails from trusted domain.
- Stripe/payment API keys → financial fraud.
- Third-party API keys → API abuse, cost escalation.

## Where to Look
- `/.env`, `/.env.local`, `/.env.development`, `/.env.production`, `/.env.backup`
- `/config.php`, `/wp-config.php`, `/configuration.php`, `/app/config/database.yml`
- `/appsettings.json`, `/appsettings.Development.json`, `/appsettings.Production.json`
- `/settings.py`, `/local_settings.py`, `/config/secrets.yml`
- `/database.yml`, `/database.php`, `/db.config.json`
- `/.env.bak`, `/.env~`, `/.env.old`, `/config.php.bak`

## Testing Steps
1. Request `/.env` directly: `curl -s https://target.com/.env`.
2. Check status code — 200 with env-like content = confirmed exposure.
3. Try backup variants: `.env.bak`, `.env.old`, `.env~`, `.env.save`.
4. Try production/staging variants: `.env.production`, `.env.staging`, `.env.local`.
5. Check common CMS config files: `/wp-config.php`, `/configuration.php` (Joomla), `/sites/default/settings.php` (Drupal).
6. Run a wordlist of config file paths with ffuf.
7. Check GitHub/GitLab/Bitbucket for public repos containing the target's domain in `.env` files.
8. Search for the domain on paste sites and GitHub using: `site:github.com "target.com" ".env" "DB_PASSWORD"`.

## Payloads / Techniques
```bash
# Direct requests
curl -s https://target.com/.env
curl -s https://target.com/.env.local
curl -s https://target.com/.env.production
curl -s https://target.com/.env.bak
curl -s https://target.com/wp-config.php
curl -s https://target.com/config.php
curl -s https://target.com/database.yml

# Wordlist scan
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -u https://target.com/FUZZ \
  -mc 200 -fc 404

# GitHub search (replace target.com with actual domain)
# Search: "APP_SECRET" "target.com" extension:env
# Search: "DB_PASSWORD" "target.com"

# Common .env content patterns to look for
grep -E "DB_PASSWORD|APP_KEY|AWS_SECRET|STRIPE_SECRET|JWT_SECRET|MAIL_PASSWORD" .env_output.txt
```

**Typical .env structure to look for:**
```
APP_ENV=production
APP_KEY=base64:xxx...
DB_HOST=localhost
DB_DATABASE=myapp
DB_USERNAME=root
DB_PASSWORD=SuperSecret123
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
STRIPE_SECRET=sk_live_...
JWT_SECRET=my_jwt_secret
MAIL_PASSWORD=email_password
```

## Burp Suite Tips
- Add common config file paths to the **Target > Site map** and use **"Discover Content"** or **Intruder** to probe them.
- Check the **Scanner** results for "Sensitive data in plaintext" findings.
- Set up a **Match and Replace** rule to automatically flag responses containing `DB_PASSWORD`, `APP_KEY`, `SECRET` strings.

## Tools
- ffuf / gobuster — directory and file enumeration
- truffleHog — https://github.com/trufflesecurity/trufflehog (secret scanning in git history)
- gitleaks — https://github.com/gitleaks/gitleaks (git secret scanning)
- GitDorker — GitHub dorking for exposed secrets

## Remediation
- Add `.env*` to `.gitignore` before ever creating the file.
- Use secrets management services (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault) instead of `.env` files in production.
- Configure the web server to deny access to dotfiles and backup files:
  - Nginx: `location ~ /\. { deny all; }`
  - Apache: `<FilesMatch "^\."> Deny from all </FilesMatch>`
- Rotate all credentials immediately upon discovery of an exposure.
- Audit git history for committed secrets using gitleaks/truffleHog.

## References
https://owasp.org/www-project-top-ten/2021/A02_2021-Cryptographic_Failures
https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
https://portswigger.net/web-security/information-disclosure
https://trufflesecurity.com/blog/trufflehog-v3
