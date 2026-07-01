# Hardcoded Secrets / Keys in JS/Source

## Overview
Hardcoded secrets occur when developers embed sensitive values — API keys, passwords, cryptographic secrets, OAuth tokens, private keys, or database credentials — directly in source code, configuration files, or client-side JavaScript. These secrets are then committed to version control, bundled into applications, or served to clients, where they can be trivially extracted by anyone with access to the codebase or the running application. This is one of the most common and impactful vulnerability classes in modern web and mobile applications.

## How It Works
Secrets enter code through multiple paths:

1. **Client-side JavaScript bundles:** Frontend frameworks (React, Vue, Angular) often embed environment variables (e.g., `REACT_APP_API_KEY`) directly in the compiled JavaScript bundle that is served to every browser visitor.
2. **Source code commits:** Developers commit secrets to Git repositories. Even if removed in a later commit, the secret persists in Git history indefinitely.
3. **Mobile app binaries:** API keys, encryption keys, and endpoint URLs are often embedded in APK/IPA files and can be extracted with static analysis tools.
4. **Public repository leakage:** `.env` files, `config.json`, or AWS credential files are accidentally committed to public GitHub/GitLab repositories.
5. **CI/CD pipeline artifacts:** Secrets used in build scripts sometimes appear in build logs or are baked into Docker image layers.
6. **Comment blocks:** Developers leave secrets in code comments, TODO notes, or test files.

Once an attacker finds a secret, they can impersonate the application to third-party services, access backend infrastructure, exfiltrate data, or escalate privileges.

## Impact
- Unauthorized access to third-party APIs (AWS, Stripe, Twilio, SendGrid, Google APIs).
- Full infrastructure compromise if AWS/GCP/Azure keys are exposed (create resources, exfiltrate data, incur massive costs).
- Database credential exposure leading to data breach.
- JWT signing secret exposure allowing creation of arbitrary valid tokens and authentication bypass.
- Stripe/payment API key exposure enabling fraudulent charges or data exfiltration of customer payment data.
- OAuth client secret exposure enabling impersonation of the application to the identity provider.
- Cryptographic key exposure enabling decryption of all historical encrypted data.

## Where to Look
- JavaScript bundle files served by the app: `main.js`, `bundle.js`, `app.[hash].js`, `vendor.[hash].js`.
- HTML source code: inline `<script>` blocks, data attributes (`data-api-key="..."`).
- Public Git repositories: GitHub, GitLab, Bitbucket — search the full commit history.
- `.env`, `.env.local`, `.env.production` files in web roots or accidentally served.
- `config.json`, `settings.json`, `appsettings.json`, `web.config` served publicly.
- JavaScript source maps (`.map` files) that reconstruct original pre-minified source.
- Mobile app binaries: strings extracted from APK/IPA.
- Docker images on Docker Hub.
- CI/CD logs (GitHub Actions, CircleCI, Jenkins) visible to authenticated users.
- npm packages published with `node_modules/` or config files included.
- AWS metadata endpoint: `http://169.254.169.254/latest/meta-data/iam/security-credentials/` (if SSRF is available).

## Testing Steps
1. Browse the target site and open browser DevTools. Navigate to the **Sources** tab and inspect all loaded JavaScript files.
2. Download all JavaScript bundle files and search for key patterns (see grep commands below).
3. Check for `.map` source map files — they may expose original source with comments and secrets.
4. Search the target's GitHub/GitLab organisation for exposed repos. Search commit history.
5. Request common config file paths: `/.env`, `/config.json`, `/settings.json`, `/.git/config`.
6. Check HTML source for inline secrets in `<script>` blocks or HTML attributes.
7. For mobile apps: extract APK and run `strings` against native libraries and decompile Dalvik bytecode.
8. Run automated secret scanners (truffleHog, gitleaks, detect-secrets) against any downloaded source.
9. Search JavaScript for patterns that reveal API endpoint construction (may reveal keys in query params).
10. Check network requests in DevTools Network tab — some apps send API keys as URL parameters or request headers that are visible in plain text.

## Payloads / Techniques

```bash
# ===== GREP PATTERNS FOR LOCAL SOURCE / DOWNLOADED JS =====

# Generic high-value secret patterns
grep -rniE \
  "api[_-]?key|apikey|api[_-]?secret|access[_-]?key|secret[_-]?key|auth[_-]?token|bearer|private[_-]?key" \
  /path/to/source/

# AWS credentials
grep -rniE \
  "AKIA[0-9A-Z]{16}|aws[_-]?access[_-]?key|aws[_-]?secret|aws[_-]?session[_-]?token" \
  /path/to/source/

# AWS secret key value pattern (40 chars alphanumeric)
grep -rniE "['\"][0-9a-zA-Z/+]{40}['\"]" /path/to/source/

# JWT secrets
grep -rniE "jwt[_-]?secret|jwt[_-]?key|signing[_-]?secret|token[_-]?secret" /path/to/source/

# Database credentials
grep -rniE \
  "password[[:space:]]*=[[:space:]]*['\"][^'\"]{4,}|db[_-]?pass|database[_-]?password|mysql[_-]?pass|postgres[_-]?password" \
  /path/to/source/

# OAuth / client secrets
grep -rniE \
  "client[_-]?secret|consumer[_-]?secret|oauth[_-]?secret|app[_-]?secret" \
  /path/to/source/

# Stripe keys
grep -rniE "sk_live_[0-9a-zA-Z]{24,}|rk_live_[0-9a-zA-Z]{24,}|sk_test_[0-9a-zA-Z]{24,}" /path/to/source/

# GitHub tokens
grep -rniE "ghp_[a-zA-Z0-9]{36}|github[_-]?token|gh[_-]?token" /path/to/source/

# Google API keys
grep -rniE "AIza[0-9A-Za-z_-]{35}" /path/to/source/

# Slack tokens
grep -rniE "xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}" /path/to/source/

# Twilio credentials
grep -rniE "AC[a-z0-9]{32}|SK[a-z0-9]{32}" /path/to/source/

# Private RSA/EC keys
grep -rniE "BEGIN (RSA |EC )?PRIVATE KEY|BEGIN OPENSSH PRIVATE KEY" /path/to/source/

# Hardcoded passwords in config
grep -rniE "password[[:space:]]*:[[:space:]]*['\"][^'\"]{4,}" /path/to/source/

# .env variable patterns
grep -rniE "^[A-Z_]+=.{8,}" /path/to/.env* 2>/dev/null

# ===== GIT HISTORY SCANNING =====

# truffleHog — scan git history for high-entropy secrets
trufflehog git https://github.com/target-org/target-repo --only-verified

# truffleHog — scan local repo
trufflehog filesystem /path/to/local/repo

# gitleaks — scan git history
gitleaks detect --source /path/to/repo --report-format json --report-path gitleaks-report.json

# gitleaks — scan remote GitHub org
gitleaks detect --source https://github.com/target-org --no-git

# git log — search all commits for keyword
git -C /path/to/repo log --all -p -S "api_key" --source --remotes

# git log — find commits that added/removed a specific string
git -C /path/to/repo log --all --diff-filter=M -p -- "*.env"

# ===== JAVASCRIPT BUNDLE ANALYSIS =====

# Download all JS from a page
wget -r -l1 -nd -A "*.js" https://target.example.com/ -P /tmp/js_files/

# Search downloaded JS bundles
grep -rniE "api[_-]?key|secret|token|password|AKIA|AIza|sk_live" /tmp/js_files/

# Find and download source maps (reconstruct original source)
find /tmp/js_files/ -name "*.map" -exec cat {} \; | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        m = json.loads(line)
        for i, src in enumerate(m.get('sources', [])):
            print(f'--- {src} ---')
            if 'sourcesContent' in m and i < len(m['sourcesContent']):
                print(m['sourcesContent'][i])
    except: pass
"

# ===== COMMON EXPOSED FILE PATHS TO CHECK =====
for path in /.env /.env.local /.env.production /config.json /settings.json \
            /appsettings.json /.git/config /web.config /secrets.json \
            /credentials.json /.npmrc /.docker/config.json; do
  result=$(curl -s -o /dev/null -w "%{http_code}" "https://target.example.com${path}")
  echo "$path -> HTTP $result"
done

# ===== MOBILE APP =====
# Extract strings from APK
apktool d target.apk -o /tmp/apk_extracted
grep -rniE "api[_-]?key|secret|password|AKIA|AIza" /tmp/apk_extracted/

# strings on native libraries
strings /tmp/apk_extracted/lib/arm64-v8a/libnative.so | grep -iE "api|key|secret|token"
```

```python
# detect-secrets — baseline secret scanner for CI
# Install: pip install detect-secrets
# Scan a directory
# detect-secrets scan /path/to/source > .secrets.baseline
# Review findings
# detect-secrets audit .secrets.baseline

import subprocess, json

result = subprocess.run(
    ["detect-secrets", "scan", "--all-files", "/path/to/source"],
    capture_output=True, text=True
)
baseline = json.loads(result.stdout)
for filename, secrets in baseline.get("results", {}).items():
    for s in secrets:
        print(f"[{s['type']}] {filename}:{s['line_number']}")
```

## Burp Suite Tips
- In Burp's **Proxy > HTTP History**, filter by `Content-Type: application/javascript` to quickly find JavaScript files. Right-click and send to **Decoder** or search within the response using Ctrl+F.
- Use **Target > Site Map**, right-click the target domain, and select **Engagement Tools > Search** — search for patterns like `api`, `key`, `secret`, `token`.
- Install the **JS Beautifier** BApp to pretty-print minified JavaScript directly in Burp's message editor — makes secret hunting much easier.
- Use **Burp's Logger** (Logger++ BApp) to capture all responses and run regex searches across all loaded JavaScript files.
- In **Proxy > Options**, enable **Intercept WebSocket messages** — some apps send API keys over WebSocket connections.
- Use the **Retire.js** BApp to identify outdated JS libraries that may have known CVEs alongside your manual secret search.
- Check the **Response** tab in Repeater for any API responses that echo back keys or tokens (APIs sometimes return their own configuration in `/api/config` or similar endpoints).

## Tools
- truffleHog — https://github.com/trufflesecurity/trufflehog
- gitleaks — https://github.com/gitleaks/gitleaks
- detect-secrets — https://github.com/Yelp/detect-secrets
- git-secrets — https://github.com/awslabs/git-secrets
- Semgrep (with secret detection rules) — https://semgrep.dev/
- GitGuardian — https://www.gitguardian.com/
- apktool — https://ibotpeaches.github.io/Apktool/
- jadx (Android decompiler) — https://github.com/skylot/jadx
- Burp Suite (JS Beautifier, Logger++)
- grep / ripgrep (rg) for fast local scanning

## Remediation
- Never commit secrets to version control. Use environment variables or secrets managers (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault).
- Add secret patterns to `.gitignore` and `pre-commit` hooks using tools like detect-secrets or gitleaks.
- For frontend applications, use backend proxy endpoints for API calls requiring keys — never expose API keys in client-side JavaScript.
- Rotate any discovered secrets immediately. Rotating is not optional even after the root cause is fixed, because the old secret persists in caches, logs, and backups.
- Audit Git history with truffleHog/gitleaks and use `git filter-branch` or BFG Repo Cleaner to remove secrets from history if a public repository was involved.
- Implement SAST tools in CI/CD to detect secrets before merge (Semgrep, GitHub secret scanning, GitLab secret detection).
- Use short-lived credentials and token scoping — limit damage if a secret is exposed.
- For AWS: use IAM roles instead of access keys wherever possible; enable GuardDuty to detect anomalous API key usage.

## References
https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_credentials
https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
https://portswigger.net/web-security/information-disclosure
https://github.com/trufflesecurity/trufflehog
https://github.com/gitleaks/gitleaks
https://www.gitguardian.com/
https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning
https://owasp.org/Top10/A02_2021-Cryptographic_Failures/
