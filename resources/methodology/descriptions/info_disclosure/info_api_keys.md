# API Keys / Credentials in Responses

## Overview
API keys and credentials disclosed in HTTP responses represent a direct, immediately exploitable information leak. They occur when applications inadvertently include sensitive credentials in JSON responses, HTML source, JavaScript files, debug output, error messages, or HTTP headers. Because modern applications often manage dozens of third-party API integrations, the risk surface is broad — a single endpoint returning a configuration object might expose keys for AWS, Stripe, Twilio, SendGrid, Google Maps, and more.

## How It Works
Developers may return full configuration objects from API endpoints without filtering sensitive fields, embed API keys in client-side JavaScript that gets served to all users, include credentials in verbose error messages, or log authentication tokens in HTTP response bodies for debugging. Sometimes keys appear in responses intended only for admins but where access controls are missing. Keys in JavaScript files are particularly dangerous because they are cached and indexed by search engines, and are accessible to all users without authentication.

## Impact
- Direct unauthorized access to third-party services (AWS, Stripe, Twilio, etc.)
- Financial losses from API abuse (payment processing, SMS sending, cloud resources)
- Data breaches via access to cloud storage (S3 buckets, Google Cloud Storage)
- Account takeover for services tied to disclosed keys
- Lateral movement using cloud credentials to access other internal services
- Reputation damage from API key abuse for spam or illegal activity

## Where to Look
- JSON API responses for user settings, profile, or admin configuration endpoints
- JavaScript files — especially app bundles, config.js, environment files served as JS
- HTML source comments containing developer debug data
- HTTP response headers (custom internal headers)
- Error messages and stack traces (connection strings, credentials)
- `/api/config`, `/api/settings`, `/config.js`, `/env.js`, `/app-config.js`
- GraphQL schema introspection responses
- Webhook delivery payload logs
- Any endpoint that returns "configuration" data

## Testing Steps
1. Browse the application and inspect all JSON API responses for key-value pairs that look like credentials.
2. Download all JavaScript files and search for key patterns (see payloads section for regex patterns).
3. Check configuration-related endpoints: `/api/config`, `/api/settings`, `/api/v1/app-config`.
4. Inspect HTML source for comments containing debug credentials.
5. View HTTP response headers for custom internal headers.
6. Trigger error conditions to check if error messages include connection string credentials.
7. If admin-role API endpoints are accessible (IDOR, broken access control), check those specifically for config data.
8. Use automated tools to scan JavaScript bundles for secret patterns.
9. Check for OIDC/OAuth discovery documents that might reveal client secrets.

## Payloads / Techniques

```
# Regex patterns for common API key formats
# Use in grep, Burp Search, or JS scanners

# AWS Access Key ID
AKIA[0-9A-Z]{16}
ASIA[0-9A-Z]{16}    # Temporary STS credential

# AWS Secret Access Key (contextual — look near AccessKeyId)
[0-9a-zA-Z/+]{40}

# Stripe
sk_live_[0-9a-zA-Z]{24,}    # Stripe live secret key
pk_live_[0-9a-zA-Z]{24,}    # Stripe publishable (less sensitive)
rk_live_[0-9a-zA-Z]{24,}    # Stripe restricted key

# Twilio
AC[a-z0-9]{32}               # Account SID
SK[a-z0-9]{32}               # API Key SID

# SendGrid
SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}

# GitHub Token
ghp_[a-zA-Z0-9]{36}         # Personal access token
github_pat_[a-zA-Z0-9_]{82}

# Google API Key
AIza[0-9A-Za-z\-_]{35}

# Google OAuth Client Secret
GOCSPX-[a-zA-Z0-9\-_]{28}

# Slack
xoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}  # Bot token
xoxp-[0-9]{11}-[0-9]{11}-[0-9]{12}-[a-zA-Z0-9]{32}  # User token
xoxa-2-[0-9]{11}-[0-9]{11}-[0-9]{12}-[a-zA-Z0-9]{32}  # App token
xoxr-[a-zA-Z0-9]{64}        # Refresh token

# JWT
eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+

# Generic patterns
(?i)(api[_-]?key|apikey|api[_-]?secret|app[_-]?secret|auth[_-]?token|access[_-]?token)\s*[:=]\s*['"]?[a-zA-Z0-9\-_/+]{16,}['"]?
(?i)(password|passwd|secret|credential|private[_-]?key)\s*[:=]\s*['"]?[^'"]{8,}['"]?
```

```bash
# Download all JS files and grep for secrets
# Extract JS URLs from page
curl -s "https://target.com/" | grep -oP '"[^"]+\.js"' | tr -d '"' | \
  sed 's|^|https://target.com|' | sort -u > /tmp/js_files.txt

# Download and search
while read url; do
  filename=$(echo "$url" | md5sum | cut -d' ' -f1)
  curl -s "$url" -o "/tmp/js_$filename.js"
done < /tmp/js_files.txt

grep -rP 'AKIA[0-9A-Z]{16}|sk_live_|SG\.|AIza|ghp_|xoxb-' /tmp/js_*.js

# API response scanning for credentials
curl -s "https://target.com/api/user/settings" | \
  python3 -m json.tool | \
  grep -iE '"(api_key|secret|token|password|credential)"'

# Check config-related endpoints
for endpoint in config settings app-config env environment configuration init; do
  echo "=== /api/$endpoint ==="
  curl -s "https://target.com/api/$endpoint" | python3 -m json.tool 2>/dev/null | \
    grep -iE '"(key|secret|token|password|credential|auth)"'
done
```

```bash
# Validate found AWS credentials
aws sts get-caller-identity \
  --aws-access-key-id AKIAIOSFODNN7EXAMPLE \
  --aws-secret-access-key wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# Validate Stripe key (read-only check)
curl https://api.stripe.com/v1/charges \
  -u "sk_live_XXXX:"

# Validate GitHub token
curl -s -H "Authorization: token ghp_XXXX" \
  "https://api.github.com/user"

# Validate Google API key (Maps)
curl "https://maps.googleapis.com/maps/api/geocode/json?address=1600+Amphitheatre+Parkway&key=AIzaXXXX"

# Validate SendGrid
curl -s -X GET "https://api.sendgrid.com/v3/user/account" \
  -H "Authorization: Bearer SG.XXXX"
```

## Burp Suite Tips
- Use **Burp > Search** (Ctrl+Shift+F) across all tools with the regex `(AKIA|sk_live|SG\.|AIza|ghp_|xoxb-)` to scan the entire session history.
- Install the **JS Miner** extension (BApp Store) — it automatically scans JavaScript files loaded during browsing for secrets, API keys, and URLs.
- The **Retire.js** extension identifies outdated JS libraries which often have known CVEs.
- Use **Target > Scope** to define the target and then run **Active Scan** which includes JS analysis.
- In **Proxy > HTTP History**, filter responses by MIME type "script" to focus on JavaScript files only, then manually review each.

## Tools
- Burp Suite Pro (Search, JS Miner extension)
- truffleHog (https://github.com/trufflesecurity/trufflehog) — secret scanner
- gitleaks — scan JS/HTML files for secrets
- SecretFinder (https://github.com/m4ll0k/SecretFinder) — JS secret scanner
- nuclei with `exposures/tokens` templates
- semgrep — pattern-based code scanning
- git-secrets — prevent committing secrets

## Remediation
- Never include API keys or secrets in API responses returned to clients — filter sensitive fields before serialization.
- Store API keys server-side only; never embed them in client-side JavaScript.
- Use a secrets management solution (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault) instead of hardcoding keys.
- Implement API response serialization with explicit field allowlisting (not denylist).
- Rotate any exposed keys immediately upon discovery.
- Add pre-commit hooks using gitleaks or git-secrets to prevent accidental key commits.
- Use environment variables for secrets, not configuration files checked into version control.

## References
https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/01-Information_Gathering/
https://portswigger.net/web-security/information-disclosure
https://cwe.mitre.org/data/definitions/312.html
https://github.com/trufflesecurity/trufflehog
https://github.com/m4ll0k/SecretFinder
https://owasp.org/www-community/vulnerabilities/Insecure_Storage_of_Sensitive_Information
