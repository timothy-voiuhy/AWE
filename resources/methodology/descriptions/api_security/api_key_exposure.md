# API Key Exposure

## Overview
API keys provide machine-to-machine authentication and authorize access to services, data, and actions. When keys are exposed in JavaScript source code, HTML comments, git repositories, error messages, or API responses, attackers gain unauthorized access to third-party services (payment processors, cloud providers, communication platforms), internal APIs, and can incur substantial costs or cause data breaches.

## How It Works
- API keys hardcoded in client-side JavaScript are sent to every browser that loads the page.
- Keys committed to public GitHub repositories are indexed by search engines and tools like GitLeaks.
- Keys included in error messages or debug output expose credentials to users.
- Keys returned in API responses (e.g., third-party service keys in a settings endpoint).
- Keys in `/.env` files accidentally deployed to production web-accessible directories.
- Keys in minified JS bundles that attackers can de-obfuscate.
- Mobile app API keys extracted from APK/IPA binaries.

## Impact
- Unauthorized access to third-party services (Stripe, Twilio, SendGrid, AWS, Google Maps).
- Financial charges to the victim's accounts (paid API calls).
- Data exfiltration via cloud storage or database APIs.
- Sending emails/SMS from the victim's account (phishing, spam).
- Accessing internal APIs with authentication bypass.
- Lateral movement from third-party service to internal systems.

## Where to Look
- JavaScript source files (main.js, app.bundle.js, vendor.js).
- HTML source comments.
- `/.env`, `/.env.local`, `/.env.production`, `/.gitignore`, `/.git/config`.
- Error pages and debug output.
- API responses containing configuration or settings.
- GitHub organization repositories (search for `target.com + apikey`).
- Browser network requests to third-party services.

## Testing Steps
1. View page source and search for: `key`, `token`, `secret`, `api_key`, `password`, `Bearer`, `Authorization`.
2. Download JavaScript bundle files and search for patterns: `[A-Za-z0-9]{32,}` (long random strings).
3. Check `/.env`, `/.env.production`, `/.env.local` directly.
4. Check `/.git/config` — if git is exposed, clone the repo and search history.
5. Search GitHub: `site:github.com target.com "api_key"`, `site:github.com target.com "aws_access_key"`.
6. Check network requests in browser DevTools for API keys in request parameters or headers.
7. Try error-triggering requests — check if stack traces reveal API keys.
8. Inspect mobile apps: extract APK → `strings classes.dex | grep -i "key\|token\|secret"`.

## Payloads / Techniques
```bash
# Check for .env file exposure
curl -s https://target.com/.env | grep -i "key\|secret\|password\|token"
curl -s https://target.com/.env.local
curl -s https://target.com/.env.production

# Download and search JavaScript bundles
# First get the page source and extract JS file URLs:
curl -s https://target.com | grep -oE 'src="[^"]+\.js"' | sed 's/src="//' | sed 's/"//'
# Then for each JS file:
curl -s https://target.com/static/main.bundle.js | \
  grep -oE '([A-Za-z0-9_]+key|[A-Za-z0-9_]+token|[A-Za-z0-9_]+secret)["\s:=]+[A-Za-z0-9_\-]{20,}'

# AWS key patterns
grep -oE 'AKIA[0-9A-Z]{16}' *.js       # AWS Access Key ID
grep -oE '[0-9a-zA-Z/+]{40}' *.js       # AWS Secret (broad)

# Google API key patterns
grep -oE 'AIza[0-9A-Za-z_-]{35}' *.js

# Stripe patterns
grep -oE 'sk_live_[0-9a-zA-Z]{24}' *.js
grep -oE 'sk_test_[0-9a-zA-Z]{24}' *.js

# GitHub search dorks
# site:github.com "target.com" api_key
# site:github.com "target.com" "Authorization: Bearer"
# repo:targetorg/targetrepo "password"

# GitLeaks on cloned repo
gitleaks detect --source . --report-format json --report-path leaks.json

# TruffleHog
trufflehog git file://. --json
```

## Burp Suite Tips
- Use **Burp Search** across all responses for patterns: `apikey`, `api_key`, `secret`, `AKIA`.
- In **Engagement Tools → Find Scripts**, extract all JavaScript files for analysis.
- Check `.env` paths in the **Target → Site Map** after active scanning.

## Tools
- GitLeaks — https://github.com/gitleaks/gitleaks (secrets in git repos)
- TruffleHog — https://github.com/trufflesecurity/trufflehog
- gf patterns — https://github.com/tomnomnom/gf (grep-framework for common patterns)
- Shodan + GreyNoise for exposed keys in indexed services

## Remediation
- Never hardcode API keys in client-side code — use server-side proxying to third-party APIs.
- Store keys in environment variables, never in source code.
- Add secret detection to CI/CD pipeline (GitHub's secret scanning, pre-commit hooks with GitLeaks).
- Rotate any exposed key immediately and audit usage logs.
- Use scoped/restricted API keys — apply least-privilege to what each key can access.
- Add `.env` to `.gitignore` and ensure deployment processes don't copy it to web root.

## References
https://owasp.org/www-project-api-security/ (API8:2023 Security Misconfiguration)
https://portswigger.net/web-security/information-disclosure
https://trufflesecurity.com/blog/trufflehog-v3
https://github.com/gitleaks/gitleaks
