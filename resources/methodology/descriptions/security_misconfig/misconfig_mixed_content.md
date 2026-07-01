# Mixed Content (HTTP resources over HTTPS)

## Overview
Mixed content occurs when an HTTPS page loads sub-resources (scripts, stylesheets, images, iframes) over HTTP. "Active" mixed content (scripts, iframes) is blocked by modern browsers, but its presence indicates poor security hygiene. "Passive" mixed content (images, audio) may still load and can be tampered with by a MitM attacker. Mixed content undermines the HTTPS protection of the page.

## How It Works
- The page is served over HTTPS but references resources via `http://` URLs.
- A MitM attacker intercepts the HTTP resource request and serves malicious content (script, style, image).
- Even for passive content (images), a MitM can substitute the image or use it for tracking/fingerprinting.
- For active mixed content (scripts): if not blocked, a compromised script can fully control the page despite HTTPS.
- Browser console shows mixed content warnings; `Content-Security-Policy: upgrade-insecure-requests` can auto-upgrade.

## Impact
- MitM substitution of HTTP-loaded scripts → XSS on HTTPS page.
- Substitution of HTTP stylesheets → CSS injection / data exfiltration.
- Tracking via HTTP image requests on an ostensibly HTTPS page.
- Loss of user confidence and browser security indicators.
- Leakage of authenticated session data via HTTP referrer headers.

## Where to Look
- View browser developer console → Console tab for mixed content warnings.
- Look at page source for `http://` references in `<script>`, `<link>`, `<img>`, `<iframe>`, `<form>` tags.
- Check third-party scripts, analytics, and CDN resources.
- API calls from JavaScript code using hardcoded `http://` endpoints.
- Redirect chains that start at HTTPS but include HTTP intermediate steps.

## Testing Steps
1. Browse the site and open browser Developer Tools → Console tab.
2. Look for "Mixed Content" warnings — note which resources are HTTP.
3. In Burp, search HTTP History for requests from HTTPS pages that use `http://` resource URLs.
4. Check page source for `http://` in resource references.
5. Test CSP header: look for `upgrade-insecure-requests` directive.
6. Try submitting forms via HTTP to see if credentials are sent insecurely.
7. Check if the `Referer` header on HTTP resource requests leaks sensitive path/query info.

## Payloads / Techniques
```bash
# Check for mixed content via grep on page source
curl -s https://target.com | grep -oE 'src="http://[^"]+"|href="http://[^"]+"' | head -20

# Check CSP for upgrade-insecure-requests
curl -s -D - https://target.com | grep -i "content-security"

# Manual browser check
# Open DevTools → Network tab → filter by "http://"
# Open DevTools → Console tab → search "Mixed Content"
```

## Burp Suite Tips
- In **Proxy HTTP History**, filter requests by clicking on "https://target.com" pages and look for outgoing `http://` requests.
- **Active Scanner** (Pro) reports mixed content issues.
- Use **"Search"** in the Proxy history to find `http://` in response bodies.

## Tools
- Browser Developer Tools (Console + Network tabs)
- Mozilla Observatory — flags mixed content issues
- Security Headers — https://securityheaders.com/
- Why No Padlock — https://www.whynopadlock.com/ (external mixed content checker)

## Remediation
- Update all resource URLs from `http://` to `https://` or use protocol-relative `//` URLs.
- Add `Content-Security-Policy: upgrade-insecure-requests` to automatically upgrade HTTP sub-resource requests to HTTPS.
- Enable HSTS to prevent downgrade attacks.
- Audit third-party scripts and CDN links for HTTP references.
- Use a Content Security Policy to block loading of HTTP resources entirely.

## References
https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content
https://web.dev/mixed-content/
https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html
