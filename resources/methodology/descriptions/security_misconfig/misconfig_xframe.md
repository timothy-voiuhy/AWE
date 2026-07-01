# Clickjacking — Missing X-Frame-Options / CSP frame-ancestors

## Overview
Clickjacking (UI redress attack) tricks users into clicking on hidden interface elements by overlaying the target site in a transparent iframe. Without `X-Frame-Options` or CSP `frame-ancestors` headers preventing framing, an attacker can embed the victim's authenticated session in a malicious page, tricking them into performing actions like changing account settings, making purchases, or transferring funds.

## How It Works
- Attacker creates a malicious page that embeds the target site in a transparent iframe (`opacity: 0`).
- The iframe is positioned over a "decoy" UI element on the attacker's page.
- When the victim clicks the decoy button, they are actually clicking a button in the hidden iframe within their authenticated session.
- The action executes in the victim's session context without their awareness.

## Impact
- Forced clicks on privileged actions (account deletion, payment confirmation, admin actions).
- Changing security settings (email, password, 2FA devices) without victim's knowledge.
- "Likejacking" — forced social media likes, shares, or follows.
- Leaking sensitive information from the UI via pixel-perfect attacks.
- Combining with CSRF for compounded attacks.

## Where to Look
- Check for `X-Frame-Options: DENY` or `X-Frame-Options: SAMEORIGIN` in all page responses.
- Check CSP for `frame-ancestors 'self'` or `frame-ancestors 'none'`.
- If neither header is present, the page can be framed.
- Test particularly on sensitive pages: account settings, password change, payment confirmation.

## Testing Steps
1. Check response headers for `X-Frame-Options` and `Content-Security-Policy: frame-ancestors`.
2. If absent, create a test HTML page with an iframe pointing to the target:
3. Open the test page in a browser and check if the target page loads in the iframe.
4. If the site loads → clickjacking is possible.
5. Test sensitive pages: `/account/settings`, `/change-password`, `/delete-account`, `/checkout`.
6. Identify which actions can be triggered with a single click (most dangerous).

## Payloads / Techniques
```html
<!-- Basic clickjacking PoC -->
<!DOCTYPE html>
<html>
<head>
<style>
  iframe {
    position: absolute;
    top: 0; left: 0;
    width: 1000px; height: 800px;
    opacity: 0.1;  /* Set to 0 for real attack, 0.1 to see overlay */
    z-index: 2;
    border: none;
  }
  .decoy-button {
    position: absolute;
    top: 300px; left: 200px;
    z-index: 1;
    padding: 10px 20px;
    background: #28a745;
    color: white;
    font-size: 16px;
    cursor: pointer;
  }
</style>
</head>
<body>
  <div class="decoy-button">Click here to WIN a prize!</div>
  <iframe src="https://target.com/account/settings"></iframe>
</body>
</html>
```

```html
<!-- Dragging clickjacking PoC (drag actions) -->
<div style="position:absolute;top:100px;left:100px;">
  <div id="drag" draggable="true" style="background:red;padding:20px;z-index:10">
    Drag this
  </div>
</div>
<iframe src="https://target.com/upload" style="opacity:0.1;position:absolute;top:100px"></iframe>
```

## Burp Suite Tips
- **Clickbandit** tool in Burp Suite (Pro) — automatically generates a clickjacking PoC by recording click positions on the target page and overlaying them.
- **Active Scanner** (Pro) reports missing `X-Frame-Options` / CSP `frame-ancestors`.
- In **Repeater**, check response headers for frame-blocking directives.
- The **Clickjacking** BApp extension provides automated PoC generation.

## Tools
- Burp Suite Clickbandit (built-in, Pro)
- PoC HTML (manual construction as above)
- Security Headers — https://securityheaders.com/

## Remediation
- Add `X-Frame-Options: DENY` to all page responses (blocks all framing):
  Or `X-Frame-Options: SAMEORIGIN` (allows framing from same origin only).
- Prefer CSP `frame-ancestors` over `X-Frame-Options` (more flexible and modern):
  `Content-Security-Policy: frame-ancestors 'none'` (no framing allowed)
  `Content-Security-Policy: frame-ancestors 'self'` (same-origin only)
- Apply at web server/reverse proxy level for consistency.
- Do NOT rely solely on JavaScript framebusting code — it's easily bypassed.

## References
https://portswigger.net/web-security/clickjacking
https://owasp.org/www-community/attacks/Clickjacking
https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html
https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
