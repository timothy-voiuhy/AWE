# Integer Overflow / Underflow in Business Logic

## Overview
Integer overflow occurs when an arithmetic operation produces a value exceeding the maximum size of the integer type used to store it, causing it to wrap around to a negative or very large number. In business logic, this manifests in price calculations, quantity handling, wallet balances, and reward points — potentially allowing attackers to get products for negative prices, generate massive account credits, or bypass quantity limits.

## How It Works
- **32-bit integer max**: 2,147,483,647. Adding 1 gives -2,147,483,648 (wrap-around).
- If `total_price = quantity × unit_price` is computed in a 32-bit integer, a sufficiently large quantity overflows to a negative total.
- **Wallet balance abuse**: Spending more than your balance wraps around to a very large positive number.
- **Quantity limit bypass**: A maximum quantity check of `qty <= MAX_INT` can be bypassed by sending a negative quantity that passes the check but behaves unexpectedly.
- **Negative quantity**: Ordering -1 items in a shopping cart reduces the total by the item price rather than adding.

## Impact
- Obtaining products for zero or negative prices.
- Generating massive account credits from a small balance.
- Bypassing quantity purchase limits.
- Financial system manipulation.

## Where to Look
- Shopping cart quantity fields.
- Price calculation endpoints.
- Wallet/credit balance operations (deposits, withdrawals, transfers).
- Reward point accumulation and redemption.
- Voting, like, or count systems with per-user limits.
- File size or resource allocation checks.

## Testing Steps
1. Add an item to the cart and change the quantity to a very large number (2147483647, 2147483648, 4294967295).
2. Check if the total price overflows to a negative number or zero.
3. Try a negative quantity (-1, -100) — does the cart accept it and subtract from total?
4. In a wallet system, try transferring more money than your balance — does the balance wrap?
5. Try sending 0 quantity — does the endpoint accept it?
6. Test with quantities as strings: `"1e10"`, `"1.5"` (float injection into integer field).
7. Try sending JSON numbers exceeding 64-bit max: `99999999999999999999`.
8. Test reward point redemption: redeem more points than you have.

## Payloads / Techniques
```bash
# Large quantity order
curl -s -X POST https://target.com/api/cart/add \
  -H "Content-Type: application/json" \
  -H "Cookie: session=VALID_SESSION" \
  -d '{"product_id": 1, "quantity": 2147483647}'

# Negative quantity
curl -s -X POST https://target.com/api/cart/add \
  -H "Content-Type: application/json" \
  -d '{"product_id": 1, "quantity": -1}'

# Zero quantity
curl -s -X POST https://target.com/api/cart/add \
  -H "Content-Type: application/json" \
  -d '{"product_id": 1, "quantity": 0}'

# Float injection for integer field
curl -s -X POST https://target.com/api/cart/add \
  -H "Content-Type: application/json" \
  -d '{"product_id": 1, "quantity": 1.9}'
# If server floor()s to 1 but logs 1.9, inconsistency

# Transfer more than balance
curl -s -X POST https://target.com/api/wallet/transfer \
  -H "Content-Type: application/json" \
  -d '{"to": "victim@target.com", "amount": 99999999999}'
# If balance is stored as 32-bit, overflow gives negative balance → possible free credit

# Price manipulation: if price is sent client-side
curl -s -X POST https://target.com/api/checkout \
  -H "Content-Type: application/json" \
  -d '{"cart_id": "123", "total": -100}'
```

## Burp Suite Tips
- In **Repeater**, modify quantity/amount fields to extreme values (large positive, negative, zero, floats).
- Use **Intruder** to fuzz numeric fields with boundary values: 0, 1, -1, 2147483647, 2147483648, 9999999999.
- Intercept checkout flow in **Proxy** and modify price/total fields if they appear in the request.

## Tools
- Burp Suite Repeater + Intruder
- curl for direct API testing

## Remediation
- Use arbitrary-precision arithmetic (BigDecimal/Decimal) for financial calculations.
- Validate all numeric inputs server-side: minimum 1 for quantities, positive values for amounts.
- Never trust client-supplied price or total — always recalculate on the server.
- Store monetary values as cents (integers) or use database decimal types, never floats.
- Implement server-side balance checks using database transactions with row-level locking.
- Cap maximum values on all quantity and amount fields.

## References
https://portswigger.net/web-security/logic-flaws
https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/05-Test_for_Integer_Overflow
https://cwe.mitre.org/data/definitions/190.html
