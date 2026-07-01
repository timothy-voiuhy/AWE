# Coupon and Discount Code Abuse

## Overview
Coupon and discount code abuse exploits weaknesses in how applications validate and apply promotional codes. Vulnerabilities include codes that can be reused indefinitely, applied multiple times per order, brute-forced due to predictable formats, combined in unauthorized ways, or applied to items they were not intended for. These represent business logic flaws that bypass the commercial intent of the promotion system.

## How It Works
- **Reuse after cancellation**: Apply coupon, cancel the order, and the coupon remains in some "applied" state.
- **Stack multiple coupons**: Apply multiple codes simultaneously if the API doesn't enforce single-code limits.
- **Race condition abuse**: Simultaneously submit multiple order requests all referencing the same single-use coupon.
- **Brute force**: Try sequential or pattern-based codes: `SAVE10`, `SAVE11`, `SAVE12`, or `DISC2024`.
- **Self-referral abuse**: Use your own referral code on a second account you control.
- **Negative total**: Stack discounts until the order total becomes negative or zero, potentially triggering a credit.

## Impact
- Direct financial loss to the business.
- Free products or services.
- Unauthorized credit accumulation.
- Competitor price manipulation.
- Reputation damage if abuse is widespread.

## Where to Look
- `/api/cart/apply-coupon`, `/checkout/coupon`, `/promo/apply`
- Coupon application endpoints in cart and checkout flows.
- Order confirmation flows that credit/debit accounts.
- Referral program endpoints.
- Flash sale and limited-time offer systems.

## Testing Steps
1. Apply a valid coupon, complete the order, then try applying the same coupon code again.
2. Apply a coupon, then cancel/abandon the order — retry the coupon on a new order.
3. Try applying the same coupon code twice in the same cart before checkout.
4. If there's a "one coupon per order" rule, try two Burp Repeater tabs applying different coupons simultaneously (race condition).
5. Brute force coupon codes: `SAVE5`, `SAVE10`, `SAVE15`, `DISCOUNT20`, `WELCOME10`.
6. Test if expired coupon codes still work (replay).
7. Try applying employee discount codes found in JavaScript source or error messages.
8. Test if the minimum order value is enforced (apply coupon then reduce cart below minimum).
9. Apply a coupon to an order, get the discount, then change items to higher-value items without re-validation.

## Payloads / Techniques
```bash
# Brute force common coupon patterns
for code in SAVE5 SAVE10 SAVE15 SAVE20 SAVE25 SAVE30 SAVE50 \
            DISCOUNT10 DISCOUNT20 WELCOME10 FIRST10 VIP20 \
            PROMO2024 SUMMER2024 WINTER2024 FLASH50; do
  curl -s -X POST https://target.com/api/coupon/apply \
    -H "Content-Type: application/json" \
    -H "Cookie: session=YOUR_SESSION" \
    -d "{\"code\": \"$code\", \"cart_id\": \"CART_ID\"}" | \
    grep -i "discount\|valid\|success"
  echo "Tested: $code"
done

# Race condition: apply same coupon simultaneously
# Using Burp Suite Turbo Intruder:
# or
for i in {1..10}; do
  curl -s -X POST https://target.com/api/coupon/apply \
    -H "Content-Type: application/json" \
    -d '{"code":"SINGLE-USE-CODE","cart_id":"123"}' &
done
wait
```

## Burp Suite Tips
- Use **Intruder** to brute-force coupon codes with a wordlist of common patterns.
- Use **Turbo Intruder** (BApp Store) for race condition testing — send 50+ requests simultaneously.
- In **Repeater**, replay the coupon application request after order completion to check for reuse.
- Use **Logger++** (BApp) to log all coupon-related requests for analysis.

## Tools
- Burp Suite Intruder + Turbo Intruder
- curl with `&` for parallel requests (basic race condition testing)
- Custom Python script using `asyncio` for precise race condition attacks

## Remediation
- Mark single-use coupons as redeemed immediately upon application, not upon order completion.
- Implement server-side rate limiting on coupon application (e.g., 3 per session per hour).
- Use cryptographically random coupon codes (not sequential or pattern-based).
- Enforce minimum order values, user eligibility, and product category restrictions server-side.
- Use database-level locks or transactions when applying coupons to prevent race conditions.
- Log all coupon usage attempts with user ID, IP, and timestamps for fraud detection.

## References
https://portswigger.net/web-security/logic-flaws
https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/
https://portswigger.net/web-security/race-conditions
