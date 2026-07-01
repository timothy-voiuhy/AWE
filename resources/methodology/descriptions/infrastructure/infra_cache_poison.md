# Web Cache Poisoning

## Overview
Web cache poisoning abuses caching mechanisms to inject a malicious response that is subsequently served to other users from the cache. By identifying "unkeyed inputs" — request components that influence the response but are not included in the cache key — attackers can craft a request that causes the server to generate a poisoned response which is then cached and served to all future users requesting the same resource.

## How It Works
- Cache keys typically include: URL, query string, Host header.
- Unkeyed inputs (not in cache key but affect response): `X-Forwarded-Host`, `X-Forwarded-For`, `X-Original-URL`, custom headers.
- An attacker sends a request with a malicious `X-Forwarded-Host` header; the server reflects this host in the response (e.g., for CDN link generation).
- The response is cached because the cache key (URL) is unchanged.
- Subsequent legitimate users receive the poisoned response with the attacker-controlled content.
- Combined with XSS or CSRF, cache poisoning can affect all users site-wide.

## Impact
- Site-wide XSS affecting all users who load the cached resource.
- Reflected XSS converted to stored XSS via cache.
- Serving malicious JavaScript to all visitors.
- DoS via cached error responses.
- Phishing via cached redirects to attacker-controlled domains.

## Where to Look
- Caching headers in responses: `Cache-Control: public`, `X-Cache`, `Age`, `Cf-Cache-Status`.
- CDN-fronted applications (Cloudflare, CloudFront, Varnish, Fastly).
- Applications that reflect request headers in HTML or JavaScript responses.
- Import/script src values generated dynamically based on incoming headers.

## Testing Steps
1. Identify if caching is in use: look for `X-Cache: HIT`, `Age:`, `CF-Cache-Status:` headers.
2. Find unkeyed inputs: add headers like `X-Forwarded-Host: evil.com` and see if the response changes.
3. If the response reflects the injected header, the endpoint is a candidate for cache poisoning.
4. Add a cache-buster to your test requests: `?cachebuster=uniquevalue` (ensure you're not poisoning the real cache during testing).
5. Check if the cache responds with your poisoned response on the next request (without the header).
6. Escalate: inject XSS payload via the reflected header, poison the cache, and verify other sessions get the XSS.

## Payloads / Techniques
```bash
# Step 1: Test if response reflects X-Forwarded-Host
curl -s https://target.com/ \
  -H "X-Forwarded-Host: evil.com?cachebust=test123" \
  | grep -i "evil.com"

# Step 2: Test other unkeyed headers
for header in "X-Forwarded-Host" "X-Host" "X-Original-URL" "X-Rewrite-URL" \
              "X-Forwarded-Scheme" "X-Forwarded-Proto" "X-HTTP-Method-Override"; do
  echo -n "Testing $header: "
  curl -s https://target.com/?cb=$RANDOM \
    -H "$header: evil.com" | grep -c "evil.com"
done

# Step 3: Poison the cache with XSS
# If X-Forwarded-Host is reflected in a script src:
# Response: <script src="https://evil.com/static/app.js"></script>
# Host your malicious JS at evil.com/static/app.js then poison:
curl -s https://target.com/page \
  -H "X-Forwarded-Host: evil.com" \
  --head | grep -i "X-Cache"
# If response X-Cache: MISS → cache will store this response
# Next request from victim:
curl -s https://target.com/page  # Gets cached poisoned response

# Param Miner style: test all headers
# Use Burp Suite Param Miner BApp for automated unkeyed input discovery
```

## Burp Suite Tips
- **Param Miner** (BApp Store) — automatically discovers unkeyed headers that affect responses.
- In **Repeater**, add `X-Cache-Buster: {random}` as a query parameter to isolate your tests.
- Add headers one at a time and compare responses using **Comparer**.
- Monitor `X-Cache: HIT` vs `MISS` to understand when your poisoned response is cached.
- **Web Cache Deception** is related but different — involves tricking cache into storing private responses.

## Tools
- Param Miner (Burp BApp) — https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943
- curl — manual testing
- web-cache-vulnerability-scanner — https://github.com/Hackmanit/Web-Cache-Vulnerability-Scanner

## Remediation
- Remove or normalize unkeyed inputs that affect responses (don't reflect arbitrary headers in responses).
- Include all response-influencing request components in the cache key.
- Disable caching for responses that contain user-specific or header-reflected content.
- Use `Vary` header to include all response-varying request components in the cache key.
- Configure CDN to strip or normalize potentially dangerous headers before forwarding.

## References
https://portswigger.net/web-security/web-cache-poisoning
https://portswigger.net/research/practical-web-cache-poisoning
https://owasp.org/www-community/attacks/Cache_Poisoning
