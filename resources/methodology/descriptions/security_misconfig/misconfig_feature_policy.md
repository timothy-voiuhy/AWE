# Permissions-Policy Missing / Overly Permissive

## Overview
The `Permissions-Policy` header (formerly `Feature-Policy`) controls which browser features and APIs are available to the page and its embedded iframes. Without this header, third-party content embedded in iframes can access powerful browser features (camera, microphone, geolocation, payment, USB) without restriction — creating privacy and security risks, especially on pages with third-party embeds.

## How It Works
- Without a `Permissions-Policy`, browsers apply default behavior — some features are available to top-level documents and some are restricted to cross-origin iframes.
- If the application embeds third-party content via iframe, that content may attempt to access device features.
- An overly permissive policy (`Permissions-Policy: camera=*, microphone=*`) allows any iframe to access these features.
- Malicious third-party content (compromised analytics, ad networks) can silently access sensitive APIs if the policy doesn't restrict them.

## Impact
- Unauthorized camera/microphone access by malicious third-party scripts.
- Geolocation data leakage to embedded third-party services.
- Payment handler abuse via compromised embedded content.
- USB device enumeration by malicious embeds.
- Clipboard access by third-party scripts (clipboard hijacking).

## Where to Look
- `Permissions-Policy` header in HTTP responses (note: formerly `Feature-Policy`).
- Pages with embedded iframes (maps, video players, payment forms, analytics widgets).
- Pages that load third-party JavaScript.
- Mobile web apps that might access device sensors.

## Testing Steps
1. Check for `Permissions-Policy` header in page responses.
2. If absent → default browser behavior applies (check MDN for defaults).
3. If present, analyze each directive for overly permissive values (`*` allows all origins).
4. Identify which potentially sensitive features are used legitimately.
5. Test in browser: check if `navigator.getUserMedia()` works from an embedded iframe.
6. Check if the policy restricts features not used by the application.

## Payloads / Techniques
```bash
# Check Permissions-Policy header
curl -s -D - https://target.com/ | grep -i permissions-policy
curl -s -D - https://target.com/ | grep -i feature-policy

# Good Permissions-Policy example (restrictive):
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=(), fullscreen=(self)
# () = blocked for all, (self) = only this origin, (*) = all origins

# Test in browser console if a feature is available:
# navigator.geolocation.getCurrentPosition(pos => console.log(pos))
# navigator.mediaDevices.getUserMedia({video: true}).then(s => console.log("camera:", s))
```

## Burp Suite Tips
- Check `Permissions-Policy` in response headers in the Proxy history.
- **Active Scanner** (Pro) reports missing security headers including Permissions-Policy.
- Security Headers check via Mozilla Observatory.

## Tools
- Browser Developer Tools
- Mozilla Observatory — https://observatory.mozilla.org/
- Security Headers — https://securityheaders.com/

## Remediation
- Add a restrictive `Permissions-Policy` header that disables unused features:
  `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=(), autoplay=(), fullscreen=(self)`
- Explicitly allow only the features your application needs.
- Apply `allow="..."` attribute on individual `<iframe>` tags for fine-grained control.
- Review what browser features third-party embeds need and restrict accordingly.

## References
https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy
https://developer.chrome.com/en/docs/privacy-sandbox/permissions-policy/
https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration
