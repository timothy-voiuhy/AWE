# OAuth2 / OIDC Misconfiguration

## Overview
OAuth2 is an authorization delegation framework widely used for "Login with Google/GitHub/Facebook" and API access delegation. OpenID Connect (OIDC) extends OAuth2 for authentication. Misconfigurations in redirect URI validation, state parameter handling, token leakage, and scope management frequently lead to account takeover, authorization code theft, and CSRF on the OAuth flow. These vulnerabilities are common because the specification is complex and implementations often take shortcuts.

## How It Works
- **Authorization Code Flow**: User is redirected to the provider, grants consent, provider redirects back with a code, client exchanges code for tokens. Flaws include open redirect in `redirect_uri`, missing `state` parameter (CSRF), and code interception.
- **Implicit Flow (deprecated)**: Access token returned directly in the URL fragment — logged in browser history, Referer headers, and proxy logs.
- **redirect_uri validation bypass**: The authorization server improperly validates the redirect URI, allowing the code to be sent to an attacker-controlled URL.
- **Missing state parameter**: Without `state`, an attacker can initiate an OAuth flow and trick the victim's browser into completing it (OAuth CSRF), linking the victim's account to the attacker's external identity.
- **Token leakage**: Tokens in URL fragments, logged in access logs, or returned in the body via Referer headers.
- **Scope escalation**: Requesting broader scopes than necessary, or the server not enforcing requested vs. granted scopes.

## Impact
- Account takeover via authorization code theft (redirected to attacker's domain).
- Account takeover via OAuth CSRF (linking attacker's identity to victim's account).
- Token theft from Referer headers, browser history, or server logs.
- Privilege escalation via scope manipulation.
- Persistent access via refresh token theft.

## Where to Look
- The authorization endpoint URL: check `redirect_uri` parameter for validation weakness.
- The `state` parameter: is it present, unique, and validated?
- The `response_type` parameter: `token` (implicit) vs. `code` (authorization code).
- Token storage: localStorage vs. sessionStorage vs. httpOnly cookie.
- OIDC `nonce` parameter: prevents ID token replay — is it validated?
- The client_secret: is it exposed in JavaScript, mobile APKs, or public repositories?
- Refresh token handling: expiry, single-use enforcement, revocation on logout.
- PKCE implementation for public clients.

## Testing Steps
1. Capture the full OAuth authorization request and inspect: `client_id`, `redirect_uri`, `response_type`, `scope`, `state`.
2. Verify the `state` parameter: is it present? Is it unique per request? Is it validated on callback? Remove it and complete the flow — if it succeeds, CSRF is possible.
3. Test `redirect_uri` validation: change it to `https://attacker.com` — does the server reject it? Try subdomain variants: `https://attacker.legitimate.com`, `https://legitimate.com.attacker.com`, `https://legitimate.com/callback/../redirect?url=https://attacker.com`.
4. Test open redirect chaining: if the app has an open redirect at `/redirect?url=`, use `redirect_uri=https://legitimate.com/redirect?url=https://attacker.com`.
5. Check for implicit flow (`response_type=token`): if available, the token appears in the URL fragment.
6. Test scope escalation: add higher-privilege scopes not shown in the consent screen.
7. Check the `client_secret` in the application's JavaScript source, mobile APK, or GitHub.
8. Attempt CSRF: initiate an OAuth flow on your attacker account, capture the authorization URL before completion, and trick the victim into visiting it.
9. Test the PKCE implementation (for public clients): remove `code_challenge` or use a trivial value.

## Payloads / Techniques

OAuth CSRF attack URL (missing state):
```
https://auth.target.com/oauth/authorize?
  client_id=CLIENT_ID&
  redirect_uri=https://app.target.com/callback&
  response_type=code&
  scope=openid+email
```
Victim visits this URL → their browser completes the flow → attacker's identity linked to victim.

redirect_uri bypass attempts:
```
redirect_uri=https://attacker.com
redirect_uri=https://attacker.com%2F@legitimate.com/callback
redirect_uri=https://legitimate.com.attacker.com/callback
redirect_uri=https://legitimate.com/callback%2F..%2F..%2Fattacker.com
redirect_uri=https://legitimate.com/callback?x=1&redirect=https://attacker.com
redirect_uri=https://legitimate.com@attacker.com
redirect_uri=//attacker.com
```

Open redirect chaining:
```
redirect_uri=https://legitimate.com/redirect?next=//attacker.com
```

Scope escalation:
```
# Original request: scope=read
# Modified: scope=read+write+admin
scope=openid+email+profile+https://api.target.com/admin
```

Steal code via Referer (if redirect_uri page loads external resources):
```
# If the callback page at https://app.target.com/callback?code=XXXX
# loads external JS or images, the code appears in Referer headers
# to those external servers
```

Test implicit flow:
```
response_type=token
# Token returned in URL fragment: #access_token=XXX
```

PKCE downgrade (for public clients):
```bash
# Remove code_challenge and code_challenge_method
# If server still issues token, PKCE is not enforced
curl -X POST https://auth.target.com/oauth/token \
  -d "grant_type=authorization_code&code=AUTH_CODE&client_id=CLIENT_ID&redirect_uri=https://app.target.com/callback"
```

## Burp Suite Tips
- Use **Proxy** to capture the full OAuth flow; map all endpoints: `/authorize`, `/token`, `/userinfo`, `/introspect`, `/revoke`.
- In **Repeater**, test redirect_uri variations on the `/authorize` endpoint — a 302 redirect response with `Location: attacker.com` confirms the bypass.
- The **OWTF OAuth** or **OAuth Scanner** Burp extensions automate common OAuth misconfiguration checks.
- Use **Collaborator** as the attacker's server to receive stolen authorization codes via redirect.
- Test the `state` parameter: in the callback request in Repeater, try removing it or replacing it with a static value — if the server accepts it without error, CSRF is confirmed.
- Check the response to `/oauth/token` for excessive token information (refresh tokens, internal claims) in the body.

## Tools
- **Burp Suite** — Full OAuth flow interception and parameter manipulation.
- **oauth2-testing-tools** — Purpose-built scripts for OAuth vulnerability assessment.
- **jwt.io** — Decode and inspect OIDC ID tokens and access tokens.
- **Postman** — OAuth flow testing with built-in OAuth2 helper.
- **truffleHog / gitleaks** — Scan repos for exposed client_secrets.
- **Nuclei** — Templates for common OAuth2 misconfigurations.

## Remediation
- Validate `redirect_uri` against an exact allowlist of pre-registered URIs — no partial matching, wildcard domains, or URL parsing.
- Enforce the `state` parameter as a CSRF token: generate a cryptographically random value, store it in the session, and validate it on callback.
- Use Authorization Code flow with PKCE for all public clients (mobile, SPA); never use implicit flow for new implementations.
- Store tokens in `httpOnly`, `Secure`, `SameSite=Strict` cookies — not localStorage where XSS can steal them.
- Validate the `nonce` in OIDC ID tokens to prevent replay attacks.
- Rotate client secrets regularly; never expose them in client-side JavaScript or public code repositories.
- Implement the principle of least privilege for scopes; validate that granted scopes match requested scopes.
- Set short access token lifetimes (15–60 minutes); use refresh tokens with rotation and revocation.

## References
https://portswigger.net/web-security/oauth
https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/05-Testing_for_Cross_Site_Request_Forgery
https://datatracker.ietf.org/doc/html/rfc6819
https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html
https://portswigger.net/research/hidden-oauth-attack-vectors
