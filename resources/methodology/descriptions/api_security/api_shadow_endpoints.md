# Undocumented / Shadow API Endpoints

## Overview
Shadow or undocumented API endpoints are routes that exist in the backend but are not listed in official API documentation. They may be leftover from old versions, internal debugging endpoints, endpoints used by mobile apps or microservices, or development endpoints never removed from production. These often have weaker authentication, authorization, and validation than documented endpoints.

## How It Works
- Development endpoints (`/api/test`, `/debug`, `/api/v1/internal`) remain in production.
- Old API version routes (`/api/v1/`) still work after `/api/v2/` was released — with weaker security.
- Endpoints documented for mobile apps differ from web app endpoints and may have different security controls.
- Admin endpoints exposed at predictable paths without proper authentication.
- Routes discoverable from JavaScript source code, mobile app decompilation, or API gateway config.
- `.bak`, `.old`, `.swp` file exposures reveal endpoint logic.

## Impact
- Access to admin functionality without proper authorization.
- Data exfiltration via data export or debug endpoints.
- Server-side actions (delete, modify) via old endpoints without modern security controls.
- Authentication bypass via old or debug endpoints that skip auth middleware.
- Information disclosure via debug/status endpoints.

## Where to Look
- JavaScript source files (API calls hardcoded in JS bundles).
- Mobile app APK/IPA decompilation.
- Web archive (Wayback Machine) for old endpoints.
- API gateway logs or documentation files left exposed.
- `robots.txt`, `sitemap.xml`, `.well-known/` directory.
- Error messages revealing internal paths.
- Common debug/test endpoint names.

## Testing Steps
1. Extract all API endpoint references from page JavaScript bundles.
2. Brute force API paths using common wordlists.
3. Test old API versions: if `/api/v2/` is current, test `/api/v1/`, `/api/v0/`, `/api/`.
4. Check for debug endpoints: `/debug`, `/health`, `/status`, `/metrics`, `/actuator`.
5. Test admin endpoints: `/api/admin`, `/internal/api`, `/management`, `/admin-api`.
6. Look at error responses — do they reveal path patterns in stack traces?
7. Check the Wayback Machine for the API: `web.archive.org/web/*/target.com/api/*`.
8. Decompile mobile apps and grep for `https://api.target.com/`.

## Payloads / Techniques
```bash
# Extract API endpoints from JavaScript
curl -s https://target.com/static/app.js | \
  grep -oE '"/api/[a-zA-Z0-9/_-]+"' | sort -u

# Brute force API paths
ffuf -u https://api.target.com/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/api-endpoints.txt \
  -mc 200,201,401,403 -o ffuf_api.txt

# Test API version enumeration
for ver in v0 v1 v2 v3 old beta internal; do
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    https://api.target.com/api/$ver/)
  echo "/api/$ver/: HTTP $status"
done

# Common debug/admin endpoints
for path in health status debug metrics actuator admin internal management \
            test dev console swagger api-docs openapi.json v3/api-docs; do
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    https://target.com/$path)
  echo "/$path: HTTP $status"
done

# Spring Boot Actuator endpoints
for ep in env beans mappings health metrics httptrace logfile heapdump threaddump; do
  curl -s https://target.com/actuator/$ep | head -5
done

# Wayback Machine endpoint discovery
curl -s "https://web.archive.org/cdx/search/cdx?url=target.com/api/*&output=text&fl=original" | \
  awk -F'/' '{print $4}' | sort -u
```

## Burp Suite Tips
- Use **Content Discovery** (Active Scan sub-feature) to brute force hidden paths.
- **Spider** the application and check the site map for discovered routes.
- In **Target → Engagement Tools → Discover Content**, run discovery against the `/api/` path.
- Extract JS files and use **Search** to find API endpoint patterns.
- **Param Miner** (BApp) can discover hidden API endpoints via parameter fuzzing.

## Tools
- ffuf — https://github.com/ffuf/ffuf (fast web fuzzer)
- gobuster — directory brute forcing
- Arjun — https://github.com/s0md3v/Arjun (parameter discovery)
- SecLists API wordlists: `/usr/share/seclists/Discovery/Web-Content/`
- Wayback Machine CDX API

## Remediation
- Maintain a complete inventory of all API endpoints and decommission unused ones.
- Remove development and debug endpoints before deploying to production.
- Apply consistent authentication middleware to all routes, not just listed endpoints.
- Implement an API gateway that enforces authentication on all routes.
- Conduct periodic API audits to discover orphaned endpoints.
- Version all APIs and have a formal deprecation and removal process.

## References
https://owasp.org/www-project-api-security/ (API9:2023 Improper Inventory Management)
https://portswigger.net/web-security/api-testing
https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/
