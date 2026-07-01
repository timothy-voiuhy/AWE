# Version Disclosure (Headers, Meta Tags)

## Overview
Version disclosure occurs when a web server, framework, CMS, or application reveals the exact software version it is running through HTTP response headers, HTML meta tags, error pages, or embedded comments. While version disclosure alone is an informational finding, it becomes critical when combined with public exploit databases — an attacker who knows the exact version can trivially search for and apply known vulnerabilities without needing to discover them independently, dramatically reducing the time to exploit.

## How It Works
Web server software includes version strings in default configurations as a courtesy to administrators. Apache includes version and OS information in the `Server` header and in error pages. PHP adds an `X-Powered-By: PHP/8.1.12` header by default. WordPress embeds `<meta name="generator" content="WordPress 6.4.2">` in HTML. Content Management Systems and frameworks announce their presence and version in consistent, well-known locations. Attackers cross-reference these versions against CVE databases, public exploit repositories (ExploitDB, Metasploit), and PoC code on GitHub.

## Impact
- Identify known CVEs applicable to the exact software version
- Select pre-written exploits from ExploitDB, Metasploit, or GitHub without needing to discover the vulnerability from scratch
- Prioritize targets: an application running a 3-year-old unpatched version is more likely to be vulnerable
- Enumerate the full technology stack for attack surface mapping
- Identify EOL software versions with no available patches

## Where to Look
- `Server` HTTP response header (Apache, Nginx, IIS, Lighttpd)
- `X-Powered-By` header (PHP, ASP.NET, Express.js)
- `X-AspNet-Version`, `X-AspNetMvc-Version` headers
- `X-Generator` header
- HTML `<meta name="generator">` tags
- HTML comments containing CMS or framework version strings
- JavaScript files with version comments at the top
- CSS files with version strings in comments
- `/robots.txt` (some CMS put version info or version-specific paths)
- `CHANGELOG`, `VERSION`, `README` files accessible from web root
- Error pages (Apache default 404, 403, 500 pages include server version)
- API response `X-API-Version` or similar headers
- Cookie names (e.g., `JSESSIONID` = Java/Tomcat, `PHPSESSID` = PHP, `ASP.NET_SessionId` = .NET)
- Form field hidden inputs (Rails authenticity token patterns, etc.)

## Testing Steps
1. Make a basic GET request to the target and inspect all response headers.
2. Trigger default error pages (404, 403, 500) and check for version info in the body.
3. View HTML source of the main page and search for `generator`, `version`, `powered by`, `CMS`.
4. Check `/robots.txt` for CMS-specific paths that reveal the CMS type and version.
5. Look for `CHANGELOG`, `VERSION`, `RELEASE_NOTES`, `readme.html`, `readme.txt` in common locations.
6. Cross-reference all found versions against:
   - https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=SOFTWARE+VERSION
   - https://www.exploit-db.com/search?q=SOFTWARE+VERSION
   - https://nvd.nist.gov/vuln/search
7. Note all technology stack components with versions for the final report.

## Payloads / Techniques

```bash
# Inspect all response headers for version info
curl -s -I "https://target.com/" | grep -iE "(server|x-powered-by|x-generator|x-aspnet|via|x-runtime)"

# Full request with verbose headers
curl -s -v "https://target.com/" 2>&1 | grep -E "^<" | grep -iE "(server|powered|generator|version)"

# Trigger 404 and check for version in body
curl -s "https://target.com/NONEXISTENT_PAGE_12345" | grep -iE "(apache|nginx|iis|php|version)"

# Check HTML meta tags
curl -s "https://target.com/" | grep -i "meta.*generator\|generator.*content"

# Check common CMS version files
for file in readme.html readme.txt CHANGELOG.txt VERSION.txt license.txt wp-links-opml.php; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/$file")
  if [ "$code" = "200" ]; then
    echo "[FOUND] https://target.com/$file"
    curl -s "https://target.com/$file" | head -10
  fi
done

# WordPress version detection
curl -s "https://target.com/wp-includes/version.php" 2>/dev/null
curl -s "https://target.com/feed/" | grep "generator"
curl -s "https://target.com/?v=VERSION" # CSS/JS versioned query string
# Read: https://target.com/readme.html
# Check: https://target.com/wp-includes/css/dashicons.min.css?ver=X.X.X

# Joomla version
curl -s "https://target.com/administrator/manifests/files/joomla.xml"
curl -s "https://target.com/language/en-GB/en-GB.xml"

# Drupal version
curl -s "https://target.com/CHANGELOG.txt"
curl -s "https://target.com/core/CHANGELOG.txt"

# phpMyAdmin version
curl -s "https://target.com/phpmyadmin/README"
curl -s "https://target.com/pma/README"

# Magento version
curl -s "https://target.com/magento_version"

# Jenkins version
curl -s -I "https://target.com/" | grep "X-Jenkins"

# Apache Tomcat version
curl -s "https://target.com/nonexistent" | grep "Apache Tomcat"
```

```
# Common version-disclosing headers:
Server: Apache/2.4.51 (Ubuntu)
Server: nginx/1.18.0
Server: Microsoft-IIS/10.0
Server: Apache-Coyote/1.1
X-Powered-By: PHP/7.4.3
X-Powered-By: ASP.NET
X-AspNet-Version: 4.0.30319
X-AspNetMvc-Version: 5.2
X-Generator: Drupal 9 (https://www.drupal.org)
X-Pingback: https://target.com/xmlrpc.php
X-Drupal-Cache: HIT
X-Joomla-Module-Position: head

# HTML meta generator examples:
<meta name="generator" content="WordPress 6.4.2" />
<meta name="generator" content="Joomla! - Open Source Content Management" />
<meta name="generator" content="Drupal 9 (https://www.drupal.org)" />
<meta name="generator" content="TYPO3 CMS" />
<meta name="generator" content="Hugo 0.115.4" />

# CMS-specific HTML patterns:
# WordPress
<link rel='stylesheet' href='/wp-content/themes/...' />
<script src='/wp-includes/js/...' />

# Joomla
<link href="/media/system/css/system.css" />

# Drupal
<meta name="Generator" content="Drupal 9 (https://www.drupal.org)" />
<html lang="en" dir="ltr" prefix="og: https://ogp.me/ns# ...">
```

```bash
# Cross-reference version against known exploits
# After finding: Apache 2.4.49

searchsploit "Apache 2.4.49"
# or
curl -s "https://www.exploit-db.com/search?q=Apache+2.4.49&type=webapps" | grep -i "CVE\|Remote Code"

# Check NVD for CVEs
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Apache+2.4.49&resultsPerPage=5" | \
  python3 -m json.tool | grep -i "id\|description"

# WhatWeb — technology fingerprinting
whatweb "https://target.com" -v

# Wappalyzer equivalent (cli)
webanalyze -host "https://target.com"
```

## Burp Suite Tips
- In **Proxy > HTTP History**, click the **Headers** tab of any response and look for Server, X-Powered-By, and generator headers.
- Use **Search** (Ctrl+Shift+F) with the term `X-Powered-By` across all response headers.
- Run **Active Scanner** (Pro) — it includes technology fingerprinting and version detection.
- The **Software Vulnerability Scanner** BApp cross-references detected versions against CVE databases.
- **Retire.js** extension scans JavaScript files for known vulnerable library versions automatically.
- **Wappalyzer** browser extension (use alongside Burp) identifies technology stack in real-time.

## Tools
- Burp Suite Pro (Scanner, Retire.js extension, Software Vulnerability Scanner)
- WhatWeb (https://github.com/urbanadventurer/WhatWeb) — CMS/framework fingerprinting
- Wappalyzer — browser extension and CLI
- Nikto — version detection in headers and error pages
- searchsploit / ExploitDB — cross-reference versions to exploits
- nuclei with `technologies/` templates
- nmap with `-sV --script http-headers,http-generator`

## Remediation
- Apache: Set `ServerTokens Prod` and `ServerSignature Off` in `httpd.conf`.
- Nginx: Set `server_tokens off;` in `nginx.conf`.
- PHP: Set `expose_php = Off` in `php.ini` to remove `X-Powered-By: PHP/...`.
- ASP.NET: Remove `X-AspNet-Version` and `X-AspNetMvc-Version` headers in `web.config`.
- WordPress: Remove the generator meta tag in `functions.php`: `remove_action('wp_head', 'wp_generator');`
- Remove `CHANGELOG.txt`, `readme.html`, `VERSION` files from production web roots.
- Keep software up to date so version disclosure provides less exploitable information even when present.
- Use a WAF to strip identifying headers.

## References
https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server
https://portswigger.net/web-security/information-disclosure
https://cwe.mitre.org/data/definitions/200.html
https://httpd.apache.org/docs/2.4/mod/core.html#servertokens
https://www.cvedetails.com/
https://www.exploit-db.com/
