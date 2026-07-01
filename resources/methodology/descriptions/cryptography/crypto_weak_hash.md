# Weak Hashing (MD5, SHA1 for Passwords)

## Overview
Password hashing is the practice of transforming a password into a fixed-length digest that is stored instead of the plaintext password. When weak hashing algorithms — such as MD5, SHA1, or unsalted SHA256 — are used for password storage, attackers who obtain the hash database can recover the original passwords through precomputed rainbow tables, dictionary attacks, or brute force at extremely high speeds. Modern graphics cards can compute billions of MD5 or SHA1 hashes per second, making these algorithms entirely unsuitable for password storage regardless of input length.

## How It Works
General-purpose cryptographic hash functions (MD5, SHA1, SHA256) are designed to be fast — their speed is a feature for their intended use cases (file integrity, digital signatures). For password hashing, speed is a liability: the faster the hash, the faster an attacker can try candidate passwords against a stolen hash.

The attack chain:

1. Attacker gains access to the database (via SQL injection, backup exposure, insider threat, etc.).
2. Attacker exports the hashes.
3. If MD5/SHA1/SHA2 without salt: attacker runs hashes against precomputed rainbow tables (instant lookup) or a wordlist through hashcat at billions of hash-per-second speed.
4. If unsalted: identical passwords produce identical hashes, leaking which users share a password and enabling single-hash-to-many-account cracking.
5. If salted SHA256/SHA512 but not iterative: still crackable at high speed (GPU hashcat benchmarks ~10 billion SHA256/s on a mid-range GPU). With bcrypt (cost 12), the same GPU only manages ~200 hashes/s.

**MD5-specific issues beyond speed:** MD5 is cryptographically broken — collision attacks are practical. An attacker can craft two different inputs with the same MD5 hash, which has implications for any use of MD5 as an integrity check.

**SHA1-specific issues:** SHA1 was deprecated by NIST in 2011. Practical collision attacks (SHAttered, 2017) exist. Similarly broken for integrity use cases.

## Impact
- Mass password recovery from stolen databases within hours (MD5/SHA1, even salted).
- Credential stuffing: recovered passwords tried against other services where users reuse passwords.
- Account takeover of high-value accounts (admin, payment, executive).
- Regulatory violation: GDPR Article 32, PCI DSS Requirement 8, NIST SP 800-63B all require suitable password hashing.
- Reputational damage when a breach reveals weak password storage.
- If passwords are used to derive encryption keys: plaintext recovery of encrypted data.

## Where to Look
- Database schemas: look for columns named `password`, `pass`, `pwd`, `hash`, `passwd`.
- Application source code: search for references to MD5/SHA1/SHA256 in authentication code.
- Password reset functionality: some apps re-hash and return the "old password" hint, revealing the hashing scheme.
- Hash format in database dumps: MD5 = 32 hex chars, SHA1 = 40 hex chars, SHA256 = 64 hex chars, bcrypt = `$2b$`/`$2a$`, scrypt = `$s0$`, argon2 = `$argon2`.
- Login error messages that reveal timing differences (faster for wrong password on short hash lookup vs. constant-time comparison).
- Password change endpoints: if the server accepts the current password and the response is suspiciously fast, it may be doing a direct hash comparison without key-stretching delay.
- Forgot password flows that email the actual password (impossible with proper hashing — this reveals plaintext storage).
- API responses from admin endpoints that expose user records including hash fields.

## Testing Steps
1. If you have access to a database dump or SQLi, extract password hash values and observe their format/length.
2. Identify the hash type from format: 32 chars = likely MD5, 40 = SHA1, 64 = SHA256, `$2b$` prefix = bcrypt, `$argon2` = argon2.
3. Use `hash-identifier` or `hashid` tool to confirm the hash algorithm.
4. Test a known password on the application, then check if the stored hash matches `echo -n "password" | md5sum`.
5. Test for lack of salting: create two accounts with the same password — if their stored hashes are identical, no per-user salt is used.
6. If hash is unsalted MD5/SHA1: look up the hash in online databases (CrackStation, hashes.com) — common passwords may crack instantly.
7. Use Hashcat to attempt offline cracking against a wordlist.
8. Check the application's password policy — if it accepts very short or dictionary passwords, the hashing choice matters even more.
9. Review server-side code for hashing functions: `md5()`, `sha1()`, `hash('sha1', ...)`, `MessageDigest.getInstance("MD5")`.
10. Test timing of login requests: bcrypt should take ~200-500ms; MD5/SHA1 is sub-millisecond.

## Payloads / Techniques

```bash
# Identify hash type from a sample hash
hash-identifier 5f4dcc3b5aa765d61d8327deb882cf99
# or
hashid "5f4dcc3b5aa765d61d8327deb882cf99"

# Check if "password" hashes to the observed value (unsalted MD5 verification)
echo -n "password" | md5sum
# 5f4dcc3b5aa765d61d8327deb882cf99  -- confirms MD5("password")

echo -n "password" | sha1sum
# 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8 -- confirms SHA1("password")

# Online hash lookup (for common passwords — do this manually in browser)
# https://crackstation.net/
# https://hashes.com/en/decrypt/hash
# https://www.md5online.org/

# Hashcat — crack MD5 hashes with rockyou wordlist
hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt

# Hashcat — crack unsalted MD5 with rules
hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Hashcat — crack SHA1 hashes
hashcat -m 100 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt

# Hashcat — crack salted MD5 (format: hash:salt)
hashcat -m 10 -a 0 "5f4dcc3b5aa765d61d8327deb882cf99:somesalt" /usr/share/wordlists/rockyou.txt

# Hashcat — crack SHA256
hashcat -m 1400 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt

# Hashcat — crack bcrypt (slow — for context/demo only)
hashcat -m 3200 -a 0 bcrypt_hashes.txt /usr/share/wordlists/rockyou.txt

# John the Ripper — auto-detect and crack
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

# John — show cracked passwords
john --show hashes.txt

# Generate MD5 rainbow table lookup payload (test if app uses unsalted MD5)
python3 -c "
import hashlib
test_passwords = ['password', '123456', 'admin', 'letmein', 'welcome', 'monkey', 'dragon']
for p in test_passwords:
    md5 = hashlib.md5(p.encode()).hexdigest()
    sha1 = hashlib.sha1(p.encode()).hexdigest()
    print(f'{p}: MD5={md5}, SHA1={sha1}')
"

# Timing test: compare login response times to infer hashing algorithm
# bcrypt: expect ~200-500ms response time
# MD5/SHA1: expect <10ms response time
for i in $(seq 1 5); do
  time curl -s -X POST https://target.example.com/login \
    -d '{"username":"testuser","password":"wrongpassword"}' \
    -H "Content-Type: application/json" > /dev/null
done

# Check for password in forgot-password email (tests for plaintext storage)
# If the application emails you your actual password, it is stored in plaintext or reversibly encrypted
```

```python
# Check bcrypt implementation in Python (correct approach)
import bcrypt
import hashlib
import time

password = b"password123"

# WRONG - MD5 (milliseconds, no salt)
start = time.time()
md5_hash = hashlib.md5(password).hexdigest()
print(f"MD5: {md5_hash} ({(time.time()-start)*1000:.3f}ms)")

# CORRECT - bcrypt (hundreds of milliseconds, includes salt)
start = time.time()
bcrypt_hash = bcrypt.hashpw(password, bcrypt.gensalt(rounds=12))
print(f"bcrypt: {bcrypt_hash.decode()} ({(time.time()-start)*1000:.3f}ms)")
```

## Burp Suite Tips
- In **Proxy > HTTP History**, look at registration and login requests. If the client-side JavaScript is hashing the password before transmission (client-side MD5 is a red flag), you will see a fixed-length hex string sent instead of the raw password.
- Use Burp **Decoder** to test hash values: paste a candidate hash and use "Smart decode" to check encoding. Then manually compute `md5("password")` and compare.
- Send a login request to **Repeater** and try submitting a known MD5 or SHA1 hash directly as the password field — some poorly designed apps do the hashing on the client side and accept the hash as the "password."
- Use **Intruder** with a list of known MD5 hashes (generated from common passwords) if the application appears to accept pre-hashed values.
- Check the **Response** body in Repeater after registration — some apps return the stored credential representation in the response, which may reveal the hash format.
- In the **Target > Site Map**, right-click and use **Engagement Tools > Search** to look for `md5`, `sha1`, `sha256`, `hash` in JavaScript source files.

## Tools
- hashcat — https://hashcat.net/hashcat/
- John the Ripper — https://www.openwall.com/john/
- hash-identifier — included in Kali Linux
- hashid — https://github.com/psypanda/hashID
- CrackStation — https://crackstation.net/ (online lookup)
- hashes.com — https://hashes.com/en/decrypt/hash (online lookup)
- haiti — https://github.com/noraj/HAITI (hash type identifier)
- Burp Suite (timing analysis, Decoder)

## Remediation
- Use a purpose-built password hashing algorithm: **bcrypt** (work factor 12+), **scrypt**, **Argon2id** (recommended by OWASP and NIST SP 800-63B), or **PBKDF2-HMAC-SHA256** with at least 310,000 iterations.
- Never use MD5, SHA1, SHA256, or SHA512 directly for password hashing.
- Always use a unique, cryptographically random salt per user (bcrypt, scrypt, and Argon2 handle this automatically).
- If upgrading from weak hashes: implement an upgrade-on-login strategy — when a user logs in with a correct password, immediately re-hash with the strong algorithm and update the stored hash.
- Enforce a minimum password length of at least 8 characters; longer is better.
- Store only the hash — never the plaintext, and never with reversible encryption (which stores the key alongside).
- Do not perform any password transformation (lowercase, trim) before hashing — hash the password as the user typed it.
- Implement pepper (server-side secret added to the hash input) as a defence-in-depth measure.

## References
https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
https://owasp.org/www-community/vulnerabilities/Insecure_Randomness
https://pages.nist.gov/800-63-3/sp800-63b.html
https://portswigger.net/web-security/authentication/password-based
https://hashcat.net/wiki/doku.php?id=hashcat
https://www.openwall.com/john/
https://password-hashing.net/
https://argon2.online/
