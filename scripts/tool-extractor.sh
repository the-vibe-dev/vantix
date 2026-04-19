#!/usr/bin/env bash
# tool-extractor.sh — Opponent artifact extraction and analysis
#
# Pulls files left by opponents on a KotH/CTF target (or analyzes a local dir),
# runs static analysis on each, and generates a structured report that is ingested
# by learn_engine.py as source_kind=opponent_tool.
#
# Usage:
#   # Pull from live target
#   tool-extractor.sh -t 10.10.10.5 -i /tmp/id_rsa [-u root] [--strace] [--session SESSION_ID]
#
#   # Analyze a local directory you already captured
#   tool-extractor.sh -d /tmp/captured_tools [--session SESSION_ID]
#
# Output: ${CTF_ROOT:-.}/memory/opponent_tools/<session>/<ts>/
#   opponent_tool_report_<ts>.md   — human-readable analysis
#   <binary>.analysis              — per-file detail

set -euo pipefail

CTF_ROOT="${CTF_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
LEARN_ENGINE="$CTF_ROOT/scripts/learn_engine.py"
OUT_BASE="$CTF_ROOT/memory/opponent_tools"

TARGET_IP=""
SSH_KEY=""
SSH_USER="root"
LOCAL_DIR=""
SESSION_ID=""
DO_STRACE=false
STRINGS_MIN=8
MAX_BINARY_MB=10

# ── arg parsing ───────────────────────────────────────────────────────────────
usage() {
  grep '^#' "$0" | head -20 | sed 's/^# \?//'
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -t|--target)     TARGET_IP="$2"; shift 2 ;;
    -i|--identity)   SSH_KEY="$2";   shift 2 ;;
    -u|--user)       SSH_USER="$2";  shift 2 ;;
    -d|--dir)        LOCAL_DIR="$2"; shift 2 ;;
    --session)       SESSION_ID="$2"; shift 2 ;;
    --strace)        DO_STRACE=true;  shift ;;
    -h|--help)       usage ;;
    *) echo "[!] Unknown flag: $1"; usage ;;
  esac
done

if [[ -z "$TARGET_IP" && -z "$LOCAL_DIR" ]]; then
  echo "[!] Provide -t TARGET_IP or -d LOCAL_DIR"
  exit 1
fi

[[ -z "$SESSION_ID" ]] && SESSION_ID="ext-$(date +%Y%m%d-%H%M%S)"
TS=$(date +%Y%m%d-%H%M%S)
OUT_DIR="$OUT_BASE/$SESSION_ID/$TS"
mkdir -p "$OUT_DIR"

REPORT="$OUT_DIR/opponent_tool_report_$TS.md"
WORK_DIR="/tmp/tool_extractor_$$"
mkdir -p "$WORK_DIR"
cleanup() { rm -rf "$WORK_DIR"; }
trap cleanup EXIT

ssh_run() {
  local cmd="$1"
  if [[ -n "$SSH_KEY" ]]; then
    ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o BatchMode=yes \
        -o ConnectTimeout=10 "${SSH_USER}@${TARGET_IP}" "$cmd" 2>/dev/null
  else
    ssh -o StrictHostKeyChecking=no -o BatchMode=yes \
        -o ConnectTimeout=10 "${SSH_USER}@${TARGET_IP}" "$cmd" 2>/dev/null
  fi
}

ssh_pull() {
  local src="$1" dst="$2"
  if [[ -n "$SSH_KEY" ]]; then
    scp -i "$SSH_KEY" -o StrictHostKeyChecking=no \
        "${SSH_USER}@${TARGET_IP}:${src}" "$dst" 2>/dev/null
  else
    scp -o StrictHostKeyChecking=no \
        "${SSH_USER}@${TARGET_IP}:${src}" "$dst" 2>/dev/null
  fi
}

# ── collect files ─────────────────────────────────────────────────────────────
echo "[*] tool-extractor: session=$SESSION_ID target=${TARGET_IP:-local} out=$OUT_DIR"

if [[ -n "$TARGET_IP" ]]; then
  echo "[*] Probing target for recent/unusual artifacts..."
  # Find: recently modified files + world-writable dirs that look like drops
  FIND_CMD='find /tmp /dev/shm /var/tmp /run /var/run /dev/mqueue \
    \( -name "*.sh" -o -name "*.py" -o -name "*.pl" -o -name "*.rb" \
       -o -type f -newer /proc/1/exe -perm /111 \) \
    -not -path "*/proc/*" -not -path "*/sys/*" -size -'"${MAX_BINARY_MB}"'M \
    -printf "%T@ %s %p\n" 2>/dev/null | sort -rn | head -60'
  FILE_LIST=$(ssh_run "$FIND_CMD" || true)

  # Also check crontabs for injected entries
  CRON_DUMP=$(ssh_run 'crontab -l 2>/dev/null; cat /etc/cron.d/* 2>/dev/null; cat /var/spool/cron/crontabs/* 2>/dev/null' || true)

  # Check for unusual processes
  PROC_SNAP=$(ssh_run 'ps auxf 2>/dev/null || ps aux 2>/dev/null' || true)

  # Save proc/cron snapshots
  echo "$CRON_DUMP" > "$OUT_DIR/cron_snapshot.txt"
  echo "$PROC_SNAP" > "$OUT_DIR/proc_snapshot.txt"

  # Pull each found binary
  PULLED=0
  while IFS= read -r entry; do
    [[ -z "$entry" ]] && continue
    fpath=$(echo "$entry" | awk '{print $3}')
    [[ -z "$fpath" ]] && continue
    fname=$(basename "$fpath")
    dst="$WORK_DIR/$fname"
    if ssh_pull "$fpath" "$dst" 2>/dev/null; then
      echo "[+] Pulled: $fpath"
      PULLED=$((PULLED + 1))
    fi
  done <<< "$FILE_LIST"
  echo "[*] Pulled $PULLED files from target"
else
  # Local dir mode: just copy everything
  cp -r "$LOCAL_DIR"/. "$WORK_DIR/" 2>/dev/null || true
  CRON_DUMP=""
  PROC_SNAP=""
fi

# ── per-file analysis ─────────────────────────────────────────────────────────
{
  echo "# Opponent Tool Analysis Report"
  echo ""
  echo "- session: $SESSION_ID"
  echo "- target: ${TARGET_IP:-local:$LOCAL_DIR}"
  echo "- ts: $TS"
  echo "- operator: $(whoami)@$(hostname)"
  echo ""
  echo "## Summary"
  echo ""
} > "$REPORT"

TOOL_COUNT=0
declare -A SUSPECTED_TOOLS=()

KNOWN_TOOL_PATTERNS=(
  "king-protect:flag-defender"
  "protectking:flag-defender"
  "chisel:tunnel-tool"
  "ligolo:tunnel-tool"
  "pwncat:shell-tool"
  "msfvenom:framework-tool"
  "metasploit:framework-tool"
  "socat:relay-tool"
  "ncat:relay-tool"
  "netcat:relay-tool"
  "mimikatz:cred-dumper"
  "lazagne:cred-dumper"
  "linpeas:enum-tool"
  "winpeas:enum-tool"
  "linenum:enum-tool"
  "linux-exploit-suggester:enum-tool"
  "dirty_cow:kernel-exploit"
  "dirtypipe:kernel-exploit"
)

for binary in "$WORK_DIR"/*; do
  [[ -f "$binary" ]] || continue
  fname=$(basename "$binary")
  sha256=$(sha256sum "$binary" | awk '{print $1}')
  ftype=$(file -b "$binary" 2>/dev/null || echo "unknown")
  fsize=$(stat -c%s "$binary" 2>/dev/null || echo "?")
  is_elf=false
  is_script=false
  [[ "$ftype" == *"ELF"* ]] && is_elf=true
  [[ "$ftype" == *"script"* || "$ftype" == *"text"* ]] && is_script=true

  analysis_file="$OUT_DIR/${fname}.analysis"
  TOOL_COUNT=$((TOOL_COUNT + 1))

  {
    echo "## File: $fname"
    echo ""
    echo "- sha256: $sha256"
    echo "- type: $ftype"
    echo "- size_bytes: $fsize"
    echo ""
  } >> "$REPORT"

  {
    echo "# $fname"
    echo "sha256: $sha256"
    echo "type: $ftype"
    echo "size: $fsize bytes"
    echo ""
  } > "$analysis_file"

  # Strings extraction
  INTERESTING_STRINGS=""
  if command -v strings &>/dev/null; then
    INTERESTING_STRINGS=$(strings -n "$STRINGS_MIN" "$binary" 2>/dev/null | \
      grep -Ei '(http|ftp|ssh|/bin/|/etc/|king|root|flag|password|token|secret|eval|exec|system|socket|connect|127\.0\.0\.1|0\.0\.0\.0|cve-|exploit|payload|shell|backdoor|nc -|bash -i|socat|chisel|ligolo)' \
      | head -40 || true)
  fi

  # Tool family identification
  SUSPECTED_FAMILY="unknown"
  raw_strings_lower=$(strings -n 4 "$binary" 2>/dev/null | tr '[:upper:]' '[:lower:]' || true)
  for pattern_entry in "${KNOWN_TOOL_PATTERNS[@]}"; do
    kw="${pattern_entry%%:*}"
    family="${pattern_entry##*:}"
    if echo "$raw_strings_lower" | grep -q "$kw"; then
      SUSPECTED_FAMILY="$family"
      SUSPECTED_TOOLS["$family"]="$fname"
      break
    fi
  done
  # Also check filename
  fname_lower=$(echo "$fname" | tr '[:upper:]' '[:lower:]')
  for pattern_entry in "${KNOWN_TOOL_PATTERNS[@]}"; do
    kw="${pattern_entry%%:*}"
    family="${pattern_entry##*:}"
    if [[ "$fname_lower" == *"$kw"* ]]; then
      SUSPECTED_FAMILY="$family"
      SUSPECTED_TOOLS["$family"]="$fname"
      break
    fi
  done

  # ELF headers
  ELF_INFO=""
  if $is_elf && command -v readelf &>/dev/null; then
    ELF_INFO=$(readelf -h "$binary" 2>/dev/null | grep -E '(Type:|Machine:|Entry point)' | head -5 || true)
    IMPORTS=$(readelf -d "$binary" 2>/dev/null | grep NEEDED | head -10 || true)
  fi

  # Entropy check (rough: check for high-entropy sections suggesting packing)
  PACKED_HINT=""
  if $is_elf && command -v objdump &>/dev/null; then
    # Count sections with suspicious names
    suspicious_sections=$(objdump -h "$binary" 2>/dev/null | grep -cE '(UPX|\.packed|\.vmp|\.themida)' || true)
    suspicious_sections="${suspicious_sections//[^0-9]/}"
    [[ -n "$suspicious_sections" && "$suspicious_sections" -gt 0 ]] && PACKED_HINT="[PACKED/OBFUSCATED - suspicious sections detected]"
  fi

  # Extract IPs/URLs/ports from strings
  NETWORK_IOCS=$(strings -n 4 "$binary" 2>/dev/null | \
    grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}(:[0-9]+)?|https?://[^ ]+|[0-9]{4,5}/tcp|:[0-9]{2,5}' \
    | sort -u | head -20 || true)

  # Write analysis file
  {
    echo "## Suspected tool family: $SUSPECTED_FAMILY"
    echo ""
    echo "## Interesting strings"
    echo "$INTERESTING_STRINGS"
    echo ""
    echo "## Network IOCs"
    echo "${NETWORK_IOCS:-none}"
    echo ""
    if $is_elf; then
      echo "## ELF headers"
      echo "$ELF_INFO"
      echo ""
      echo "## Dynamic imports"
      echo "${IMPORTS:-none}"
      echo ""
    fi
    [[ -n "$PACKED_HINT" ]] && echo "## Packing: $PACKED_HINT"
  } >> "$analysis_file"

  # Append to main report
  {
    echo "### Suspected family: $SUSPECTED_FAMILY"
    if [[ -n "$INTERESTING_STRINGS" ]]; then
      echo ""
      echo "**Notable strings:**"
      echo '```'
      echo "$INTERESTING_STRINGS"
      echo '```'
    fi
    if [[ -n "$NETWORK_IOCS" ]]; then
      echo ""
      echo "**Network IOCs:** \`${NETWORK_IOCS//$'\n'/ | }\`"
    fi
    [[ -n "$PACKED_HINT" ]] && echo ""  && echo "**$PACKED_HINT**"
    echo ""
    # Counter-technique suggestion
    case "$SUSPECTED_FAMILY" in
      flag-defender)
        echo "**Counter-technique:** Mask/stop the service via systemd before claiming. Use kothholder.sh --hijack-service to overwrite service definition."
        ;;
      tunnel-tool)
        echo "**Counter-technique:** Kill chisel/ligolo processes (pkill -f chisel); block their port if firewall is permitted; monitor /proc for reconnect."
        ;;
      shell-tool)
        echo "**Counter-technique:** Kill pwncat process; check for persistence in cron/systemd; verify authorized_keys was not injected."
        ;;
      cred-dumper)
        echo "**Counter-technique:** Rotate all credentials immediately; review /etc/shadow and authorized_keys for changes."
        ;;
      enum-tool)
        echo "**Counter-technique:** Monitor /tmp and /dev/shm; note enumeration timing — opponent may be escalating soon."
        ;;
      kernel-exploit)
        echo "**Counter-technique:** Check kernel version; if vuln matches, patch or place decoy. Monitor for privilege escalation."
        ;;
      *)
        echo "**Counter-technique:** Perform manual strings review in ${fname}.analysis; correlate with known CVEs."
        ;;
    esac
    echo ""
    echo "---"
    echo ""
  } >> "$REPORT"

  # Optional strace (sandboxed)
  if $DO_STRACE && command -v firejail &>/dev/null; then
    echo "[*] strace (sandboxed) on $fname..."
    strace_out=$(timeout 5 firejail --net=none strace -f -e trace=network,file "$binary" 2>&1 | head -50 || true)
    echo "### strace (sandboxed, 5s)" >> "$REPORT"
    echo '```' >> "$REPORT"
    echo "$strace_out" >> "$REPORT"
    echo '```' >> "$REPORT"
    echo "" >> "$REPORT"
  fi
done

# ── cron/proc analysis section ────────────────────────────────────────────────
if [[ -n "$CRON_DUMP" ]]; then
  {
    echo "## Cron Entries (at time of capture)"
    echo ""
    echo '```'
    echo "$CRON_DUMP"
    echo '```'
    echo ""
    SUSPICIOUS_CRON=$(echo "$CRON_DUMP" | grep -Ei '(king|echo|root|/tmp|/dev/shm|bash -i|nc |socat|python|perl)' || true)
    if [[ -n "$SUSPICIOUS_CRON" ]]; then
      echo "**Suspicious cron entries detected:**"
      echo '```'
      echo "$SUSPICIOUS_CRON"
      echo '```'
      echo ""
      echo "**Counter-technique:** Remove with crontab -r (all) or edit specific entry; also check /var/spool/cron/crontabs/root."
    fi
    echo ""
  } >> "$REPORT"
fi

# ── summary section ───────────────────────────────────────────────────────────
{
  echo "## Tool Inventory"
  echo ""
  echo "- total_files_analyzed: $TOOL_COUNT"
  if [[ ${#SUSPECTED_TOOLS[@]} -gt 0 ]]; then
    echo "- identified_families:"
    for family in "${!SUSPECTED_TOOLS[@]}"; do
      echo "  - $family: ${SUSPECTED_TOOLS[$family]}"
    done
  else
    echo "- identified_families: none matched known patterns"
  fi
  echo ""
  echo "## What worked / What to absorb"
  echo ""
  echo "- Reviewing opponent tools gives us their persistence and hold patterns."
  echo "- Each identified tool family maps to a counter-technique in this report."
  echo "- Run learn_engine.py ingest to absorb this report into vectors/guardrails."
  echo ""
} >> "$REPORT"

echo "[+] Report: $REPORT"
echo "[+] Analysis files: $OUT_DIR/"

# ── learn_engine ingest ───────────────────────────────────────────────────────
if [[ -f "$LEARN_ENGINE" ]]; then
  echo "[*] Ingesting into learn_engine..."
  python3 "$LEARN_ENGINE" \
    --root "$CTF_ROOT" \
    ingest \
    --session-id "$SESSION_ID" \
    --source-path "$REPORT" \
    --generate-reports \
    2>&1 | tail -3
fi

echo "[+] tool-extractor complete. Session: $SESSION_ID"
