#!/usr/bin/env bash
# binary-re.sh — Static binary analysis wrapper
#
# Runs a binary through available RE tools and extracts intelligence:
# file type, hashes, interesting strings, ELF/PE headers, entropy, radare2 analysis,
# optional Ghidra headless analysis, optional sandboxed strace execution.
# Output feeds into learn_engine as source_kind=artifact.
#
# Usage:
#   binary-re.sh -f /tmp/suspicious_binary
#   binary-re.sh -f ./app --r2
#   binary-re.sh -f ./exploit.bin --ghidra /opt/ghidra --sandbox
#   binary-re.sh -f ./tool -t 10.10.10.5   # tags report to target

set -euo pipefail

CTF_ROOT="${CTF_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
LEARN_ENGINE="$CTF_ROOT/scripts/learn_engine.py"
ARTIFACTS_ROOT="$CTF_ROOT/artifacts"

BINARY=""
TARGET_IP=""
REQUIRE_R2=false
GHIDRA_HOME=""
DO_SANDBOX=false
SESSION_ID=""
STRINGS_MIN=8

usage() {
  grep '^#' "$0" | head -15 | sed 's/^# \?//'
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -f|--file)      BINARY="$2";       shift 2 ;;
    -t|--target)    TARGET_IP="$2";    shift 2 ;;
    --r2)           REQUIRE_R2=true;   shift ;;
    --ghidra)       GHIDRA_HOME="$2";  shift 2 ;;
    --sandbox)      DO_SANDBOX=true;   shift ;;
    --session)      SESSION_ID="$2";   shift 2 ;;
    -h|--help)      usage ;;
    *) echo "[!] Unknown flag: $1"; usage ;;
  esac
done

[[ -z "$BINARY" ]] && { echo "[!] -f BINARY required"; exit 1; }
[[ ! -f "$BINARY" ]] && { echo "[!] File not found: $BINARY"; exit 1; }

[[ -z "$SESSION_ID" ]] && SESSION_ID="re-$(date +%Y%m%d-%H%M%S)"
TS=$(date +%Y%m%d-%H%M%S)
FNAME=$(basename "$BINARY")
SAFE_TARGET="${TARGET_IP//./_}"
OUT_DIR="$ARTIFACTS_ROOT/${SAFE_TARGET:-unknown}/binary_re"
mkdir -p "$OUT_DIR"
REPORT="$OUT_DIR/${TS}_${FNAME}_analysis.md"

echo "[*] binary-re: $BINARY -> $REPORT"

# ── step 1: identification ────────────────────────────────────────────────────
FTYPE=$(file -b "$BINARY" 2>/dev/null || echo "unknown")
SHA256=$(sha256sum "$BINARY" | awk '{print $1}')
MD5=$(md5sum "$BINARY" | awk '{print $1}')
FSIZE=$(stat -c%s "$BINARY" 2>/dev/null || echo "?")
IS_ELF=false
IS_PE=false
[[ "$FTYPE" == *"ELF"* ]] && IS_ELF=true
[[ "$FTYPE" == *"PE32"* || "$FTYPE" == *"MS-DOS executable"* ]] && IS_PE=true

{
  echo "# Binary Analysis: $FNAME"
  echo ""
  echo "## Identification"
  echo ""
  echo "- file: $FNAME"
  echo "- type: $FTYPE"
  echo "- sha256: $SHA256"
  echo "- md5: $MD5"
  echo "- size: $FSIZE bytes"
  echo "- target: ${TARGET_IP:-unknown}"
  echo "- ts: $TS"
  echo ""
} > "$REPORT"

# ── step 2: strings extraction ────────────────────────────────────────────────
echo "[*] Extracting strings..."
ALL_STRINGS=$(strings -n "$STRINGS_MIN" "$BINARY" 2>/dev/null || true)

# Categorized string extraction
NETWORK_IOCS=$(echo "$ALL_STRINGS" | \
  grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}(:[0-9]+)?|https?://[^ ]+|[a-zA-Z0-9\-]+\.[a-z]{2,6}(/[^ ]*)?' | \
  grep -v '^\.' | sort -u | head -20 || true)
CRED_HINTS=$(echo "$ALL_STRINGS" | \
  grep -Ei '(password|passwd|secret|token|api.?key|apikey|credential|private.?key|auth)' | \
  head -15 || true)
PATH_REFS=$(echo "$ALL_STRINGS" | \
  grep -E '^(/[a-z]+){2,}|^[A-Z]:\\' | head -20 || true)
TOOL_SIGS=$(echo "$ALL_STRINGS" | \
  grep -Ei '(metasploit|meterpreter|cobalt.strike|empire|pwncat|chisel|ligolo|king|koth|flag|/root/|authorized_keys|ld.so.preload|/etc/shadow)' | \
  head -15 || true)
INTERESTING=$(echo "$ALL_STRINGS" | \
  grep -Ei '(http|ftp|ssh|/bin/|/etc/|eval|exec|system|socket|connect|bash|sh -i|nc -|socat|python -c|perl -e|cve-|exploit|payload|shellcode)' | \
  head -30 || true)

{
  echo "## String Analysis"
  echo ""
  if [[ -n "$TOOL_SIGS" ]]; then
    echo "### Tool Signatures (HIGH VALUE)"
    echo '```'
    echo "$TOOL_SIGS"
    echo '```'
    echo ""
  fi
  if [[ -n "$NETWORK_IOCS" ]]; then
    echo "### Network IOCs"
    echo '```'
    echo "$NETWORK_IOCS"
    echo '```'
    echo ""
  fi
  if [[ -n "$CRED_HINTS" ]]; then
    echo "### Credential Hints"
    echo '```'
    echo "$CRED_HINTS"
    echo '```'
    echo ""
  fi
  if [[ -n "$PATH_REFS" ]]; then
    echo "### Path References"
    echo '```'
    echo "$PATH_REFS"
    echo '```'
    echo ""
  fi
  if [[ -n "$INTERESTING" ]]; then
    echo "### Other Interesting Strings"
    echo '```'
    echo "$INTERESTING"
    echo '```'
    echo ""
  fi
} >> "$REPORT"

# ── step 3: ELF headers ───────────────────────────────────────────────────────
if $IS_ELF; then
  echo "[*] ELF analysis..."
  ELF_HEADER=$(readelf -h "$BINARY" 2>/dev/null | grep -E '(Type:|Machine:|Entry point|Class)' || true)
  SECTIONS=$(readelf -S "$BINARY" 2>/dev/null | grep -E '^\s+\[' | head -20 || true)
  DYNAMIC=$(readelf -d "$BINARY" 2>/dev/null | grep 'NEEDED' | head -15 || true)
  SYMBOLS=$(readelf -s "$BINARY" 2>/dev/null | grep -Ei '(main|exec|system|socket|connect|fork|bind|recv|send)' | head -20 || true)

  # Entropy heuristic: check for suspicious section names
  PACKED_SECTIONS=$(readelf -S "$BINARY" 2>/dev/null | grep -Ei '(upx|packed|vmp|themida|\.enigma|\.aspack)' || true)

  {
    echo "## ELF Headers"
    echo ""
    echo '```'
    echo "$ELF_HEADER"
    echo '```'
    echo ""
    echo "### Sections"
    echo '```'
    echo "$SECTIONS"
    echo '```'
    echo ""
    echo "### Dynamic Dependencies (NEEDED)"
    echo '```'
    echo "${DYNAMIC:-none}"
    echo '```'
    echo ""
    if [[ -n "$SYMBOLS" ]]; then
      echo "### Notable Symbol Exports"
      echo '```'
      echo "$SYMBOLS"
      echo '```'
      echo ""
    fi
    if [[ -n "$PACKED_SECTIONS" ]]; then
      echo "### PACKING DETECTED"
      echo '```'
      echo "$PACKED_SECTIONS"
      echo '```'
      echo ""
    fi
  } >> "$REPORT"
fi

# ── step 4: PE headers ────────────────────────────────────────────────────────
if $IS_PE && command -v objdump &>/dev/null; then
  echo "[*] PE analysis (objdump)..."
  PE_INFO=$(objdump -f "$BINARY" 2>/dev/null || true)
  PE_IMPORTS=$(objdump -p "$BINARY" 2>/dev/null | grep -A3 'DLL Name' | head -30 || true)
  {
    echo "## PE Headers"
    echo ""
    echo '```'
    echo "$PE_INFO"
    echo '```'
    echo ""
    echo "### DLL Imports"
    echo '```'
    echo "${PE_IMPORTS:-none}"
    echo '```'
    echo ""
  } >> "$REPORT"
fi

# ── step 5: radare2 ───────────────────────────────────────────────────────────
R2_AVAILABLE=false
command -v r2 &>/dev/null && R2_AVAILABLE=true
if $REQUIRE_R2 && ! $R2_AVAILABLE; then
  echo "[!] radare2 (r2) required but not installed. Install: apt install radare2"
  exit 1
fi
if $R2_AVAILABLE; then
  echo "[*] radare2 analysis..."
  R2_FUNCTIONS=$(timeout 60 r2 -A -q -c "afl~?" "$BINARY" 2>/dev/null | head -1 || echo "0")
  R2_TOP_FUNCS=$(timeout 60 r2 -A -q -c "afll~imp" "$BINARY" 2>/dev/null | head -20 || true)
  R2_IMPORTS=$(timeout 60 r2 -A -q -c "ii" "$BINARY" 2>/dev/null | head -30 || true)
  R2_STRINGS=$(timeout 60 r2 -A -q -c "izz~exec\|system\|socket\|connect\|king\|flag\|password" "$BINARY" 2>/dev/null | head -20 || true)
  {
    echo "## Radare2 Analysis"
    echo ""
    echo "- total_functions: $R2_FUNCTIONS"
    echo ""
    if [[ -n "$R2_TOP_FUNCS" ]]; then
      echo "### Imported Functions"
      echo '```'
      echo "$R2_TOP_FUNCS"
      echo '```'
      echo ""
    fi
    if [[ -n "$R2_IMPORTS" ]]; then
      echo "### All Imports"
      echo '```'
      echo "$R2_IMPORTS"
      echo '```'
      echo ""
    fi
    if [[ -n "$R2_STRINGS" ]]; then
      echo "### Strings matching dangerous patterns"
      echo '```'
      echo "$R2_STRINGS"
      echo '```'
      echo ""
    fi
  } >> "$REPORT"
fi

# ── step 6: Ghidra headless ───────────────────────────────────────────────────
if [[ -n "$GHIDRA_HOME" && -d "$GHIDRA_HOME" ]]; then
  echo "[*] Ghidra headless analysis..."
  GHIDRA_OUT="$OUT_DIR/ghidra_${FNAME}"
  mkdir -p "$GHIDRA_OUT"
  GHIDRA_SCRIPT="$GHIDRA_HOME/support/analyzeHeadless"
  if [[ -x "$GHIDRA_SCRIPT" ]]; then
    GHIDRA_LOG="$OUT_DIR/ghidra_${TS}.log"
    timeout 180 "$GHIDRA_SCRIPT" "$GHIDRA_OUT" "proj_$TS" \
      -import "$BINARY" -analysisTimeoutPerFile 120 \
      -log "$GHIDRA_LOG" -noanalysis 2>/dev/null || true
    FUNC_COUNT=$(grep -c 'Function:' "$GHIDRA_LOG" 2>/dev/null || echo "?")
    {
      echo "## Ghidra Headless"
      echo ""
      echo "- project: $GHIDRA_OUT"
      echo "- log: $GHIDRA_LOG"
      echo "- functions_found: $FUNC_COUNT"
      echo ""
    } >> "$REPORT"
  fi
fi

# ── step 7: sandboxed strace ──────────────────────────────────────────────────
if $DO_SANDBOX; then
  echo "[*] Sandboxed execution with strace..."
  STRACE_OUT=""
  if command -v firejail &>/dev/null; then
    STRACE_OUT=$(timeout 10 firejail --net=none --private-tmp \
      strace -f -e trace=network,file,process "$BINARY" 2>&1 | head -50 || true)
  elif command -v unshare &>/dev/null; then
    STRACE_OUT=$(timeout 10 unshare --net --fork \
      strace -f -e trace=network,file,process "$BINARY" 2>&1 | head -50 || true)
  else
    STRACE_OUT="[!] No sandbox available (firejail/unshare not found); skipping execution"
  fi
  {
    echo "## Sandboxed Execution (strace, 10s)"
    echo ""
    echo '```'
    echo "$STRACE_OUT"
    echo '```'
    echo ""
  } >> "$REPORT"
fi

# ── step 8: summary and counter-techniques ────────────────────────────────────
{
  echo "## Analysis Summary"
  echo ""
  # Infer likely purpose from strings
  PURPOSE="unknown"
  ALL_HIGH_VAL="$TOOL_SIGS $INTERESTING $NETWORK_IOCS"
  if echo "$ALL_HIGH_VAL" | grep -qi 'king\|koth\|flag'; then
    PURPOSE="KotH flag defender/attacker"
  elif echo "$ALL_HIGH_VAL" | grep -qi 'chisel\|ligolo\|tunnel'; then
    PURPOSE="Network tunnel tool"
  elif echo "$ALL_HIGH_VAL" | grep -qi 'pwncat\|bash -i\|nc -\|socat'; then
    PURPOSE="Reverse shell / callback tool"
  elif echo "$ALL_HIGH_VAL" | grep -qi 'meterpreter\|metasploit\|msfvenom'; then
    PURPOSE="Metasploit payload"
  elif echo "$ALL_HIGH_VAL" | grep -qi 'password\|shadow\|credential\|mimikatz'; then
    PURPOSE="Credential harvester"
  elif echo "$ALL_HIGH_VAL" | grep -qi 'linpeas\|linenum\|enum'; then
    PURPOSE="Privilege escalation enumerator"
  elif echo "$ALL_HIGH_VAL" | grep -qi 'ld.so.preload\|LD_PRELOAD\|hook'; then
    PURPOSE="Library hook / process hider (persistence daemon component)"
  fi

  echo "- inferred_purpose: $PURPOSE"
  echo ""
  echo "## What worked / Reusable techniques"
  echo ""
  echo "- Binary analysis of $FNAME identified purpose as: $PURPOSE"
  echo "- Network IOCs can be used to identify C2/callback infrastructure."
  echo "- String patterns can be used to detect this tool on other targets."
  [[ -n "$PACKED_SECTIONS" ]] && echo "- Binary is packed/obfuscated — unpacking required for full analysis."
  echo ""
} >> "$REPORT"

echo "[+] Report: $REPORT"

# ── learn ingest ──────────────────────────────────────────────────────────────
if [[ -f "$LEARN_ENGINE" ]]; then
  python3 "$LEARN_ENGINE" \
    --root "$CTF_ROOT" \
    ingest \
    --session-id "$SESSION_ID" \
    --source-path "$REPORT" \
    2>&1 | tail -2
fi

echo "[+] binary-re complete."
echo "    Report: $REPORT"
