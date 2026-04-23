#!/usr/bin/env bash
# source-audit.sh — Source code vulnerability pattern scanner
#
# Scans a directory of source code for common vulnerability patterns.
# Uses semgrep if available, otherwise falls back to grep-based taint analysis.
# Maps findings to CWE IDs. Outputs a findings report and feeds it to learn_engine.
#
# Usage:
#   source-audit.sh -d /path/to/source
#   source-audit.sh -d /var/www/html -l php
#   source-audit.sh -d ./app --semgrep --target 10.10.10.5

set -euo pipefail

CTF_ROOT="${CTF_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
LEARN_ENGINE="$CTF_ROOT/scripts/learn_engine.py"
ARTIFACTS_ROOT="${ARTIFACTS_ROOT:-$CTF_ROOT/artifacts}"

SOURCE_DIR=""
LANG="auto"
REQUIRE_SEMGREP=false
TARGET_IP=""
SESSION_ID=""

usage() {
  grep '^#' "$0" | head -15 | sed 's/^# \?//'
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -d|--dir)        SOURCE_DIR="$2";     shift 2 ;;
    -l|--lang)       LANG="$2";           shift 2 ;;
    --semgrep)       REQUIRE_SEMGREP=true; shift ;;
    -t|--target)     TARGET_IP="$2";      shift 2 ;;
    --session)       SESSION_ID="$2";     shift 2 ;;
    -h|--help)       usage ;;
    *) echo "[!] Unknown flag: $1"; usage ;;
  esac
done

[[ -z "$SOURCE_DIR" ]] && { echo "[!] -d SOURCE_DIR required"; exit 1; }
[[ ! -d "$SOURCE_DIR" ]] && { echo "[!] Not a directory: $SOURCE_DIR"; exit 1; }

[[ -z "$SESSION_ID" ]] && SESSION_ID="audit-$(date +%Y%m%d-%H%M%S)"
TS=$(date +%Y%m%d-%H%M%S)
SAFE_TARGET="${TARGET_IP//./_}"
OUT_DIR="$ARTIFACTS_ROOT/${SAFE_TARGET:-local}/source_audit"
mkdir -p "$OUT_DIR"
DETAIL_DIR="$OUT_DIR/details"
mkdir -p "$DETAIL_DIR"
REPORT="$OUT_DIR/${TS}_findings.md"

echo "[*] source-audit: dir=$SOURCE_DIR lang=$LANG"

# ── language detection ────────────────────────────────────────────────────────
if [[ "$LANG" == "auto" ]]; then
  file_counts() { find "$SOURCE_DIR" -name "*.$1" 2>/dev/null | wc -l; }
  php_count=$(file_counts php)
  py_count=$(file_counts py)
  js_count=$(file_counts js)
  ts_count=$(file_counts ts)
  c_count=$(file_counts c)
  cpp_count=$(file_counts cpp)
  rb_count=$(file_counts rb)
  max=0
  js_total=$((js_count + ts_count))
  for pair in "php:$php_count" "python:$py_count" "js:$js_total" "c:$c_count"; do
    lang_name="${pair%%:*}"
    count="${pair##*:}"
    if [[ "$count" -gt "$max" ]]; then max="$count"; LANG="$lang_name"; fi
  done
  [[ "$max" -eq 0 ]] && LANG="generic"
  echo "[*] Auto-detected language: $LANG (primary)"
fi

TOTAL_FINDINGS=0

# ── helper: grep_pattern(name, cwe, severity, pattern, file_glob) ─────────────
declare -a FINDINGS=()

grep_pattern() {
  local name="$1" cwe="$2" severity="$3" pattern="$4"
  shift 4
  local results
  local include_args=()
  for glob in "$@"; do
    include_args+=(--include="$glob")
  done
  results=$(grep -rn \
    --exclude-dir=.git \
    --exclude-dir=node_modules \
    --exclude-dir=test \
    --exclude-dir=tests \
    --exclude-dir=cypress \
    --exclude-dir=codefixes \
    --exclude-dir=private \
    --exclude-dir=dist \
    --exclude-dir=build \
    --exclude-dir=coverage \
    --exclude='*.min.js' \
    --exclude='*.map' \
    "${include_args[@]}" \
    -P "$pattern" "$SOURCE_DIR" 2>/dev/null | head -30 || true)
  if [[ -n "$results" ]]; then
    local count
    count=$(echo "$results" | wc -l)
    local safe_name detail_file
    safe_name=$(echo "$name" | tr '[:upper:] /' '[:lower:]__' | tr -cd 'a-z0-9_-')
    detail_file="$DETAIL_DIR/${safe_name}.txt"
    echo "$results" > "$detail_file"
    FINDINGS+=("$severity|$name|$cwe|$count|$detail_file")
    TOTAL_FINDINGS=$((TOTAL_FINDINGS + count))
  fi
}

# ── PHP patterns ──────────────────────────────────────────────────────────────
if [[ "$LANG" == "php" || "$LANG" == "generic" ]]; then
  grep_pattern "PHP eval injection"           "CWE-94"  "HIGH"   'eval\s*\(' '*.php'
  grep_pattern "PHP system/exec"              "CWE-78"  "HIGH"   '(system|exec|shell_exec|passthru|popen)\s*\(' '*.php'
  grep_pattern "PHP unfiltered GET/POST"      "CWE-20"  "MEDIUM" '\$_(GET|POST|REQUEST|COOKIE)\s*\[' '*.php'
  grep_pattern "PHP include with variable"    "CWE-98"  "HIGH"   '(include|require(_once)?)\s*\(\s*\$' '*.php'
  grep_pattern "PHP preg_replace /e modifier" "CWE-94"  "HIGH"   "preg_replace\s*\(\s*['\"].*\/e" '*.php'
  grep_pattern "PHP serialize/unserialize"    "CWE-502" "MEDIUM" 'unserialize\s*\(' '*.php'
  grep_pattern "PHP file_get/put with var"    "CWE-22"  "HIGH"   '(file_get_contents|file_put_contents)\s*\(\s*\$' '*.php'
  grep_pattern "PHP SQL concat"               "CWE-89"  "HIGH"   '(mysql_query|mysqli_query|PDO.*query)\s*\(\s*["\x27][^"]*\.\s*\$' '*.php'
  grep_pattern "PHP SSRF via curl"            "CWE-918" "HIGH"   'curl_setopt\s*\(.*CURLOPT_URL.*\$' '*.php'
  grep_pattern "PHP XXE"                      "CWE-611" "MEDIUM" 'simplexml_load_string|DOMDocument.*loadXML' '*.php'
fi

# ── Python patterns ───────────────────────────────────────────────────────────
if [[ "$LANG" == "python" || "$LANG" == "generic" ]]; then
  grep_pattern "Python os.system"             "CWE-78"  "HIGH"   'os\.(system|popen)\s*\(' '*.py'
  grep_pattern "Python subprocess shell=True" "CWE-78"  "HIGH"   'subprocess\.(call|run|Popen).*shell\s*=\s*True' '*.py'
  grep_pattern "Python eval/exec"             "CWE-94"  "HIGH"   '\b(eval|exec)\s*\(' '*.py'
  grep_pattern "Python pickle loads"          "CWE-502" "HIGH"   'pickle\.(loads|load)\s*\(' '*.py'
  grep_pattern "Python yaml.load unsafe"      "CWE-502" "MEDIUM" 'yaml\.load\s*\([^)]*\)(?!.*Loader)' '*.py'
  grep_pattern "Python SSRF requests"         "CWE-918" "MEDIUM" 'requests\.(get|post)\s*\([^)]*(?:url|path)\s*=' '*.py'
  grep_pattern "Python SQLi format string"    "CWE-89"  "HIGH"   'execute\s*\(\s*[f"\x27].*%s\|.*format\(' '*.py'
  grep_pattern "Python open with user input"  "CWE-22"  "HIGH"   'open\s*\([^)]*\+[^)]*\)' '*.py'
fi

# ── JavaScript/Node patterns ──────────────────────────────────────────────────
if [[ "$LANG" == "js" || "$LANG" == "generic" ]]; then
  grep_pattern "JS eval"                       "CWE-94"  "HIGH"   '\beval\s*\(' '*.js' '*.jsx' '*.ts' '*.tsx'
  grep_pattern "JS innerHTML assignment"       "CWE-79"  "HIGH"   'innerHTML\s*=' '*.js' '*.jsx' '*.ts' '*.tsx'
  grep_pattern "JS document.write"             "CWE-79"  "MEDIUM" 'document\.write\s*\(' '*.js' '*.jsx' '*.ts' '*.tsx'
  grep_pattern "JS dangerouslySetInnerHTML"    "CWE-79"  "HIGH"   'dangerouslySetInnerHTML' '*.js' '*.jsx' '*.ts' '*.tsx'
  grep_pattern "Angular trusted HTML bypass"   "CWE-79"  "HIGH"   'bypassSecurityTrustHtml\s*\(' '*.ts' '*.tsx'
  grep_pattern "Node child_process shell"      "CWE-78"  "HIGH"   "(require\\(['\\\"]child_process['\\\"]\\)|from ['\\\"]child_process['\\\"]|child_process\\.|require\\(['\\\"]child_process['\\\"]\\)\\.(exec|spawn|execFile))" '*.js' '*.ts'
  grep_pattern "Node SSRF URL fetch/request"   "CWE-918" "HIGH"   '(fetch|request|http\.(get|request)|https\.(get|request))\s*\(\s*([^)]*req\.(body|query|params)|[^)]*\bimageUrl\b|url\b)' '*.js' '*.ts'
  grep_pattern "Sequelize raw SQL interpolation" "CWE-89" "HIGH"  'sequelize\.query\s*\(\s*`[^`]*\$\{' '*.js' '*.ts'
  grep_pattern "XML external entity expansion" "CWE-611" "HIGH"   'parseXml\s*\([^)]*noent\s*:\s*true' '*.js' '*.ts'
  grep_pattern "Unsafe YAML load"              "CWE-502" "MEDIUM" 'yaml\.load\s*\(' '*.js' '*.ts'
fi

# ── C/C++ patterns ────────────────────────────────────────────────────────────
if [[ "$LANG" == "c" || "$LANG" == "generic" ]]; then
  grep_pattern "C strcpy/strcat unsafe"       "CWE-120" "HIGH"   '\b(strcpy|strcat|gets|sprintf)\s*\(' '*.c' '*.cpp' '*.h'
  grep_pattern "C system() call"              "CWE-78"  "HIGH"   '\bsystem\s*\(' '*.c' '*.cpp'
  grep_pattern "C recv/read unchecked size"   "CWE-120" "MEDIUM" '\b(recv|read)\s*\([^,]+,[^,]+,[^,]+\)' '*.c' '*.cpp'
  grep_pattern "C format string"              "CWE-134" "HIGH"   '\b(printf|fprintf|sprintf)\s*\([^"]*\$' '*.c' '*.cpp'
  grep_pattern "C alloca"                     "CWE-770" "LOW"    '\balloca\s*\(' '*.c' '*.cpp'
fi

# ── semgrep (if available) ────────────────────────────────────────────────────
SEMGREP_REPORT=""
if command -v semgrep &>/dev/null; then
  echo "[*] Running semgrep..."
  SEMGREP_REPORT=$(semgrep --config "p/owasp-top-ten" --config "p/command-injection" \
    --config "p/sql-injection" --quiet --json "$SOURCE_DIR" 2>/dev/null | \
    python3 -c "
import sys, json
d = json.load(sys.stdin)
results = d.get('results', [])
print(f'semgrep findings: {len(results)}')
for r in results[:50]:
    path = r.get('path','?')
    line = r.get('start',{}).get('line','?')
    rule = r.get('check_id','?').split('.')[-1]
    msg = r.get('extra',{}).get('message','')[:100]
    sev = r.get('extra',{}).get('severity','?')
    print(f'  [{sev}] {path}:{line} — {rule}: {msg}')
" 2>/dev/null || true)
elif $REQUIRE_SEMGREP; then
  echo "[!] semgrep required (--semgrep) but not installed. Install: pip install semgrep"
  exit 1
fi

# ── write report ──────────────────────────────────────────────────────────────
{
  echo "# Source Audit Findings"
  echo ""
  echo "- source_dir: $SOURCE_DIR"
  echo "- language: $LANG"
  echo "- target: ${TARGET_IP:-local}"
  echo "- ts: $TS"
  echo "- total_grep_findings: $TOTAL_FINDINGS"
  echo ""

  if [[ -n "$SEMGREP_REPORT" ]]; then
    echo "## Semgrep Results"
    echo ""
    echo '```'
    echo "$SEMGREP_REPORT"
    echo '```'
    echo ""
  fi

  echo "## Pattern-Based Findings"
  echo ""

  if [[ ${#FINDINGS[@]} -eq 0 ]]; then
    echo "No grep-based findings."
  else
    echo "| Severity | Finding | CWE | Matches |"
    echo "|----------|---------|-----|---------|"
    for entry in "${FINDINGS[@]}"; do
      IFS='|' read -r sev name cwe count detail_file <<< "$entry"
      echo "| $sev | $name | $cwe | $count |"
    done
    echo ""
    echo "## Finding Details"
    echo ""
    for entry in "${FINDINGS[@]}"; do
      IFS='|' read -r sev name cwe count detail_file <<< "$entry"
      echo "### [$sev] $name ($cwe)"
      echo ""
      echo '```'
      head -10 "$detail_file"
      echo '```'
      echo ""

      # Exploitation guidance per CWE
      case "$cwe" in
        CWE-78|CWE-94)
          echo "**Attack path:** If user-controlled input reaches this call, attempt OS command injection."
          echo "**Test:** \`; id\`, \`\$(id)\`, backtick injection, newline injection."
          ;;
        CWE-89)
          echo "**Attack path:** SQL injection. Test: \`' OR '1'='1\`, \`' UNION SELECT...\`"
          echo "**Tool:** sqlmap -u TARGET --level 3 --risk 2"
          ;;
        CWE-22)
          echo "**Attack path:** Path traversal / LFI. Test: \`../../../etc/passwd\`, \`php://filter\`"
          ;;
        CWE-502)
          echo "**Attack path:** Insecure deserialization. Generate payload with ysoserial (Java), pickle (Python)."
          ;;
        CWE-918)
          echo "**Attack path:** SSRF. Test internal endpoints: http://127.0.0.1/, http://169.254.169.254/"
          ;;
        CWE-79)
          echo "**Attack path:** XSS. Test: \`<script>alert(1)</script>\`, \`javascript:alert(1)\`"
          ;;
        CWE-120|CWE-134)
          echo "**Attack path:** Buffer/format string overflow. Requires binary analysis to confirm exploitability."
          ;;
      esac
      echo ""
    done
  fi

  echo "## What worked / Reusable patterns"
  echo ""
  echo "- Source audit on $SOURCE_DIR found $TOTAL_FINDINGS potential vulnerability markers."
  [[ -n "$SEMGREP_REPORT" ]] && echo "- Semgrep provided additional OWASP-mapped findings."
  echo "- Review each CWE detail section for targeted test inputs."
  echo ""
} > "$REPORT"

echo "[+] Report: $REPORT"

# ── learn ingest ──────────────────────────────────────────────────────────────
if [[ -f "$LEARN_ENGINE" ]]; then
  set +e
  INGEST_OUTPUT=$(python3 "$LEARN_ENGINE" \
    --root "$CTF_ROOT" \
    ingest \
    --session-id "$SESSION_ID" \
    --source-path "$REPORT" \
    2>&1 | tail -2)
  INGEST_RC=${PIPESTATUS[0]}
  set -e
  [[ -n "$INGEST_OUTPUT" ]] && echo "$INGEST_OUTPUT"
  if [[ "$INGEST_RC" -ne 0 ]]; then
    echo "[!] learning ingest skipped or failed for source audit report (rc=$INGEST_RC)"
  fi
fi

echo "[+] source-audit complete. Total findings: $TOTAL_FINDINGS"
echo "    Report: $REPORT"
