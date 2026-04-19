#!/usr/bin/env bash
# patchdiff-helper.sh — diff adjacent refs for version-grounded vuln research
#
# Usage:
#   patchdiff-helper.sh --repo /path/to/repo --from v1.2.3 --to v1.2.4
#   patchdiff-helper.sh --repo-url https://github.com/org/repo.git --from v1.2.3 --to v1.2.4

set -euo pipefail

CTF_ROOT="${CTF_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
LEARN_ENGINE="$CTF_ROOT/scripts/learn_engine.py"
ARTIFACTS_ROOT="$CTF_ROOT/artifacts"
REPO_DIR=""
REPO_URL=""
FROM_REF=""
TO_REF=""
TARGET_IP=""
SESSION_ID=""
KEYWORDS="auth|xss|csrf|sqli|sanitize|escape|serialize|unserialize|ssrf|path|upload|permission|access|admin|token|cookie"

usage() {
  grep '^#' "$0" | head -10 | sed 's/^# \?//'
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo) REPO_DIR="$2"; shift 2 ;;
    --repo-url) REPO_URL="$2"; shift 2 ;;
    --from) FROM_REF="$2"; shift 2 ;;
    --to) TO_REF="$2"; shift 2 ;;
    --target) TARGET_IP="$2"; shift 2 ;;
    --session) SESSION_ID="$2"; shift 2 ;;
    --keywords) KEYWORDS="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "[!] Unknown flag: $1"; usage ;;
  esac
done

[[ -z "$FROM_REF" || -z "$TO_REF" ]] && { echo "[!] --from and --to are required"; exit 1; }

TS=$(date +%Y%m%d-%H%M%S)
[[ -z "$SESSION_ID" ]] && SESSION_ID="patchdiff-$TS"
SAFE_TARGET="${TARGET_IP//./_}"
OUT_DIR="$ARTIFACTS_ROOT/${SAFE_TARGET:-local}/version_research/$TS"
mkdir -p "$OUT_DIR"

if [[ -z "$REPO_DIR" && -n "$REPO_URL" ]]; then
  REPO_DIR="$OUT_DIR/repo"
  git clone --quiet --filter=blob:none "$REPO_URL" "$REPO_DIR"
fi

[[ -z "$REPO_DIR" || ! -d "$REPO_DIR/.git" ]] && { echo "[!] valid --repo or --repo-url is required"; exit 1; }

REPORT="$OUT_DIR/patchdiff_report.md"
DIFF_FILE="$OUT_DIR/patch.diff"

git -C "$REPO_DIR" fetch --tags --quiet >/dev/null 2>&1 || true
git -C "$REPO_DIR" diff "$FROM_REF" "$TO_REF" > "$DIFF_FILE"

{
  echo "# Patch Diff Report"
  echo
  echo "- repo: $REPO_DIR"
  echo "- from: $FROM_REF"
  echo "- to: $TO_REF"
  echo "- ts: $TS"
  echo
  echo "## Diff Stat"
  echo
  echo '```'
  git -C "$REPO_DIR" diff --stat "$FROM_REF" "$TO_REF" | sed -n '1,120p'
  echo '```'
  echo
  echo "## Commit Log"
  echo
  echo '```'
  git -C "$REPO_DIR" log --oneline "$FROM_REF..$TO_REF" | sed -n '1,80p'
  echo '```'
  echo
  echo "## Security-Keyword Hits"
  echo
  if grep -niE "$KEYWORDS" "$DIFF_FILE" >/dev/null; then
    echo '```'
    grep -niE "$KEYWORDS" "$DIFF_FILE" | sed -n '1,200p'
    echo '```'
  else
    echo "No keyword hits in diff."
  fi
} > "$REPORT"

if [[ -f "$LEARN_ENGINE" ]]; then
  timeout 15 python3 "$LEARN_ENGINE" --root "$CTF_ROOT" --no-llm ingest --session-id "$SESSION_ID" --source-path "$REPORT" >/dev/null 2>&1 || true
fi

echo "$REPORT"
