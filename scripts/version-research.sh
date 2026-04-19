#!/usr/bin/env bash
# version-research.sh — scaffold public upstream source research for a versioned target
#
# Usage:
#   version-research.sh --service "Apache 2.4.41" --target 10.10.10.10
#   version-research.sh --service "Roundcube 1.6.6" --target 10.10.10.10 \
#     --repo https://github.com/roundcube/roundcubemail.git --ref 1.6.6

set -euo pipefail

CTF_ROOT="${CTF_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
ARTIFACTS_ROOT="$CTF_ROOT/artifacts"
LEARN_ENGINE="$CTF_ROOT/scripts/learn_engine.py"
SOURCE_MAP="$CTF_ROOT/scripts/service-source-map.py"
PATCHDIFF="$CTF_ROOT/scripts/patchdiff-helper.sh"

SERVICE_STR=""
PRODUCT=""
VERSION=""
TARGET_IP=""
REPO_URL=""
REF=""
FROM_REF=""
TO_REF=""
SUSPECTED_CLASS=""
SESSION_ID=""
DO_CLONE=true

usage() {
  grep '^#' "$0" | head -12 | sed 's/^# \?//'
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --service) SERVICE_STR="$2"; shift 2 ;;
    --product) PRODUCT="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --target) TARGET_IP="$2"; shift 2 ;;
    --repo) REPO_URL="$2"; shift 2 ;;
    --ref) REF="$2"; shift 2 ;;
    --from) FROM_REF="$2"; shift 2 ;;
    --to) TO_REF="$2"; shift 2 ;;
    --suspected-class) SUSPECTED_CLASS="$2"; shift 2 ;;
    --session) SESSION_ID="$2"; shift 2 ;;
    --no-clone) DO_CLONE=false; shift ;;
    -h|--help) usage ;;
    *) echo "[!] Unknown flag: $1"; usage ;;
  esac
done

[[ -z "$SERVICE_STR" && -z "$PRODUCT" ]] && { echo "[!] --service or --product is required"; exit 1; }

TS=$(date +%Y%m%d-%H%M%S)
[[ -z "$SESSION_ID" ]] && SESSION_ID="vresearch-$TS"
SAFE_TARGET="${TARGET_IP//./_}"
OUT_DIR="$ARTIFACTS_ROOT/${SAFE_TARGET:-local}/version_research/$TS"
mkdir -p "$OUT_DIR"

MAP_JSON="$OUT_DIR/source_map.json"
REPORT="$OUT_DIR/version_research.md"
CLONE_DIR="$OUT_DIR/upstream"

map_args=(--format json)
[[ -n "$SERVICE_STR" ]] && map_args+=(--service "$SERVICE_STR")
[[ -n "$PRODUCT" ]] && map_args+=(--product "$PRODUCT")
[[ -n "$VERSION" ]] && map_args+=(--version "$VERSION")
python3 "$SOURCE_MAP" "${map_args[@]}" > "$MAP_JSON"

if [[ -z "$REPO_URL" ]]; then
  REPO_URL=$(python3 - <<'PY' "$MAP_JSON"
import json, sys
data = json.load(open(sys.argv[1]))
candidates = data.get("candidates", [])
print(candidates[0]["repo"] if len(candidates) == 1 else "")
PY
)
fi

NORM_PRODUCT=$(python3 - <<'PY' "$MAP_JSON"
import json, sys
data = json.load(open(sys.argv[1]))
print(data["input"].get("product",""))
PY
)
NORM_VERSION=$(python3 - <<'PY' "$MAP_JSON"
import json, sys
data = json.load(open(sys.argv[1]))
print(data["input"].get("version",""))
PY
)

TAG_REPORT=""
if $DO_CLONE && [[ -n "$REPO_URL" ]]; then
  git clone --quiet --filter=blob:none "$REPO_URL" "$CLONE_DIR"
  git -C "$CLONE_DIR" fetch --tags --quiet >/dev/null 2>&1 || true
  if [[ -n "$NORM_VERSION" ]]; then
    TAG_REPORT=$(git -C "$CLONE_DIR" tag -l "*$NORM_VERSION*" | sed -n '1,20p' || true)
  fi
  if [[ -n "$REF" ]]; then
    git -C "$CLONE_DIR" checkout --quiet --detach "$REF"
  fi
fi

{
  echo "# Version Research Note"
  echo
  echo "- target: ${TARGET_IP:-unknown}"
  echo "- observed service string: ${SERVICE_STR:-$PRODUCT}"
  echo "- normalized product: ${NORM_PRODUCT:-unknown}"
  echo "- normalized version: ${NORM_VERSION:-unknown}"
  echo "- suspected class: ${SUSPECTED_CLASS:-unknown}"
  echo "- upstream repo: ${REPO_URL:-not-selected}"
  echo "- working ref: ${REF:-not-selected}"
  echo
  echo "## Research Queries"
  echo
  python3 - <<'PY' "$MAP_JSON"
import json, sys
data = json.load(open(sys.argv[1]))
for query in data.get("queries", []):
    print(f"- {query}")
PY
  echo
  echo "## Candidate Source Matches"
  echo
  python3 - <<'PY' "$MAP_JSON"
import json, sys
data = json.load(open(sys.argv[1]))
candidates = data.get("candidates", [])
if not candidates:
    print("- no direct catalog match")
for cand in candidates:
    print(f"- {cand['project']}")
    print(f"  - repo: {cand['repo']}")
    print(f"  - package: {cand['package']}")
    print(f"  - ecosystem: {cand['ecosystem']}")
    print(f"  - docs: {cand['docs']}")
PY
  echo
  if [[ -n "$TAG_REPORT" ]]; then
    echo "## Matching Tags"
    echo
    echo '```'
    echo "$TAG_REPORT"
    echo '```'
    echo
  fi
  echo "## Required Next Steps"
  echo
  echo "1. Confirm the exact route, sink, parser, or auth flow observed on the live target."
  echo "2. Inspect the closest public source ref for that exact path."
  echo "3. If adjacent fixed refs are known, run:"
  echo "   \`bash scripts/patchdiff-helper.sh --repo <local_clone> --from <vuln_ref> --to <fixed_ref>\`"
  echo "4. Derive one bounded proof check and return to the live target."
  echo
  echo "## Validation Hypothesis"
  echo
  echo "- hypothesis:"
  echo "- measurable proof check:"
  echo "- result:"
  echo "- next pivot:"
} > "$REPORT"

if [[ -n "$FROM_REF" && -n "$TO_REF" && -d "$CLONE_DIR/.git" ]]; then
  "$PATCHDIFF" --repo "$CLONE_DIR" --from "$FROM_REF" --to "$TO_REF" --target "$TARGET_IP" --session "$SESSION_ID" >/dev/null
fi

if [[ -f "$LEARN_ENGINE" ]]; then
  timeout 15 python3 "$LEARN_ENGINE" --root "$CTF_ROOT" --no-llm ingest --session-id "$SESSION_ID" --source-path "$REPORT" >/dev/null 2>&1 || true
fi

echo "$REPORT"
