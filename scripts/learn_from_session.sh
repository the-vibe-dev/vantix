#!/usr/bin/env bash
set -euo pipefail

if [ "${1:-}" = "" ]; then
  echo "Usage: $0 <retro-file.md>"
  exit 1
fi

RETRO_FILE="$1"
BASE="${CTF_ROOT:-.}"
MEM_FILE="$BASE/MEM.md"
LESSONS_FILE="$BASE/notes/SESSION_LESSONS.md"
STAMP="$(date '+%F %T %Z')"

if [ ! -f "$RETRO_FILE" ]; then
  echo "Retro file not found: $RETRO_FILE"
  exit 1
fi

mkdir -p "$BASE/notes"

if [ ! -f "$LESSONS_FILE" ]; then
  cat > "$LESSONS_FILE" <<'HDR'
# Session Lessons

Append-only session learning log.
HDR
fi

{
  echo
  echo "## $STAMP"
  echo "Source: $RETRO_FILE"
  echo
  cat "$RETRO_FILE"
  echo
} >> "$LESSONS_FILE"

{
  echo
  echo "## Session Learnings - $STAMP"
  echo "- Source: $RETRO_FILE"
  echo "- Summary appended to: $LESSONS_FILE"
} >> "$MEM_FILE"

echo "Learning artifacts updated:"
echo "- $LESSONS_FILE"
echo "- $MEM_FILE"

if [ -x "$BASE/scripts/learn-ingest.sh" ]; then
  "$BASE/scripts/learn-ingest.sh" --source-path "$RETRO_FILE" --source-path "$LESSONS_FILE" >/tmp/ctf_learn_ingest.out 2>/tmp/ctf_learn_ingest.err || {
    echo "Learning ingest warning:"
    sed -n '1,40p' /tmp/ctf_learn_ingest.err
  }
fi
