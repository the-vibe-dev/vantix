#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${CTF_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
SESSION_ID=""
WINDOW_HOURS=24
TMP_DIR=""

usage() {
  cat <<'USAGE'
Usage: bash ${CTF_ROOT:-.}/scripts/tmp-artifact-sweep.sh [--session-id <id>] [--window-hours <N>] [--tmp-dir <dir>]

Collects high-signal CTF artifacts from /tmp into:
  ${CTF_ROOT:-.}/artifacts/tmp_capture/<session_or_nosession>_<timestamp>/
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --session-id) SESSION_ID="${2:-}"; shift 2 ;;
    --window-hours) WINDOW_HOURS="${2:-24}"; shift 2 ;;
    --tmp-dir) TMP_DIR="${2:-}"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "$TMP_DIR" && -f "$ROOT_DIR/.ctf_tmpdir" ]]; then
  TMP_DIR="$(cat "$ROOT_DIR/.ctf_tmpdir" 2>/dev/null || true)"
fi
if [[ -z "$TMP_DIR" ]]; then
  TMP_DIR="/tmp"
fi

stamp="$(date '+%Y%m%d_%H%M%S')"
prefix="${SESSION_ID:-nosession}"
dest="$ROOT_DIR/artifacts/tmp_capture/${prefix}_${stamp}"
mkdir -p "$dest"
index="$dest/index.txt"

echo "# tmp artifact sweep" > "$index"
echo "timestamp=$stamp" >> "$index"
echo "session_id=${SESSION_ID:-}" >> "$index"
echo "window_hours=$WINDOW_HOURS" >> "$index"
echo "tmp_dir=$TMP_DIR" >> "$index"
echo >> "$index"

now_epoch="$(date +%s)"
cutoff_epoch="$(( now_epoch - (WINDOW_HOURS * 3600) ))"

copied=0
skipped=0

copy_one() {
  local src="$1"
  [[ -f "$src" ]] || return 0

  local mtime
  mtime="$(stat -c %Y "$src" 2>/dev/null || echo 0)"
  [[ "$mtime" =~ ^[0-9]+$ ]] || mtime=0
  if (( mtime < cutoff_epoch )); then
    return 0
  fi

  local size
  size="$(stat -c %s "$src" 2>/dev/null || echo 0)"
  [[ "$size" =~ ^[0-9]+$ ]] || size=0
  if (( size > 52428800 )); then
    echo "skip(size>50MB): $src ($size bytes)" >> "$index"
    skipped=$((skipped+1))
    return 0
  fi

  local base
  base="$(basename "$src")"
  local out="$dest/$base"
  if [[ -e "$out" ]]; then
    out="$dest/${base}.$copied"
  fi
  cp -a "$src" "$out"
  copied=$((copied+1))
  echo "copy: $src -> $out ($size bytes)" >> "$index"
}

for pattern in \
  "$TMP_DIR/ep*" \
  "$TMP_DIR/easy*" \
  "$TMP_DIR/easypeasy*" \
  "$TMP_DIR/*flag*" \
  "$TMP_DIR/*hash*" \
  "$TMP_DIR/*nmap*" \
  "$TMP_DIR/*robots*" \
  "$TMP_DIR/*binary*" \
  "$TMP_DIR/*ssh*" \
  "$TMP_DIR/*proof*" \
  "$TMP_DIR/*gobuster*" \
  "$TMP_DIR/*ffuf*"
do
  while IFS= read -r f; do
    copy_one "$f"
  done < <(compgen -G "$pattern" || true)
done

echo >> "$index"
echo "copied=$copied" >> "$index"
echo "skipped=$skipped" >> "$index"

if (( copied == 0 )); then
  echo "NO_ARTIFACTS"
else
  echo "$dest"
fi
