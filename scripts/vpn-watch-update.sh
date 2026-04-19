#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${CTF_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
TARGET_FILE="$ROOT_DIR/.vpn_target"
PORTS_FILE="$ROOT_DIR/.vpn_ports"

TARGET=""
PORTS=""
CLEAR_PORTS=0
SHOW_ONLY=0

usage() {
  cat <<'USAGE'
Usage: bash ${CTF_ROOT:-.}/scripts/vpn-watch-update.sh [options]

Options:
  --target <IP>          Update watched target IP
  --ports "80,443,22"    Update watched TCP ports (comma-separated)
  --clear-ports          Clear watched port list (route-only health)
  --show                 Show current watcher config only

Examples:
  bash scripts/vpn-watch-update.sh --target 10.64.135.182 --ports "80,6498,65524"
  bash scripts/vpn-watch-update.sh --ports "22,80,443"
  bash scripts/vpn-watch-update.sh --clear-ports
  bash scripts/vpn-watch-update.sh --show
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) TARGET="${2:-}"; shift 2 ;;
    --ports) PORTS="${2:-}"; shift 2 ;;
    --clear-ports) CLEAR_PORTS=1; shift ;;
    --show) SHOW_ONLY=1; shift ;;
    --help|-h) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [[ "$SHOW_ONLY" -eq 0 ]]; then
  if [[ -n "$TARGET" ]]; then
    printf '%s\n' "$TARGET" > "$TARGET_FILE"
  fi

  if [[ "$CLEAR_PORTS" -eq 1 ]]; then
    : > "$PORTS_FILE"
  elif [[ -n "$PORTS" ]]; then
    # Normalize commas/spaces into comma-separated list
    NORMALIZED="$(echo "$PORTS" | tr ' ' ',' | tr -s ',' | sed 's/^,*//; s/,*$//')"
    printf '%s\n' "$NORMALIZED" > "$PORTS_FILE"
  fi
fi

CURRENT_TARGET=""
CURRENT_PORTS=""
[[ -s "$TARGET_FILE" ]] && CURRENT_TARGET="$(tr -d '[:space:]' < "$TARGET_FILE")"
[[ -s "$PORTS_FILE" ]] && CURRENT_PORTS="$(tr -d '[:space:]' < "$PORTS_FILE")"

echo "[*] Watch target: ${CURRENT_TARGET:-<unset>}"
echo "[*] Watch ports : ${CURRENT_PORTS:-<route-only>}"
echo "[*] Active tmux sessions:"
tmux ls 2>/dev/null | grep -E 'ctfvpn|kothvpn' || echo "  (none)"

