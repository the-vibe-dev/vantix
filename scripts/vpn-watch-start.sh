#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${CTF_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
cd "$ROOT_DIR"

OVPN=""
TARGET=""
PORTS=""
SESSION=""
SESSION_SPECIFIED=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ovpn) OVPN="${2:-}"; shift 2 ;;
    --target) TARGET="${2:-}"; shift 2 ;;
    --ports) PORTS="${2:-}"; shift 2 ;;
    --session) SESSION="${2:-}"; SESSION_SPECIFIED=1; shift 2 ;;
    --help|-h)
      cat <<'USAGE'
Usage: bash ${CTF_ROOT:-.}/scripts/vpn-watch-start.sh [--ovpn ${CTF_ROOT:-.}/ctf.ovpn] [--target IP] [--session name]
       Optional: --ports "22,80,443"
USAGE
      exit 0
      ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "$OVPN" ]]; then
  if [[ -s "$ROOT_DIR/.vpn_profile" ]]; then
    OVPN="$(tr -d '[:space:]' < "$ROOT_DIR/.vpn_profile")"
  else
    OVPN="$ROOT_DIR/ctf.ovpn"
  fi
fi

[[ -f "$OVPN" ]] || { echo "[!] OVPN not found: $OVPN"; exit 1; }

PROFILE_NAME="$(basename "$OVPN")"
PROFILE_NAME="${PROFILE_NAME%.ovpn}"
if [[ "$SESSION_SPECIFIED" -eq 0 ]]; then
  SESSION="${PROFILE_NAME}vpn"
fi

health_check() {
  local target="$1"
  local ports_csv="$2"
  local port=""
  local ports_space=""
  local up=0

  if ! ip -o -4 addr show | grep -E 'tun[0-9]' | grep -q 'inet '; then
    return 1
  fi

  if [[ -z "$target" ]]; then
    return 0
  fi

  if [[ -n "$ports_csv" ]]; then
    ports_space="${ports_csv//,/ }"
    for port in $ports_space; do
      if timeout 2 bash -lc "</dev/tcp/$target/$port" >/dev/null 2>&1; then
        up=$((up+1))
      fi
    done
    [[ "$up" -gt 0 ]]
    return
  fi

  ip route get "$target" 2>/dev/null | grep -Eq 'dev tun[0-9]'
}

printf '%s\n' "$OVPN" > "$ROOT_DIR/.vpn_profile"
if [[ -n "$TARGET" ]]; then
  printf '%s\n' "$TARGET" > "$ROOT_DIR/.vpn_target"
fi
if [[ -n "$PORTS" ]]; then
  printf '%s\n' "$PORTS" > "$ROOT_DIR/.vpn_ports"
fi

if pgrep -f "openvpn --config $OVPN" >/dev/null 2>&1; then
  if health_check "$TARGET" "$PORTS"; then
    echo "[*] Reusing healthy tunnel for $OVPN"
    if tmux has-session -t "$SESSION" 2>/dev/null; then
      tmux capture-pane -pt "$SESSION" | tail -n 20
    else
      echo "[*] Existing OpenVPN process is healthy; leaving it in place"
    fi
    exit 0
  fi
  echo "[!] Existing tunnel for $OVPN is unhealthy; restarting watcher"
fi

tmux kill-session -t "$SESSION" 2>/dev/null || true
sudo pkill -f "openvpn --config $OVPN" 2>/dev/null || true
sleep 2
tmux new-session -d -s "$SESSION" "bash $ROOT_DIR/ctfvpn_loop.sh"

tmux capture-pane -pt "$SESSION" | tail -n 20
