#!/usr/bin/env bash
set -u

OVPN='${CTF_ROOT:-$HOME/CTF}/ctf.ovpn'
TARGET_FILE='${CTF_ROOT:-$HOME/CTF}/.vpn_target'
TARGET="${VPN_TARGET:-}"
if [ -z "$TARGET" ] && [ -s "$TARGET_FILE" ]; then
  TARGET="$(tr -d '[:space:]' < "$TARGET_FILE")"
fi
CHECK_EVERY=15
STALE_LIMIT=6   # 90s bad checks -> force restart
LOG='${CTF_ROOT:-$HOME/CTF}/ctfvpn_supervisor.log'

log(){
  echo "[$(date '+%F %T')] $*" | tee -a "$LOG"
}

start_vpn(){
  log "starting openvpn"
  sudo openvpn --config "$OVPN" --disable-dco >> "$LOG" 2>&1 &
  OVPN_PID=$!
  BAD=0
  sleep 3
}

stop_vpn(){
  if kill -0 "$OVPN_PID" 2>/dev/null; then
    log "stopping openvpn pid=$OVPN_PID"
    kill "$OVPN_PID" 2>/dev/null || true
    sleep 2
    kill -9 "$OVPN_PID" 2>/dev/null || true
  fi
}

health_check(){
  # Primary tunnel health: tun0 must exist with an IPv4 address.
  if ! ip -o -4 addr show dev tun0 | grep -q 'inet '; then
    echo "tun_down"
    return
  fi

  # Optional target health: ping if TARGET is configured.
  if [ -n "$TARGET" ]; then
    if ping -c1 -W2 "$TARGET" >/dev/null 2>&1; then
      echo "ok"
    else
      echo "target_unreachable"
    fi
    return
  fi

  echo "ok"
}

start_vpn
if [ -n "$TARGET" ]; then
  log "watchdog target=$TARGET"
else
  log "watchdog target not set (monitoring tunnel only)"
fi

while true; do
  if ! kill -0 "$OVPN_PID" 2>/dev/null; then
    log "openvpn exited; restarting in 3s"
    sleep 3
    start_vpn
    continue
  fi

  status=$(health_check)
  if [ "$status" = "ok" ]; then
    [ "$BAD" -gt 0 ] && log "health recovered (status=$status), reset bad_count=$BAD"
    BAD=0
  else
    BAD=$((BAD+1))
    log "health status=$status bad_count=$BAD/$STALE_LIMIT"
  fi

  if [ "$BAD" -ge "$STALE_LIMIT" ]; then
    log "stale detected for ~$((CHECK_EVERY*STALE_LIMIT))s; forcing vpn restart"
    stop_vpn
    sleep 2
    start_vpn
  fi

  sleep "$CHECK_EVERY"
done
