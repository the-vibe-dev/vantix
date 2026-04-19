#!/usr/bin/env bash
set -u

OVPN='${CTF_ROOT}/ctf.ovpn'
TARGET='10.66.179.145'
CHECK_EVERY=10
STALE_LIMIT=3   # 30s bad checks -> force restart
LOG='${CTF_ROOT}/ctfvpn_supervisor.log'

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
  code=$(curl -m 4 -s -o /dev/null -w '%{http_code}' "http://$TARGET/")
  [ -n "$code" ] || code=000
  echo "$code"
}

start_vpn

while true; do
  if ! kill -0 "$OVPN_PID" 2>/dev/null; then
    log "openvpn exited; restarting in 3s"
    sleep 3
    start_vpn
    continue
  fi

  code=$(health_check)
  if [ "$code" = "200" ]; then
    [ "$BAD" -gt 0 ] && log "health recovered (code=200), reset bad_count=$BAD"
    BAD=0
  else
    BAD=$((BAD+1))
    log "health code=$code bad_count=$BAD/$STALE_LIMIT"
  fi

  if [ "$BAD" -ge "$STALE_LIMIT" ]; then
    log "stale detected for ~$((CHECK_EVERY*STALE_LIMIT))s; forcing vpn restart"
    stop_vpn
    sleep 2
    start_vpn
  fi

  sleep "$CHECK_EVERY"
done
