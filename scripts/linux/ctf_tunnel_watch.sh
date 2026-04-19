#!/usr/bin/env bash
set -u

OVPN_FILE="${CTF_ROOT:-$HOME/CTF}/ctf.ovpn"
LOG_FILE="${CTF_ROOT:-$HOME/CTF}/ctf_tunnel_watch.log"
STATE_FILE="${CTF_ROOT:-$HOME/CTF}/ctf_tunnel_watch.state"

mkdir -p "$(dirname "$LOG_FILE")"

echo "[$(date '+%F %T')] watchdog starting for $OVPN_FILE" >> "$LOG_FILE"

while true; do
  echo "[$(date '+%F %T')] launch openvpn" >> "$LOG_FILE"
  echo "last_start=$(date '+%F %T')" > "$STATE_FILE"

  sudo openvpn --config "$OVPN_FILE" --disable-dco >> "$LOG_FILE" 2>&1
  rc=$?

  echo "[$(date '+%F %T')] openvpn exited rc=$rc, restarting in 5s" >> "$LOG_FILE"
  sleep 5
done
