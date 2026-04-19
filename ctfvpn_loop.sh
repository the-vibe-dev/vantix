#!/usr/bin/env bash
set -u

ROOT_DIR="${CTF_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
OVPN_DEFAULT="$ROOT_DIR/ctf.ovpn"
PROFILE_FILE="$ROOT_DIR/.vpn_profile"
OVPN="${VPN_OVPN:-${OVPN:-}}"
if [ -z "${OVPN}" ] && [ -s "$PROFILE_FILE" ]; then
  OVPN="$(tr -d '[:space:]' < "$PROFILE_FILE")"
fi
if [ -z "${OVPN}" ]; then
  OVPN="$OVPN_DEFAULT"
fi
PROFILE_NAME="$(basename "$OVPN")"
PROFILE_NAME="${PROFILE_NAME%.ovpn}"

TARGET_FILE="$ROOT_DIR/.vpn_target"
PORTS_FILE="$ROOT_DIR/.vpn_ports"
TARGET=""
TARGET_PORTS=""
VPN_TARGET_PINNED="${VPN_TARGET:-}"
VPN_PORTS_PINNED="${VPN_PORTS:-}"
CHECK_EVERY=15
STALE_LIMIT=6   # 90s generic bad checks -> force restart
PORT_STALE_LIMIT=4  # 60s of all watched ports down -> force restart sooner
if [ "$PROFILE_NAME" = "ctf" ]; then
  LOG="$ROOT_DIR/ctfvpn_supervisor.log"
else
  LOG="$ROOT_DIR/${PROFILE_NAME}vpn_supervisor.log"
fi
LOG="${VPN_LOG:-$LOG}"

log(){
  echo "[$(date '+%F %T')] $*" | tee -a "$LOG"
}

load_watch_config(){
  TARGET="$VPN_TARGET_PINNED"
  TARGET_PORTS="$VPN_PORTS_PINNED"

  if [ -z "$TARGET" ] && [ -s "$TARGET_FILE" ]; then
    TARGET="$(tr -d '[:space:]' < "$TARGET_FILE")"
  fi
  if [ -z "$TARGET_PORTS" ] && [ -s "$PORTS_FILE" ]; then
    TARGET_PORTS="$(tr -d '[:space:]' < "$PORTS_FILE")"
  fi

  TARGET_PORTS="${TARGET_PORTS//,/ }"
}

start_vpn(){
  log "starting openvpn config=$OVPN"
  sudo openvpn --config "$OVPN" --disable-dco >> "$LOG" 2>&1 &
  OVPN_PID=$!
  BAD=0
  PORT_BAD=0
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
  # Primary tunnel health: any tun device must have an IPv4 address.
  if ! ip -o -4 addr show | grep -E 'tun[0-9]' | grep -q 'inet '; then
    echo "tun_down"
    return
  fi

  # Optional target health by TCP ports when configured.
  if [ -n "$TARGET" ] && [ -n "$TARGET_PORTS" ]; then
    local up=0
    local total=0
    local p=""
    local status=""
    for p in $TARGET_PORTS; do
      total=$((total+1))
      if timeout 2 bash -lc "</dev/tcp/$TARGET/$p" >/dev/null 2>&1; then
        up=$((up+1))
        status="${status}${p}:up "
      else
        status="${status}${p}:down "
      fi
    done
    echo "ports_${up}_of_${total}|${status% }"
    return
  fi

  # Optional target route check if TARGET is configured and no ports are set.
  # This avoids flapping the VPN when the target blocks ICMP or is temporarily down.
  if [ -n "$TARGET" ]; then
    if ip route get "$TARGET" 2>/dev/null | grep -Eq 'dev tun[0-9]'; then
      echo "ok"
    else
      echo "target_route_missing"
    fi
    return
  fi

  echo "ok"
}

start_vpn
load_watch_config
PORT_BAD=0
if [ -n "$TARGET" ]; then
  if [ -n "$TARGET_PORTS" ]; then
    log "watchdog target=$TARGET ports=$TARGET_PORTS"
  else
    log "watchdog target=$TARGET"
  fi
else
  log "watchdog target not set (monitoring tunnel only)"
fi

while true; do
  load_watch_config

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
    PORT_BAD=0
  elif echo "$status" | grep -q '^ports_'; then
    summary="${status#*|}"
    up_count="$(echo "$status" | sed -n 's/^ports_\([0-9]\+\)_of_.*/\1/p')"
    total_count="$(echo "$status" | sed -n 's/^ports_[0-9]\+_of_\([0-9]\+\).*/\1/p')"
    if [ "$up_count" -gt 0 ]; then
      [ "$BAD" -gt 0 ] && log "health recovered (ports: $summary), reset bad_count=$BAD"
      BAD=0
      PORT_BAD=0
    else
      BAD=$((BAD+1))
      PORT_BAD=$((PORT_BAD+1))
      log "health status=target_ports_unreachable ports=[$summary] bad_count=$BAD/$STALE_LIMIT port_bad_count=$PORT_BAD/$PORT_STALE_LIMIT"
    fi
  elif [ "$status" = "tun_down" ] || [ "$status" = "target_route_missing" ]; then
    BAD=$((BAD+1))
    PORT_BAD=0
    log "health status=$status bad_count=$BAD/$STALE_LIMIT"
  fi

  if [ "$PORT_BAD" -ge "$PORT_STALE_LIMIT" ]; then
    log "all watched ports stayed down for ~$((CHECK_EVERY*PORT_STALE_LIMIT))s; forcing vpn restart"
    stop_vpn
    sleep 2
    start_vpn
  elif [ "$BAD" -ge "$STALE_LIMIT" ]; then
    log "stale detected for ~$((CHECK_EVERY*STALE_LIMIT))s; forcing vpn restart"
    stop_vpn
    sleep 2
    start_vpn
  fi

  sleep "$CHECK_EVERY"
done
