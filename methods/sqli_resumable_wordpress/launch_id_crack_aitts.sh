#!/usr/bin/env bash
set -euo pipefail
ID="${1:?id}"
HASH_FILE="${2:?hash file}"
SSH_KEY="$HOME/.ssh/<LAB_KEY>"
HOST="<USER>@<CRACK_NODE_HOST>"

HASH=$(tr -d '\r\n' < "$HASH_FILE")
if [ "${#HASH}" -lt 20 ]; then
  echo "hash too short" >&2
  exit 1
fi

LOCAL_TMP_HASH="/tmp/id${ID}.hash"
printf '%s\n' "$HASH" > "$LOCAL_TMP_HASH"

scp -i "$SSH_KEY" -o IdentitiesOnly=yes "$LOCAL_TMP_HASH" "$HOST:${HOME}/ctf_crack/id${ID}.hash"

cat > /tmp/remote_crack_id.sh << 'EOS'
#!/usr/bin/env bash
set -euo pipefail
ID="$1"
mkdir -p "$HOME/ctf_crack"
if [ ! -f "$HOME/ctf_crack/rockyou.txt" ]; then
  gzip -dc ${SECOPS_SHARED_ROOT}/droppoints/ctf-crack/20260402-131140/rockyou.txt.gz > "$HOME/ctf_crack/rockyou.txt"
fi
cat > "$HOME/ctf_crack/run_id${ID}_crack.sh" << 'EOI'
#!/usr/bin/env bash
set -u
ID="$1"
HASH="$HOME/ctf_crack/id${ID}.hash"
POT="$HOME/ctf_crack/id${ID}.pot"
LOG="$HOME/ctf_crack/id${ID}.log"
R="$HOME/ctf_crack/rockyou.txt"

echo "[$(date '+%F %T')] id${ID} crack start" | tee -a "$LOG"

run_stage(){
  local name="$1"; shift
  echo "[$(date '+%F %T')] stage=$name" | tee -a "$LOG"
  hashcat "$@" 2>&1 | tee -a "$LOG"
  out=$(hashcat -m 400 "$HASH" --show --potfile-path "$POT" || true)
  if [ -n "$out" ]; then
    echo "[$(date '+%F %T')] CRACKED" | tee -a "$LOG"
    echo "$out" | tee -a "$LOG"
    exit 0
  fi
}

run_stage rockyou_plain  -m 400 -a 0 -O "$HASH" "$R" --potfile-path "$POT" --status --status-timer 30 --session id${ID}ry
run_stage rockyou_best64 -m 400 -a 0 -O "$HASH" "$R" -r /usr/share/hashcat/rules/best64.rule --potfile-path "$POT" --status --status-timer 30 --session id${ID}ry
run_stage rockyou_leet   -m 400 -a 0 -O "$HASH" "$R" -r /usr/share/hashcat/rules/leetspeak.rule --potfile-path "$POT" --status --status-timer 30 --session id${ID}ry
run_stage rockyou_2digit -m 400 -a 6 -O "$HASH" "$R" '?d?d' --potfile-path "$POT" --status --status-timer 30 --session id${ID}ry

echo "[$(date '+%F %T')] done" | tee -a "$LOG"
hashcat -m 400 "$HASH" --show --potfile-path "$POT" | tee -a "$LOG"
EOI
chmod +x "$HOME/ctf_crack/run_id${ID}_crack.sh"
(tmux kill-session -t mtn-crack-id${ID} >/dev/null 2>&1 || true)
tmux new-session -d -s mtn-crack-id${ID} "$HOME/ctf_crack/run_id${ID}_crack.sh ${ID}"
EOS
chmod +x /tmp/remote_crack_id.sh
scp -i "$SSH_KEY" -o IdentitiesOnly=yes /tmp/remote_crack_id.sh "$HOST:/tmp/remote_crack_id.sh"
ssh -i "$SSH_KEY" -o IdentitiesOnly=yes "$HOST" "bash /tmp/remote_crack_id.sh ${ID}; tmux ls | grep mtn-crack-id${ID}"

echo "started mtn-crack-id${ID}"
