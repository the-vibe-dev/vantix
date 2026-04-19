#!/usr/bin/env bash
set -euo pipefail

ROOT="${CTF_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
TARGET="${1:-}"
SESSION="${2:-koth}"

if [[ -z "$TARGET" ]]; then
  echo "Usage: $0 <TARGET_IP> [SESSION_NAME]"
  exit 1
fi

mkdir -p "$ROOT/scans" "$ROOT/challenges/tryhackme/koth"
STAMP="$(date +%Y%m%d_%H%M%S)"
NOTES="$ROOT/challenges/tryhackme/koth/${STAMP}_${TARGET}.md"

cat > "$NOTES" <<NOTES
# KoTH Session - $STAMP
- Target IP: $TARGET
- Operator: ${OPERATOR_NAME:-operator}

## Timeline
- Start:
- Foothold:
- Root:
- King set:

## Commands

## Findings

## Opponent Activity

## Patches Applied

## Flags
NOTES

# Bring up VPN watcher for KoTH profile
bash "$ROOT/scripts/vpn-watch-start.sh" --ovpn "$ROOT/koth.ovpn" --target "$TARGET" --session kothvpn >/dev/null

# Clean old tmux session if present
tmux kill-session -t "$SESSION" 2>/dev/null || true

CLAIM_LOG="$ROOT/challenges/tryhackme/koth/claim_watch_${TARGET}.log"
OPP_LOG="$ROOT/challenges/tryhackme/koth/opponent_watch_${TARGET}.log"
STATUS_JSON="$ROOT/challenges/tryhackme/koth/koth_status_${TARGET}.json"

# Pane layout:
# 0: operator shell    | 1: recon (nmap)
# 2: port check loop   | 3: notes tail
# 4: claim watch       | 5: opponent watch (instructions)

tmux new-session -d -s "$SESSION" -n ops "cd $ROOT && bash"
tmux split-window -h -t "$SESSION":0 "cd $ROOT && echo 'Ready: nmap -Pn -sC -sV $TARGET -oN scans/${TARGET}_svc_$STAMP.txt' && bash"
tmux split-window -v -t "$SESSION":0.0 "cd $ROOT && echo 'Ready monitor loop' && bash"
tmux split-window -v -t "$SESSION":0.1 "cd $ROOT && tail -n +1 -f '$NOTES'"

# Start port check loop
tmux send-keys -t "$SESSION":0.0 "while true; do date; timeout 2 bash -lc '</dev/tcp/$TARGET/22' >/dev/null 2>&1 && echo '22 up' || echo '22 down'; timeout 2 bash -lc '</dev/tcp/$TARGET/80' >/dev/null 2>&1 && echo '80 up' || echo '80 down'; sleep 5; clear; done" C-m

# Start nmap
tmux send-keys -t "$SESSION":0.1 "nmap -Pn -sC -sV $TARGET -oN scans/${TARGET}_svc_$STAMP.txt" C-m

# Pane 4: Start claim watch immediately (only needs HTTP to :9999)
tmux split-window -v -t "$SESSION":0.0 "cd $ROOT && bash"
tmux send-keys -t "$SESSION":0.2 "bash scripts/koth-claim-watch.sh $TARGET ${OPERATOR_NAME:-operator} 2 '$CLAIM_LOG' '$STATUS_JSON'" C-m

# Pane 5: Opponent watch instructions (needs root SSH — started manually after foothold)
tmux split-window -v -t "$SESSION":0.3 "cd $ROOT && bash"
tmux send-keys -t "$SESSION":0.4 "echo '== Opponent Watch =='; echo 'Start after obtaining root SSH:'; echo '  bash scripts/koth-opponent-watch.sh $TARGET --ssh-key /tmp/id_rsa --auto-capture'; echo ''; echo 'Manual tool extraction:'; echo '  bash scripts/tool-extractor.sh -t $TARGET -i /tmp/id_rsa'; echo ''; echo 'Waiting for root access...'; bash" C-m

echo "KoTH prep complete"
echo "- Target: $TARGET"
echo "- Notes: $NOTES"
echo "- Claim watch: $CLAIM_LOG"
echo "- Status: $STATUS_JSON"
echo "- tmux session: $SESSION"
echo ""
echo "Attach with: tmux a -t $SESSION"
echo ""
echo "[*] Claim watch started automatically (pane 4)"
echo "[*] After obtaining root SSH, start opponent watcher in pane 5:"
echo "    bash scripts/koth-opponent-watch.sh $TARGET --ssh-key /tmp/id_rsa --auto-capture"
