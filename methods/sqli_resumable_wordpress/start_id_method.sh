#!/usr/bin/env bash
set -euo pipefail
ID="${1:?id}"
IP="${2:-10.66.179.145}"
OUT_DIR="${CTF_ROOT}/extract"
mkdir -p "$OUT_DIR"

tmux kill-session -t ctf-id${ID} 2>/dev/null || true
tmux new-session -d -s ctf-id${ID} "python3 -u /tmp/extract_id_loop.py --id $ID --ip $IP --sleep 1 --maxlen 60 --out $OUT_DIR/id${ID}.hash --log $OUT_DIR/id${ID}_extract.log"

tmux kill-session -t ctf-id${ID}-autocrack 2>/dev/null || true
tmux new-session -d -s ctf-id${ID}-autocrack "${CTF_ROOT}/extract/auto_crack_on_complete.sh $ID $OUT_DIR/id${ID}.hash"

echo "Started ctf-id${ID} + ctf-id${ID}-autocrack"
