#!/usr/bin/env bash
set -euo pipefail
ID="${1:?id required}"
HASH_FILE="${2:?hash file required}"
while true; do
  if [ -f "$HASH_FILE" ]; then
    h=$(tr -d '\r\n' < "$HASH_FILE")
    if [ "${#h}" -ge 34 ]; then
      break
    fi
  fi
  sleep 10
done
${CTF_ROOT}/methods/sqli_resumable_wordpress/launch_id_crack_<CRACK_NODE_ID>.sh "$ID" "$HASH_FILE"
echo "[$(date '+%F %T')] id${ID} hash complete -> crack launched" >> ${CTF_ROOT}/extract/id${ID}_autocrack.log
