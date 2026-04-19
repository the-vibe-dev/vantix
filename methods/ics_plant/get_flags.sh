#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <target_ip>"
  exit 1
fi

IP="$1"

echo "[*] flag1:" && curl -fsS "http://${IP}/flag1.txt" || true
echo
echo "[*] flag2:" && curl -fsS "http://${IP}/flag2.txt" || true
echo
