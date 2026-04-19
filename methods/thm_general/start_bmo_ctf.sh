#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <TARGET_IP> [ROOM_DOMAIN]"
  echo "Example: $0 10.10.10.10 bmo.thm"
  exit 1
fi

IP="$1"
DOMAIN="${2:-}"

echo "[+] Target IP: $IP"
if [[ -n "$DOMAIN" ]]; then
  echo "[+] Room domain: $DOMAIN"
fi

echo "[+] Health gate"
ip -brief addr show tun0 || true
ip route | grep -E '10\\.64\\.0\\.0/12|tun0' || true

for i in {1..3}; do
  echo "[+] Probe $i"
  timeout 3 bash -lc "echo >/dev/tcp/${IP}/80" && echo "80 open" || echo "80 fail"
  sleep 1
done

echo "[+] Initial recon (low noise)"
nmap -Pn -n -sC -sV -p- --min-rate 1200 -T3 "$IP" -oN "${CTF_ROOT}/notes/${IP}_fullscan.txt"

if [[ -n "$DOMAIN" ]]; then
  if ! grep -qE "\\s${DOMAIN}(\\s|$)" /etc/hosts; then
    echo "[+] Adding hosts entry for ${DOMAIN}"
    echo "${IP} ${DOMAIN}" | sudo tee -a /etc/hosts >/dev/null
  fi
fi

echo "[+] CVE API quick check"
curl -m 4 -s -o /tmp/cve_api_check.json -w 'HTTP:%{http_code}\n' http://127.0.0.1:5000/api/ || true

echo "[+] Done. Next: map versions -> vendor/product -> /api/browse + /api/search"
