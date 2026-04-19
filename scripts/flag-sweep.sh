#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  flag-sweep.sh -t <target_ip> -i <ssh_key> [-u <user>] [-p <port>] [-o <local_output>] [--remote-out <path>] [--keep-remote] [--deep|--quick]

Examples:
  bash scripts/flag-sweep.sh -t 10.10.28.240 -i ${CTF_ROOT:-.}/.ssh/ctf_koth_root_ed25519
  bash scripts/flag-sweep.sh -t 10.10.28.240 -i ${CTF_ROOT:-.}/.ssh/ctf_koth_root_ed25519 -u root -o /tmp/CTF/flags_1028240.txt
USAGE
}

TARGET=""
SSH_KEY=""
SSH_USER="root"
SSH_PORT="22"
LOCAL_OUT=""
REMOTE_OUT=""
KEEP_REMOTE=0
REMOTE_MODE="deep"

while [[ $# -gt 0 ]]; do
  case "$1" in
    -t|--target) TARGET="${2:-}"; shift 2 ;;
    -i|--ssh-key) SSH_KEY="${2:-}"; shift 2 ;;
    -u|--user) SSH_USER="${2:-}"; shift 2 ;;
    -p|--port) SSH_PORT="${2:-}"; shift 2 ;;
    -o|--output) LOCAL_OUT="${2:-}"; shift 2 ;;
    --remote-out) REMOTE_OUT="${2:-}"; shift 2 ;;
    --keep-remote) KEEP_REMOTE=1; shift ;;
    --deep) REMOTE_MODE="deep"; shift ;;
    --quick) REMOTE_MODE="quick"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "[-] Unknown argument: $1" >&2; usage; exit 1 ;;
  esac
done

if [[ -z "$TARGET" || -z "$SSH_KEY" ]]; then
  echo "[-] Missing required arguments." >&2
  usage
  exit 1
fi

if [[ ! -f "$SSH_KEY" ]]; then
  echo "[-] SSH key not found: $SSH_KEY" >&2
  exit 1
fi

ts="$(date +%Y%m%d_%H%M%S)"
safe_target="${TARGET//./_}"
if [[ -z "$REMOTE_OUT" ]]; then
  REMOTE_OUT="/tmp/flag_sweep_${safe_target}_${ts}.txt"
fi
if [[ -z "$LOCAL_OUT" ]]; then
  mkdir -p /tmp/CTF
  LOCAL_OUT="/tmp/CTF/flag_sweep_${safe_target}_${ts}.txt"
fi

SSH_BASE=(ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 -i "$SSH_KEY" -p "$SSH_PORT" "$SSH_USER@$TARGET")
SCP_BASE=(scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 -i "$SSH_KEY" -P "$SSH_PORT")

echo "[*] Running remote flag sweep on ${SSH_USER}@${TARGET}:${SSH_PORT}"

"${SSH_BASE[@]}" "REMOTE_OUT='$REMOTE_OUT' REMOTE_MODE='$REMOTE_MODE' bash -s" <<'REMOTE_SCRIPT'
set +e
out="${REMOTE_OUT:-/tmp/flag_sweep.txt}"
tmp_paths="/tmp/.flag_paths_$$.txt"
tmp_hits="/tmp/.flag_hits_$$.txt"
tmp_tokens="/tmp/.flag_tokens_$$.txt"
mode="${REMOTE_MODE:-deep}"

if [[ "$mode" == "quick" ]]; then
  name_roots=(/root /home /opt /srv /var/www /var/ftp /tmp)
  content_roots=(/root /home /opt /srv /var/www /var/ftp /tmp)
else
  name_roots=(/root /home /opt /srv /var/www /var/ftp /tmp /etc /var/backups /usr/local /var/lib)
  content_roots=(/root /home /opt /srv /var/www /var/ftp /tmp /etc /var/backups /usr/local)
fi

{
  echo "==== FLAG SWEEP REPORT ===="
  date -Is
  echo "host=$(hostname)"
  echo "user=$(id)"
  echo "mode=$mode"
  echo

  echo "==== KNOWN EXACT PATHS ===="
  exact_paths=(
    /root/root.txt
    /root/user.txt
    /root/flag.txt
    /root/king.txt
    /home/*/root.txt
    /home/*/user.txt
    /home/*/flag.txt
    /var/ftp/flag.txt
    /var/www/flag.txt
    /flag.txt
  )

  found_any=0
  for p in "${exact_paths[@]}"; do
    for f in $p; do
      if [[ -f "$f" ]]; then
        found_any=1
        echo "--- $f ---"
        sed -n '1,5p' "$f" 2>/dev/null
      fi
    done
  done
  [[ "$found_any" -eq 0 ]] && echo "(no exact-path flags found)"
  echo

  echo "==== CANDIDATE FILES (NAME-BASED) ===="
  find "${name_roots[@]}" \
    -xdev -type f \
    ! -name '.flag_paths_*' ! -name '.flag_hits_*' ! -name 'flag_sweep_*' \
    \( -iname 'flag*' -o -iname '*flag*' -o -iname 'user.txt' -o -iname 'root.txt' -o -iname '*proof*' -o -iname '*token*' -o -iname '*secret*' -o -iname '*king*' -o -iname '*.flag' \) \
    2>/dev/null | sort -u | tee "$tmp_paths"
  echo

  echo "==== CONTENT MATCHES (THM/HTB/CTF/flag) ===="
  grep -R -I -n -E 'THM\{|HTB\{|picoCTF\{|CTF\{|flag\{|[A-Za-z0-9_]+\\{[A-Za-z0-9_+/=:-]{12,}\\}' \
    "${content_roots[@]}" 2>/dev/null | grep -vF "$out" | head -n 800 | tee "$tmp_hits"
  echo

  echo "==== CANDIDATE CONTENT PREVIEW ===="
  while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    [[ ! -f "$f" ]] && continue
    # Read small text-like files only for readability.
    size="$(wc -c < "$f" 2>/dev/null || echo 0)"
    if [[ "$size" -le 8192 ]]; then
      echo "--- $f (size=${size}) ---"
      sed -n '1,10p' "$f" 2>/dev/null
    fi
  done < "$tmp_paths"
  echo

  echo "==== EXTRACTED FLAG TOKENS ===="
  grep -R -I -h -Eo 'THM\{[^}]+\}|HTB\{[^}]+\}|picoCTF\{[^}]+\}|flag\{[^}]+\}|CTF\{[^}]+\}' \
    "${content_roots[@]}" 2>/dev/null | grep -vF "$out" | sort -u | tee "$tmp_tokens"
  echo

  echo "==== DECODED TOKEN BODIES (base64-like) ===="
  python3 - "$tmp_tokens" <<'PY'
import base64, re, sys
tok_file = sys.argv[1]
pat = re.compile(r'^[A-Za-z0-9+/=]+$')
seen = set()
try:
    lines = [x.strip() for x in open(tok_file, 'r', encoding='utf-8', errors='ignore')]
except FileNotFoundError:
    lines = []
for t in lines:
    m = re.match(r'^[A-Za-z0-9_]+\{([^}]+)\}$', t)
    if not m:
        continue
    body = m.group(1).strip()
    if len(body) < 12 or len(body) % 4 != 0 or not pat.match(body):
        continue
    if body in seen:
        continue
    seen.add(body)
    try:
        dec = base64.b64decode(body, validate=True)
        txt = dec.decode('utf-8', errors='replace')
        print(f'{t} -> {txt}')
    except Exception:
        pass
PY
  echo

  echo "==== SUMMARY ===="
  echo "candidate_file_count=$(wc -l < "$tmp_paths" 2>/dev/null || echo 0)"
  echo "content_match_count=$(wc -l < "$tmp_hits" 2>/dev/null || echo 0)"
  echo "token_count=$(wc -l < "$tmp_tokens" 2>/dev/null || echo 0)"
} > "$out"

chmod 600 "$out" 2>/dev/null || true
rm -f "$tmp_paths" "$tmp_hits" "$tmp_tokens"
echo "$out"
REMOTE_SCRIPT

echo "[*] Pulling report to local file: $LOCAL_OUT"
"${SCP_BASE[@]}" "${SSH_USER}@${TARGET}:${REMOTE_OUT}" "$LOCAL_OUT" >/dev/null

if [[ "$KEEP_REMOTE" -eq 0 ]]; then
  "${SSH_BASE[@]}" "rm -f '$REMOTE_OUT'" >/dev/null 2>&1 || true
fi

echo "[+] Flag sweep report saved: $LOCAL_OUT"
echo "[+] Top of report:"
sed -n '1,80p' "$LOCAL_OUT"
