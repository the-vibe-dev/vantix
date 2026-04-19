#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="${CTF_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
default_runtime_root() {
  local state_home="${XDG_STATE_HOME:-$HOME/.local/state}"
  local repo_id
  repo_id="$(printf '%s' "$ROOT_DIR" | sha1sum | awk '{print substr($1,1,8)}')"
  printf '%s/ctf-security-ops/%s-%s\n' "$state_home" "$(basename "$ROOT_DIR")" "$repo_id"
}
RUNTIME_ROOT="${SECOPS_RUNTIME_ROOT:-$(default_runtime_root)}"
NODE=""; HASH_FILE=""; HASH_MODE=""; WORDLIST=""; JOB_ID="crack-$(date -u +%Y%m%dT%H%M%SZ)"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --node) NODE="$2"; shift 2 ;;
    --hash-file) HASH_FILE="$2"; shift 2 ;;
    --hash-mode|-m) HASH_MODE="$2"; shift 2 ;;
    --wordlist|-w) WORDLIST="$2"; shift 2 ;;
    --job-id) JOB_ID="$2"; shift 2 ;;
    -h|--help) echo "Usage: $0 --node <id> --hash-file hashes.txt --hash-mode <mode> --wordlist wordlist.txt"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ -f "$HASH_FILE" ]] || { echo "missing hash file" >&2; exit 1; }
[[ -n "$HASH_MODE" ]] || { echo "missing --hash-mode" >&2; exit 1; }
python3 - "$ROOT_DIR" "$RUNTIME_ROOT" "$NODE" "$HASH_FILE" "$HASH_MODE" "$WORDLIST" "$JOB_ID" <<'PY'
import sys, subprocess, yaml, json
from pathlib import Path
root=Path(sys.argv[1]); runtime_root=Path(sys.argv[2]); node_id=sys.argv[3]; hash_file=Path(sys.argv[4]); mode=sys.argv[5]; wordlist=sys.argv[6]; job_id=sys.argv[7]
conf=yaml.safe_load((root/'agent_ops/config/cracking_nodes.yaml').read_text())
node={n.get('id'):n for n in conf.get('cracking_nodes', [])}.get(node_id)
if not node: raise SystemExit('node not found')
host=node['host']; user=node['user']; key=str(Path(node.get('ssh_key','')).expanduser()); work=node.get('work_dir','~/ctf_crack'); hashcat=node.get('hashcat_bin','hashcat')
remote=f'{user}@{host}'; remote_dir=f'{work}/{job_id}'
base=['ssh']; scp=['scp']
if key: base += ['-i',key]; scp += ['-i',key]
subprocess.check_call(base+[remote, f'mkdir -p {remote_dir}'])
subprocess.check_call(scp+[str(hash_file), f'{remote}:{remote_dir}/hashes.txt'])
wl_arg=''
if wordlist:
    wl=Path(wordlist); subprocess.check_call(scp+[str(wl), f'{remote}:{remote_dir}/{wl.name}']); wl_arg=f'{remote_dir}/{wl.name}'
cmd=f'cd {remote_dir} && tmux new-session -d -s {job_id} "{hashcat} -m {mode} hashes.txt {wl_arg} -O --potfile-path potfile.txt > hashcat.log 2>&1"'
subprocess.check_call(base+[remote, cmd])
local=runtime_root/'cracking'/job_id; local.mkdir(parents=True, exist_ok=True)
(local/'manifest.json').write_text(json.dumps({'job_id':job_id,'node':node_id,'remote':remote,'remote_dir':remote_dir,'hash_mode':mode,'ssh_key':key}, indent=2)+'\n')
print(job_id)
PY
