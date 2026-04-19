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
JOB_ID="${JOB_ID:-}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --job-id) JOB_ID="$2"; shift 2 ;;
    -h|--help) echo "Usage: $0 --job-id <JOB_ID>"; exit 0 ;;
    *) JOB_ID="$1"; shift ;;
  esac
done
[[ -n "$JOB_ID" ]] || { echo "Usage: $0 --job-id <JOB_ID>" >&2; exit 2; }
python3 - "$RUNTIME_ROOT" "$JOB_ID" <<'PY'
import sys, json, subprocess
from pathlib import Path
runtime_root=Path(sys.argv[1]); job=sys.argv[2]
local=runtime_root/'cracking'/job
manifest=json.loads((local/'manifest.json').read_text())
remote=manifest['remote']; remote_dir=manifest['remote_dir']; key=manifest.get('ssh_key','')
scp=['scp'];
if key: scp += ['-i', key]
subprocess.call(scp+[f'{remote}:{remote_dir}/hashcat.log', str(local/'hashcat.log')])
subprocess.call(scp+[f'{remote}:{remote_dir}/potfile.txt', str(local/'potfile.txt')])
print(local)
PY
python3 "$ROOT_DIR/scripts/memory-write.py" --root "$ROOT_DIR" --mode checkpoint --phase cracking --objective "cracking job $JOB_ID" --done "fetched cracking results" --file "$RUNTIME_ROOT/cracking/$JOB_ID" --context "cracking" >/dev/null || true
