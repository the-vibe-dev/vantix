#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="${CTF_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
NODE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --node) NODE="$2"; shift 2 ;;
    -h|--help) echo "Usage: $0 --node <id>"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
python3 - "$ROOT_DIR" "$NODE" <<'PY'
import sys, subprocess, yaml
from pathlib import Path
root=Path(sys.argv[1]); node_id=sys.argv[2]
path=root/'agent_ops/config/cracking_nodes.yaml'
if not path.exists():
    print(f"missing config: {path}\ncopy agent_ops/config/cracking_nodes.example.yaml first", file=sys.stderr); sys.exit(1)
conf=yaml.safe_load(path.read_text()) or {}
nodes={n.get('id'):n for n in conf.get('cracking_nodes', [])}
node=nodes.get(node_id) if node_id else next(iter(nodes.values()), None)
if not node:
    print('node not found', file=sys.stderr); sys.exit(1)
host=node['host']; user=node['user']; key=node.get('ssh_key',''); work=node.get('work_dir','~/ctf_crack'); hashcat=node.get('hashcat_bin','hashcat')
cmd=['ssh']
if key: cmd += ['-i', str(Path(key).expanduser())]
cmd += ['-o','BatchMode=yes','-o','ConnectTimeout=10',f'{user}@{host}', f'mkdir -p {work} && test -w {work} && {hashcat} --version && ({hashcat} -I || true)']
print('checking', node.get('id'), f'{user}@{host}')
res=subprocess.run(cmd, text=True, capture_output=True, check=False)
print(res.stdout)
if res.returncode:
    print(res.stderr, file=sys.stderr)
sys.exit(res.returncode)
PY
