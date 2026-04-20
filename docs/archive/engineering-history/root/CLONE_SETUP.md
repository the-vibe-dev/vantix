# Clone Setup

## 1. Install

Preferred:
```bash
bash scripts/install-vantix.sh
```

Manual:
```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -e ".[dev]"
cp .env.example .env
```

## 2. Configure
Edit `.env` and set at minimum:
```bash
SECOPS_REPO_ROOT=/path/to/CTF
SECOPS_RUNTIME_ROOT=/path/to/CTF/.runtime
SECOPS_API_TOKEN=change-me
```

## 3. Verify Permissions
```bash
bash scripts/doctor.sh
```

If files were created as root inside runtime paths:
```bash
bash scripts/fix-permissions.sh --apply
```

## 4. Start API
```bash
export SECOPS_API_TOKEN=dev
bash scripts/secops-api.sh
```

Open `http://127.0.0.1:8787/docs`.

## 5. Optional CVE MCP
```bash
SECOPS_ENABLE_CVE_MCP=true SECOPS_API_TOKEN=dev bash scripts/secops-api.sh
```
MCP URL: `http://127.0.0.1:8787/mcp/cve`.

Repo-local CVE search helper:
```bash
bash scripts/secops-cve-search.sh start
bash scripts/secops-cve-search.sh status
bash scripts/secops-cve-search.sh update
```

## 6. Optional Cracking Node
Copy `agent_ops/config/cracking_nodes.example.yaml` to `agent_ops/config/cracking_nodes.yaml`, fill in your own GPU host, then run:
```bash
bash scripts/crack-node-doctor.sh --node gpu-primary
```
