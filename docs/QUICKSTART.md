# VANTIX Quick Start

## Interactive install

```bash
bash scripts/install-vantix.sh
```

## Manual setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -e ".[dev]"
cp .env.example .env
export SECOPS_API_TOKEN=dev
bash scripts/doctor.sh
bash scripts/secops-api.sh
```

## Frontend

```bash
cd frontend
corepack pnpm install
corepack pnpm dev
```

## Start a run

```bash
curl -s http://127.0.0.1:8787/api/v1/chat   -H 'Content-Type: application/json'   -d '{"message":"Full test of https://example.test","mode":"pentest"}'
```

## Continue a run

```bash
curl -s http://127.0.0.1:8787/api/v1/chat   -H 'Content-Type: application/json'   -d '{"run_id":"<run_id>","message":"Refresh recon and focus on low-noise validation."}'
```

## Review run data

```bash
curl -s http://127.0.0.1:8787/api/v1/runs/<run_id>/messages
curl -s http://127.0.0.1:8787/api/v1/runs/<run_id>/vectors
curl -s http://127.0.0.1:8787/api/v1/runs/<run_id>/results
```
