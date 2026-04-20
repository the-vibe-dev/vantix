# API

Base URL: `http://127.0.0.1:8787`

If `SECOPS_API_TOKEN` is set, send:

```text
Authorization: Bearer <token>
```

## Health and System

```bash
curl -s http://127.0.0.1:8787/api/v1/system/status
curl -s http://127.0.0.1:8787/api/v1/system/install-status
```

## Chat / Run Control

Start run:

```bash
curl -s http://127.0.0.1:8787/api/v1/chat \
  -H 'Content-Type: application/json' \
  -d '{"message":"Full test of https://example.test","mode":"pentest"}'
```

Continue run:

```bash
curl -s http://127.0.0.1:8787/api/v1/chat \
  -H 'Content-Type: application/json' \
  -d '{"run_id":"<run_id>","message":"Continue to next phase with low-noise validation"}'
```

## Run Data

```bash
curl -s http://127.0.0.1:8787/api/v1/runs/<run_id>/graph
curl -s http://127.0.0.1:8787/api/v1/runs/<run_id>/messages
curl -s http://127.0.0.1:8787/api/v1/runs/<run_id>/vectors
curl -s http://127.0.0.1:8787/api/v1/runs/<run_id>/results
curl -s http://127.0.0.1:8787/api/v1/runs/<run_id>/browser-state
```

## Skills

```bash
curl -s http://127.0.0.1:8787/api/v1/skills
curl -s -X POST http://127.0.0.1:8787/api/v1/runs/<run_id>/skills/apply
```

## Attack Chains

```bash
curl -s http://127.0.0.1:8787/api/v1/runs/<run_id>/attack-chains
curl -s -X POST http://127.0.0.1:8787/api/v1/runs/<run_id>/attack-chains \
  -H 'Content-Type: application/json' \
  -d '{"name":"Recon to validation","score":70,"steps":[{"phase":"recon"},{"phase":"validate"}]}'
```

## CVE and Intel

```bash
curl -s "http://127.0.0.1:8787/api/v1/cve/search?vendor=apache&product=struts&live_on_miss=true"
```

For MCP usage details, see archived operational references under `docs/archive/engineering-history/`.
