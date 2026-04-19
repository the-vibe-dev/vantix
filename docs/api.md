# API Guide

Base URL: `http://127.0.0.1:8787`

Set `SECOPS_API_TOKEN` to require bearer auth. When configured, send:

```bash
Authorization: Bearer <token>
```

## Bootstrap And Tooling

```bash
curl -s http://127.0.0.1:8787/api/v1/system/status
curl -s http://127.0.0.1:8787/api/v1/system/install-status
curl -s http://127.0.0.1:8787/api/v1/tools
curl -s http://127.0.0.1:8787/api/v1/tools/suites
curl -s -X POST http://127.0.0.1:8787/api/v1/tools/install \
  -H 'Content-Type: application/json' \
  -d '{"suite":"common","apply":false}'
curl -s http://127.0.0.1:8787/api/v1/tools/install/history
```

`/api/v1/system/status` and `/api/v1/system/install-status` include git/update metadata when the repo has an `origin/main` remote. Updates are applied through `bash scripts/update-vantix.sh`, not through the API.

## Chat

Start a run:

```bash
curl -s http://127.0.0.1:8787/api/v1/chat \
  -H 'Content-Type: application/json' \
  -d '{"message":"Full test of https://example.test","mode":"pentest"}'
```

Continue a run:

```bash
curl -s http://127.0.0.1:8787/api/v1/chat \
  -H 'Content-Type: application/json' \
  -d '{"run_id":"<run_id>","message":"prioritize low-noise web checks"}'
```

## Run Review

```bash
curl -s http://127.0.0.1:8787/api/v1/runs/<run_id>/graph
curl -s http://127.0.0.1:8787/api/v1/runs/<run_id>/messages
curl -s http://127.0.0.1:8787/api/v1/runs/<run_id>/skills
curl -s http://127.0.0.1:8787/api/v1/runs/<run_id>/handoff
curl -s http://127.0.0.1:8787/api/v1/runs/<run_id>/vectors
curl -s http://127.0.0.1:8787/api/v1/runs/<run_id>/results
```

## Skills

List installed packs:

```bash
curl -s http://127.0.0.1:8787/api/v1/skills
```

Reapply skill selection after adding facts or changing run context:

```bash
curl -s -X POST http://127.0.0.1:8787/api/v1/runs/<run_id>/skills/apply
```

## Attack Chains

Create a modeled path:

```bash
curl -s http://127.0.0.1:8787/api/v1/runs/<run_id>/attack-chains \
  -H 'Content-Type: application/json' \
  -d '{"name":"Recon to validated finding","score":70,"steps":[{"phase":"recon"},{"phase":"validate"}]}'
```

List chains:

```bash
curl -s http://127.0.0.1:8787/api/v1/runs/<run_id>/attack-chains
```
