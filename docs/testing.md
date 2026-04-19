# Testing

## Full Local Check

```bash
bash scripts/check-all.sh
```

This runs Python compile checks, pytest, shell syntax checks, sanitizer checks, doctor checks, and the frontend build when pnpm/corepack are available.

## Backend Tests

```bash
pytest -q
pytest -q tests/test_api.py
pytest -q tests/test_skills.py
```

## Frontend Build

```bash
cd frontend
corepack pnpm install
corepack pnpm build
```

## Runtime Smoke Test

```bash
SECOPS_ENABLE_CODEX_EXECUTION=false SECOPS_ENABLE_SCRIPT_EXECUTION=false bash scripts/secops-api.sh
```

Then create a run from the UI or API. The executor should block safely when execution is disabled, while chat, scheduler, skills, vectors, and handoff APIs remain usable.
