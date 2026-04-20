# Testing

## Full Local Check

```bash
bash scripts/check-all.sh
```

This runs compile checks, optional quality tools (`ruff`, `mypy`, `bandit` when installed), pytest, shell checks, sanitizer/doctor checks, and frontend build.

## Backend Tests

```bash
pytest -q
pytest -q tests/test_api.py
pytest -q tests/test_skills.py
pytest -q tests/test_workflow_engine.py tests/test_resume_and_retry.py tests/test_phase_handlers.py tests/test_reporting.py
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

## Durable Workflow Focused Checks

Recommended targeted checks during orchestration work:

```bash
pytest -q tests/test_workflow_engine.py
pytest -q tests/test_resume_and_retry.py
pytest -q tests/test_phase_handlers.py
pytest -q tests/test_reporting.py
timeout 240 pytest -q tests/test_api.py -k 'vantix_chat_creates_run_scheduler_state_and_vectors or start_run_creates_live_state_and_approval_when_codex_disabled'
```
