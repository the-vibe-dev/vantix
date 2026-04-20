# Developer Guide

## Local Development

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -e ".[dev]"
.venv/bin/python -m playwright install chromium
cp .env.example .env
```

Backend:

```bash
bash scripts/secops-api.sh
```

Frontend:

```bash
cd frontend
corepack pnpm install
corepack pnpm dev
```

## Test Commands

Full check:

```bash
bash scripts/check-all.sh
```

Focused suites:

```bash
pytest -q
pytest -q tests/test_workflow_engine.py tests/test_resume_and_retry.py tests/test_phase_handlers.py tests/test_reporting.py tests/test_browser_agent.py
cd frontend && corepack pnpm build
```

## Runtime and Configuration

- Runtime state is user-owned under `SECOPS_RUNTIME_ROOT`.
- Main config is in `.env` (`SECOPS_*` and `VANTIX_*` variables).
- Do not run core services with `sudo`.
- Use `bash scripts/doctor.sh` for environment checks.

## Script Conventions

- Install/update lifecycle: `scripts/install-vantix.sh`, `scripts/update-vantix.sh`.
- Local service lifecycle: `scripts/vantixctl.sh`.
- CVE ingest and smoke checks: `scripts/backfill-cve-intel.sh`, `scripts/smoke-cve-intel.sh`.
- Browser runtime bootstrap: `.venv/bin/python -m playwright install chromium`.

## Contribution Expectations

- Keep docs and API behavior aligned.
- Add/adjust tests with behavior changes.
- Keep secrets, local topology, and runtime artifacts out of commits.
