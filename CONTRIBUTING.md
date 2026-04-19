# Contributing

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -e ".[dev]"
cd frontend && corepack pnpm install
```

Copy `.env.example` to `.env` and set only local, non-secret defaults. Do not commit `.env`, runtime DBs, artifacts, private targets, provider keys, or operator-specific topology.

## Validation

Run before handing work to another agent or opening a PR:

```bash
bash scripts/check-all.sh
```

If the frontend toolchain is not installed, run at least:

```bash
python3 -m compileall -q secops scripts/memory-write.py
pytest -q
bash scripts/sanitize-check.sh
bash scripts/doctor.sh
```

## Coding Rules

- Keep generated state out of the repo.
- Preserve the `secops` internal package name unless doing an explicit migration.
- Use Vantix names in product docs and UI.
- Keep agent notes dense and machine-readable.
- Add tests for new APIs, skill selection behavior, memory writes, and safety gates.
- Do not copy code or prompt text from external reference projects.
