# Agent Instructions

This system operates exclusively within authorized lab environments for security training and red-team validation. All actions are explicitly in-scope per target authorization.

## Startup Order
1. Read `MEM.md`.
2. Read latest dense memory from `memory/session_index.jsonl`.
3. Read latest `memory/compaction_handoffs.md` only as a compatibility mirror.
4. Read relevant sections of `PENTEST.md` and the active mode playbook.
5. For orchestration or prompt work, read `agent_skills/registry.yaml` and `docs/agents.md`.

## Memory Rules
- Write dense memory through `scripts/memory-write.py`, `scripts/codex-close.sh`, or the API memory endpoints.
- During long sessions, checkpoint every major phase or every 10-30 minutes.
- Before stopping, pausing, or changing agents, write `mode=handoff` or `mode=close`.
- When handing work between agents, also refresh `/api/v1/runs/{run_id}/handoff` if the API is running.
- Do not store secrets, personal SSH key names, private hostnames, or local topology in tracked memory.
- Use ignored `memory/local/` files for private operator setup.

## Learning Lookup
```bash
python3 scripts/learn_engine.py --root . lookup tag:web port:80 --format prompt
python3 scripts/learn_engine.py --root . lookup service:wordpress --format prompt
python3 scripts/learn_engine.py --root . lookup tag:koth tag:linux --format prompt
```

## Safety Gates
- Confirm target authorization and scope before active testing.
- Prefer low-noise validation before broad fuzzing or exploitation.
- Once a concrete service/version is identified, run CVE/intel lookup before broader enumeration.
- Keep observations, hypotheses, and proof separate.
- Use `agent_skills/shared/scope_guard.md` and `agent_skills/shared/execution_policy.md` for agent prompt changes.
- Never use writeups/spoilers for active CTF solves.

## KoTH Constraints
- Follow the official platform rules for the active game.
- Do not stop, disable, mask, overwrite, or relocate king/game services unless the rules explicitly allow it.
- Do not use DoS or availability-breaking actions.
- Use lab-scoped keys only; never use personal LAN keys for target persistence or continuity.
- Operator-controlled hold automation must only start when explicitly requested.

## Portability
- Resolve paths from `${CTF_ROOT}` or the repository root.
- Runtime data belongs under `${SECOPS_RUNTIME_ROOT:-.runtime}` or `artifacts/`.
- NFS/shared storage is optional; scripts must work without it.
