# Workspace Memory Map

This tracked file is generic. Put local hostnames, private paths, SSH keys, cracking-node inventory, and operator-specific details in ignored `memory/local/MEM.local.md`.

## Startup Sources
1. `AGENTS.md`
2. Latest dense record in `memory/session_index.jsonl`
3. Latest compatibility mirror in `memory/compaction_handoffs.md`
4. Relevant sections of `PENTEST.md`

## Canonical Memory
- Dense index: `memory/session_index.jsonl`
- Per-session dense journals: `memory/sessions/<session_id>/journal.jsonl`
- Compatibility mirrors: `memory/session_journal.md`, `memory/compaction_handoffs.md`
- Learning corpus: `memory/learning/`

## Runtime Paths
- Runtime root: `${SECOPS_RUNTIME_ROOT:-.runtime}`
- Artifacts: `${SECOPS_ARTIFACTS_ROOT:-artifacts}`
- Optional shared root: `${SECOPS_SHARED_ROOT}`

## Local-Only Data
Use `memory/local/MEM.local.md` for:
- GPU cracking nodes
- private lab hosts
- personal wordlist paths
- SSH key paths
- internal service URLs
