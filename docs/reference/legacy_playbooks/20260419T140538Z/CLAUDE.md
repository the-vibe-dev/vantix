# Claude/Codex Agent Notes

Read `AGENTS.md`, `PLAN2.md`, and `docs/architecture.md` before changing orchestration, memory, skills, or runtime behavior.

## Current Priorities

- Keep runtime writes user-owned and outside tracked source.
- Improve Vantix UI/API without breaking existing `secops.*` imports.
- Use `agent_skills/` for compact specialist behavior instead of long prompt prose.
- Write memory checkpoints at startup, phase changes, blockers, handoffs, and close.

## Handoff Format

Prefer compact records:

```text
mode=handoff run=<id> phase=<phase> done=[] issues=[] next=[] files=[] facts=[]
```

## Safety

Assume authorized lab use only. If scope is missing or ambiguous, block and ask for scope rather than executing active actions.
