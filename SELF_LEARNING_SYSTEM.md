# Self-Learning System

The workspace keeps reusable lessons in a dense, machine-readable learning layer. Human-readable markdown is generated for review, not used as the only source of truth.

## Canonical Sources
- Method baseline: `PENTEST.md`
- Agent instructions: `AGENTS.md`
- Memory map: `MEM.md`
- Dense session index: `memory/session_index.jsonl`
- Learning corpus: `memory/learning/`

## Closeout
```bash
bash scripts/codex-close.sh --mode close --objective "..." --done "..." --next "..."
bash scripts/learn-ingest.sh
bash scripts/learn-report.sh
```

## Rules
- Convert misses into specific guardrails.
- Store reusable lessons as compact records.
- Track observed, inferred, and proven states separately.
- Keep target/client/private topology out of tracked memory.
- Prefer dense lookup output for startup context.

## CVE First Pass
When product/version evidence appears, query local intel first:
```bash
curl "http://127.0.0.1:8787/api/v1/cve/intel/search?q=<term>" -H "Authorization: Bearer <token>"
```
MCP clients can use the optional CVE MCP endpoint described in `docs/cve_mcp.md`.
