# Dense Memory

Canonical memory is dense JSONL. Markdown files are compatibility mirrors.

## Schema
```json
{"v":1,"ts":"...","sid":"s-...","run_id":"...","agent":"local:pid","mode":"checkpoint","phase":"recon","ctx":["web"],"obj":"...","done":["..."],"facts":[["port","80"]],"issues":[],"next":"...","files":["${CTF_ROOT}/..."],"seq":1}
```

Long paths are compacted at write time:
- Repository paths become `${CTF_ROOT}`.
- Runtime paths become `${SECOPS_RUNTIME_ROOT}`.
- User home paths become `${HOME}`.

## Commands
```bash
bash scripts/codex-start.sh --print-only
bash scripts/codex-close.sh --mode checkpoint --objective "..." --done "..." --next "..."
python3 scripts/memory-write.py --mode handoff --objective "..." --done "..." --next "..."
bash scripts/memory-health.sh
```

The API also exposes `/api/v1/memory/checkpoint`, `/api/v1/memory/handoff`, `/api/v1/memory/latest`, and `/api/v1/memory/health`.
