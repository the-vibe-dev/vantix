# Codex-Native Security Operations Platform

## Purpose
This backend turns the current `${CTF_ROOT}` repo into an application platform without discarding the existing mode-specific workflows, learning system, or shell/Python tools.

## Design Rules
- `codex` CLI remains the only agent execution runtime.
- `CTF`, `KoTH`, `pentest`, and `bugbounty` stay first-class modes.
- Existing repo docs and learning files remain source of truth.
- Existing scripts are wrapped as adapters before any rewrite.
- `cve-search` stays the primary CVE intelligence source.

## Implemented Foundation
- `FastAPI` backend in `secops/`
- SQLAlchemy persistence layer for engagements, runs, tasks, actions, artifacts, findings, and memory events
- Mode profiles that preserve current startup/read-order behavior
- Context builder that assembles Codex-ready prompts from:
  - `MEM.md`
  - latest handoffs/journal
  - relevant `PENTEST.md` sections
  - mode playbooks
  - `learn_engine.py startup-digest`
- Script adapter catalog for the current shell/Python tooling
- CVE search API wrapper over local `cve-search`

## Operational Layer
- NAS-backed run layout under `${SECOPS_SHARED_ROOT}/secops/runs/<workspace_id>/`
- Background execution manager for:
  - learning recall
  - recon sidecar
  - CVE analysis sidecar
  - primary Codex orchestration
  - learning ingest
  - summary report generation
- Live SSE event stream for terminal/log updates
- Approval queue and operator note endpoints
- React/Vite frontend for launch, monitoring, approvals, learning hits, and terminal view

## Near-Term Extensions
- Deepen sidecar orchestration and richer replan semantics
- Add database mirrors for the full JSONL learning corpus
- Add richer report/finding synthesis from live run facts
- Add distributed worker dispatch while keeping NAS as shared evidence plane
