# Architecture

## System Layers

1. **Frontend (`frontend/`)**  
   React/Vite control plane for run creation, chat guidance, approvals, attack timeline, control-center health, vectors, browser/source evidence, and results.

2. **API and Control Plane (`secops/routers`, `secops/services`)**  
   FastAPI routers expose chat, run state, workflow data, approvals, vectors, artifacts, reporting, skills, and system status.

3. **Workflow Engine (`secops/services/workflows`)**  
   Durable DB-backed phase orchestration with retries, leases, checkpoints, and resume safety.

4. **Execution and Policy Layer (`secops/services/execution.py`, `secops/services/policies.py`)**  
   Phase handlers, safety gates, approval routing, source intake, browser/runtime evidence collection, and normalized error handling.

5. **Runtime Storage (`StorageLayout`)**  
   User-owned run state: prompts, logs, artifacts, evidence, reports, and memory.

## Specialist Roles

Core roles include orchestrator, recon, knowledge base, vector store, researcher, developer, executor, reporter, and browser (web assessment phase).

## Key Design Traits

- Chat-first run lifecycle with durable state
- Evidence-first outputs (artifacts/facts/vectors/report)
- Policy-gated execution with approvals
- Restart/resume tolerance through DB-backed workflow records
- Backward compatibility with `secops` internal package naming
