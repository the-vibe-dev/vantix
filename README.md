# VANTIX

Vantix is the control plane for autonomous security testing agents. It combines durable run orchestration, specialist agents, browser/runtime evidence, policy gates, approvals, and reporting in one local-first operator console.

## Quick Start

```bash
bash scripts/install-vantix.sh
bash scripts/vantixctl.sh start
```

API: `http://127.0.0.1:8787`  
UI: `http://127.0.0.1:4173`

Manual setup and update workflow are in [Getting Started](docs/getting-started.md).

## Core Strengths

- Durable multi-phase workflow engine with resumable runs
- Policy-gated execution and approval-driven escalation
- Evidence-first artifacts, facts, vectors, and reports
- Operator-visible orchestration, live activity, and run control
- Local CVE/intel integration and optional MCP endpoints
- Browser-native authorized web assessment phase

## Repository Layout

- `secops/` backend services, workflow engine, routers, models
- `frontend/` React/Vite operator UI
- `scripts/` install, update, runtime, validation utilities
- `tests/` backend and integration test suites
- `agent_skills/` skill packs and shared agent policy guidance
- `docs/` canonical product/operator/developer documentation
- `docs/archive/` historical and superseded documentation

## Documentation

- [Getting Started](docs/getting-started.md)
- [Operator Guide](docs/operator-guide.md)
- [Developer Guide](docs/developer-guide.md)
- [Architecture](docs/architecture.md)
- [Workflow Engine](docs/workflow-engine.md)
- [API](docs/api.md)
- [Security and Safety](docs/security-and-safety.md)
- [Capability Matrix](docs/capability-matrix.md)
- [Browser Agent](docs/browser_agent.md)
- [Browser Policies](docs/browser_policies.md)
- [XBOW Evaluation Workflow](docs/xbow-evaluation.md)

## Authorized Use Only

Vantix is for authorized defensive security testing, labs, and approved engagements. Operators are responsible for scope control, legal authorization, and policy-compliant execution.
