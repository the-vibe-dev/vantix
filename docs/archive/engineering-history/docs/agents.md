# Vantix Agents

Vantix uses durable specialist records to coordinate Codex-driven work. The backend still uses the `secops` package internally, but product-facing docs and UI use Vantix names.

## Roles

| Role | Product Name | Responsibility |
| --- | --- | --- |
| `orchestrator` | Vantix Orchestrator | Normalize scope, decide phase transitions, write handoffs. |
| `recon` | Vantix Recon | Low-noise target discovery and service facts. |
| `knowledge_base` | Knowledge Base | Load memory, methods, prior cases, and tool notes. |
| `vector_store` | Vector Store | Rank candidate paths and similar prior work. |
| `researcher` | Researcher | Correlate CVE, exploit, and source intelligence. |
| `developer` | Vantix Forge | Build validation helpers and lab notes when evidence supports it. |
| `executor` | Vantix Exploit | Execute selected vectors through current approval/execution controls. |
| `reporter` | Vantix Report | Produce findings, evidence, artifacts, and next actions. |

## Skill Flow

1. A chat request creates or replans a run through `POST /api/v1/chat`.
2. `VantixScheduler` seeds tasks, agents, and the initial vector.
3. `SkillApplicationService` selects skill packs by role, run mode, and target/objective keywords.
4. Prompts are written to the user-owned runtime path under `runs/<workspace>/prompts/`.
5. Agent metadata stores `selected_skills`, `skill_count`, and prompt paths for UI and API review.

## Handoff Contract

Agents should produce dense JSON-compatible notes with these keys:

```json
{
  "obs": [],
  "evidence": [],
  "risk": [],
  "next": [],
  "blocked": [],
  "vectors": []
}
```

Use concise machine-readable statements. Do not write long explanations unless a human report is explicitly requested.

## Safety

All active actions must be inside scope, evidence-backed, and compatible with current execution settings. If scope or authorization is unclear, create a blocker instead of proceeding.
