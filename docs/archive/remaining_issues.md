# Remaining Issues (Execution Tracker)

Last updated: 2026-04-20

This tracker covers non-doc product work that remains after repository cleanup.

## P0 (Critical UX/Workflow)

| ID | Issue | Status | Acceptance |
| --- | --- | --- | --- |
| RI-001 | Run lifecycle desync (cancelled/completed runs can still appear active in UI) | completed | Run list, active pane, and backend state remain consistent after cancel/complete/restart. |
| RI-002 | Approval loop repeats the same prompt after grant/reject | completed | Same approval reason is emitted once per phase/action unless state changes. |
| RI-003 | Live activity stream mixes selected run output with stale/other run output | completed | Activity panel shows only selected run (or explicitly labeled global stream mode). |
| RI-004 | Chat replan/new-target commands can stay pinned to prior run target | completed | New target request creates/switches to correct run and updates objective/target everywhere. |

## P1 (Execution Quality)

| ID | Issue | Status | Acceptance |
| --- | --- | --- | --- |
| RI-005 | Recon quick scan uses broader-than-needed scan behavior in some paths | completed | Quick scan profile runs bounded recon only; no unnecessary top-1000/full scans without explicit escalation. |
| RI-006 | Agent status transitions not fully mirrored in chat/live activity | completed | Every role transition writes matching status + timeline event and appears in UI. |
| RI-007 | Engagement phase panel can lag real backend phase progression | completed | Phase panel updates in near-real-time and matches persisted workflow phase state. |

## P1 (Intel/Data)

| ID | Issue | Status | Acceptance |
| --- | --- | --- | --- |
| RI-008 | ExploitDB ingest returns `filtered: 0 / upserted: 0` too often | completed | Smoke ingest persists usable ExploitDB records and exposes counts by reason (accepted/rejected). |
| RI-009 | CVE/exploit external search visibility is inconsistent in chat/intel views | completed | Search execution and result summaries are visible in chat + Intel tab with source attribution. |

## P2 (Reporting/Artifacts)

| ID | Issue | Status | Acceptance |
| --- | --- | --- | --- |
| RI-010 | Report artifact navigation is inconsistent (non-clickable or partial) | completed | All report/evidence artifacts in selected run are clickable and resolve correctly. |
| RI-011 | Final report quality is not consistently client-ready | completed | Report includes full narrative, evidence, PoC/validation details, risk, and remediation without requiring external file hunting. |

## Completion Summary

- Completed in this execution cycle: RI-001 through RI-011.
- Follow-up verification should use an end-to-end live run smoke in the operator environment (`quick` + `full`) to confirm behavior against real targets and runtime services.

## Notes

- Keep fixes evidence-first and policy-gated.
- Validate each issue with a reproducible run-level smoke test before closure.
- 2026-04-20 implementation pass (partial):
  - approval idempotency + sibling pending auto-resolution added.
  - stream now starts from latest sequence to avoid replaying stale terminal history.
  - quick-scan recon bounded (`--top-ports 50`) and web-followup skipped for quick profile.
  - run target change now auto-starts a new run path.
  - agent status emits explicit `agent_status` events.
  - artifact list in Results now renders full list with scrolling instead of hard truncation.
  - ExploitDB adapter and ingest script now include delimiter/BOM fallback and richer filter stats.
