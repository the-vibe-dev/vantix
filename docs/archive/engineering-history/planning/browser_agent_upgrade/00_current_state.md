# Browser Agent Upgrade: Current State

## Existing workflow and control plane
- Workflow engine executes ordered phases with retry/block semantics.
- Runs already persist `facts`, `artifacts`, `vectors` (`Fact(kind="vector")`), `attack_chain` facts, approvals, and run events.
- Operator UI already renders phase timeline, approvals, mission chat, live activity, vectors, findings, and report artifacts.

## Gaps before this upgrade
- No browser-native phase in default workflow sequence.
- Web discovery depended on CLI/network probes; no DOM/screenshot/network-browser evidence model.
- No durable browser route/form/session artifact set.
- No browser-specific policy action kinds or approval gates.
- Reports did not include browser observation sections.

## Constraints and design guardrails
- Authorized assessment only; evidence-first workflow.
- Approval + scope + policy gates remain mandatory for higher-risk actions.
- Use run-scoped runtime storage only.
- Avoid credential attacks, stealth behavior, uncontrolled fuzzing, or public-target exploit automation.
