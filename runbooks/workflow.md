# Dense Codex Context

fmt: id=<id> mode=<csv|*> role=<csv|*> phase=<phase> tags=<csv> ports=<csv> svc=<csv> pre=<conds> act=<bounded_action> verify=<proof> next=<next> block=<stop_conditions> refs=<paths>
load: use `python3 scripts/learn_engine.py --root . lookup tag:<tag> service:<svc> --format prompt`; do not read full playbooks unless no indexed match exists.

id=flow.start mode=* role=orchestrator phase=startup tags=workflow,startup ports=* svc=* pre=session_start act=load_MEM+latest_dense+targeted_context verify=current_obj next=plan block=missing_scope refs=AGENTS.md
id=flow.loop mode=* role=orchestrator phase=all tags=workflow ports=* svc=* pre=new_evidence act=update_facts+reapply_skills+refresh_handoff verify=next_actions next=delegate block=contradiction refs=docs/agents.md
id=flow.validate mode=* role=executor phase=execute tags=workflow,validation ports=* svc=* pre=selected_vector act=bounded_validation_only verify=proof_or_negative next=report_or_replan block=scope_gap refs=agent_skills/shared/execution_policy.md
