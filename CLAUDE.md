# Dense Codex Context

fmt: id=<id> mode=<csv|*> role=<csv|*> phase=<phase> tags=<csv> ports=<csv> svc=<csv> pre=<conds> act=<bounded_action> verify=<proof> next=<next> block=<stop_conditions> refs=<paths>
load: use `python3 scripts/learn_engine.py --root . lookup tag:<tag> service:<svc> --format prompt`; do not read full playbooks unless no indexed match exists.

id=claude.priorities mode=* role=* phase=startup tags=startup,codex ports=* svc=* pre=agent_session act=read_AGENTS+PLAN2+architecture_then_targeted_lookup verify=scope+next known next=work block=full_context_dump refs=AGENTS.md,docs/architecture.md
id=claude.notes mode=* role=* phase=all tags=memory,dense ports=* svc=* pre=handoff_needed act=mode=handoff run=<id> phase=<phase> done=[] issues=[] next=[] files=[] facts=[] verify=memory_health next=transfer block=missing_next refs=scripts/codex-close.sh
id=claude.guard mode=* role=* phase=all tags=safety,scope ports=* svc=* pre=ambiguous_scope act=block+ask_for_scope verify=authorization_known next=resume block=out_of_scope refs=agent_skills/shared/scope_guard.md
id=claude.lookup mode=* role=* phase=all tags=lookup,intel ports=* svc=* pre=agent_needs_context act=read_LOOKUP+use_recon_focus_schema verify=no_full_context_dump next=continue block=missing_focus refs=LOOKUP.md
