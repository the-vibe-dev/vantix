# Dense Codex Context

fmt: id=<id> mode=<csv|*> role=<csv|*> phase=<phase> tags=<csv> ports=<csv> svc=<csv> pre=<conds> act=<bounded_action> verify=<proof> next=<next> block=<stop_conditions> refs=<paths>
load: use `python3 scripts/learn_engine.py --root . lookup tag:<tag> service:<svc> --format prompt`; do not read full playbooks unless no indexed match exists.

id=agent.startup mode=* role=* phase=startup tags=startup,memory,lookup ports=* svc=* pre=session_start act=read_MEM+latest_session_index+targeted_context_lookup verify=obj+next+blockers_known next=work block=scope_unknown refs=MEM.md
id=agent.memory mode=* role=* phase=all tags=memory,handoff ports=* svc=* pre=phase_change|blocker|switch|close act=memory-write_mode_phase_handoff_close verify=session_index_updated next=continue block=secret_or_private_topology refs=scripts/memory-write.py
id=agent.lookup mode=* role=* phase=all tags=lookup,token ports=* svc=* pre=need_methodology act=learn_engine context mode:<mode> tag:<tag> service:<svc> port:<port> verify=relevant_records_only next=apply block=full_playbook_load refs=scripts/learn_engine.py
id=agent.safety mode=* role=* phase=all tags=scope,safety ports=* svc=* pre=active_action act=confirm_scope+low_noise+proof_separation verify=obs_hypothesis_proof_split next=execute_or_block block=out_of_scope|dos|unknown_auth refs=agent_skills/shared/scope_guard.md
id=agent.koth mode=koth,windows-koth role=* phase=all tags=koth,safety ports=9999 svc=koth pre=round_active act=preserve_availability+no_king_service_tamper+operator_hold_only verify=rules_checked next=continue block=rule_conflict refs=methods/thm_general/koth_playbook.md
id=agent.intel mode=* role=* phase=all tags=lookup,intel,recon ports=* svc=* pre=recon_focus_or_agent_task act=read_LOOKUP+run_context_lookup_from_focus verify=loaded_records_match_focus next=task block=broad_context_load refs=LOOKUP.md
