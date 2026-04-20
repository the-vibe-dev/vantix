# Dense Codex Context

fmt: id=<id> mode=<csv|*> role=<csv|*> phase=<phase> tags=<csv> ports=<csv> svc=<csv> pre=<conds> act=<bounded_action> verify=<proof> next=<next> block=<stop_conditions> refs=<paths>
load: use `python3 scripts/learn_engine.py --root . lookup tag:<tag> service:<svc> --format prompt`; do not read full playbooks unless no indexed match exists.

id=usage.start mode=* role=* phase=startup tags=startup,memory ports=* svc=* pre=new_session act=read_MEM+latest_index+targeted_digest verify=current_obj+next_known next=work block=stale_memory refs=AGENTS.md,MEM.md
id=usage.chat mode=pentest,bugbounty,ctf,koth,windows-ctf,windows-koth role=orchestrator phase=init tags=ui,api ports=* svc=* pre=target+objective act=POST_/api/v1/chat_or_UI_chat verify=run_id+messages next=review_skills block=missing_target refs=README.md,docs/api.md
id=usage.skills mode=* role=orchestrator phase=plan tags=skills,prompt ports=* svc=* pre=run_exists act=GET_/runs/<id>/skills+POST_apply_if_context_changed verify=prompt_paths_exist next=handoff block=registry_missing refs=docs/skill-authoring.md
id=usage.context_lookup mode=* role=* phase=all tags=lookup,token ports=* svc=* pre=target_facts act=learn_engine_lookup tag/service/port --format prompt verify=relevant_only next=load_slice block=no_index refs=scripts/learn_engine.py
id=usage.close mode=* role=* phase=close tags=memory,handoff ports=* svc=* pre=stop_or_switch act=codex-close --mode handoff|close --objective --done --next verify=session_index+handoff_updated next=handoff block=missing_next refs=scripts/codex-close.sh
