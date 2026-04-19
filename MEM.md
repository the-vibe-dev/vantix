# Dense Codex Context

fmt: id=<id> mode=<csv|*> role=<csv|*> phase=<phase> tags=<csv> ports=<csv> svc=<csv> pre=<conds> act=<bounded_action> verify=<proof> next=<next> block=<stop_conditions> refs=<paths>
load: use `python3 scripts/learn_engine.py --root . lookup tag:<tag> service:<svc> --format prompt`; do not read full playbooks unless no indexed match exists.

id=mem.sources mode=* role=* phase=startup tags=memory,startup ports=* svc=* pre=session_start act=load_AGENTS+latest_session_index+latest_handoff+targeted_lookup verify=current_state_known next=work block=missing_index refs=AGENTS.md
id=mem.canonical mode=* role=* phase=all tags=memory,jsonl ports=* svc=* pre=memory_write act=append_session_index+session_journal_jsonl+compat_dense_mirror verify=valid_jsonl next=continue block=invalid_json refs=scripts/memory-write.py
id=mem.local mode=* role=* phase=all tags=privacy,local ports=* svc=* pre=private_host_or_key_or_node act=write_memory/local_only verify=not_tracked next=continue block=secret_in_tracked_file refs=memory/local/MEM.local.example.md
id=mem.runtime mode=* role=* phase=all tags=runtime,paths ports=* svc=* pre=artifact_or_prompt act=write_user_owned_runtime_root verify=path_under_SECOPS_RUNTIME_ROOT next=record_path block=root_owned_file refs=docs/permissions.md
id=mem.lookup mode=* role=* phase=all tags=lookup,intel ports=* svc=* pre=need_context act=read_LOOKUP+query_learning_index_by_focus verify=relevant_only next=work block=full_playbook_load refs=LOOKUP.md
