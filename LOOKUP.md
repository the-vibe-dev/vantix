# Dense Intelligence Lookup

fmt: id=<id> mode=<csv|*> role=<csv|*> phase=<phase> tags=<csv> trigger=<fact> cmd="<lookup>" use=<result> next=<action> block=<condition>

id=lookup.recon_focus mode=* role=recon phase=recon tags=lookup,intel,recon,focus trigger=open_ports|services|versions cmd="emit focus={mode,tags,ports,svc,versions,cves,phase,role,confidence}" use=handoff_fields next=research_lookup block=no_scope
id=lookup.playbook mode=* role=* phase=all tags=lookup,intel,playbook trigger=need_method cmd="python3 scripts/learn_engine.py --root . context mode:<mode> tag:<tag> service:<svc> port:<port>" use=playbook_records next=apply_bounded block=full_playbook_load
id=lookup.role_phase mode=* role=* phase=all tags=lookup,intel,role trigger=agent_task cmd="python3 scripts/learn_engine.py --root . lookup role:<role> phase:<phase> --format prompt" use=role_records next=task_plan block=no_match
id=lookup.memory mode=* role=knowledge_base,orchestrator phase=plan tags=lookup,intel,memory trigger=prior_case_needed cmd="python3 scripts/learn_engine.py --root . lookup tag:<tag> service:<svc> --format prompt" use=vectors+guardrails+bugs next=rank_patterns block=index_missing
id=lookup.cve_local mode=* role=researcher phase=research tags=lookup,intel,cve trigger=product_or_version cmd="curl -s http://127.0.0.1:8787/api/v1/cve/intel/search?q=<vendor_product_version>" use=cve_intel next=shortlist block=no_version
id=lookup.cve_recent mode=* role=researcher phase=research tags=lookup,intel,cve trigger=fresh_intel_needed cmd="curl -s http://127.0.0.1:8787/api/v1/cve/intel/recent?days=7&limit=100" use=recent_intel next=filter_by_service block=offline
id=lookup.cve_mcp mode=* role=researcher,orchestrator phase=research tags=lookup,intel,cve,mcp trigger=mcp_client_available cmd="http://127.0.0.1:8787/mcp/cve" use=MCP_tools next=tool_search block=no_token
id=lookup.skills mode=* role=orchestrator phase=plan tags=lookup,intel,skills trigger=run_context_changed cmd="GET /api/v1/runs/<run_id>/skills; POST /api/v1/runs/<run_id>/skills/apply" use=selected_skills next=prompt_review block=missing_run
id=lookup.handoff mode=* role=* phase=all tags=lookup,intel,handoff trigger=switch_or_delegate cmd="GET /api/v1/runs/<run_id>/handoff" use=services+vectors+chains+next_actions next=continue block=missing_run
id=lookup.vectors mode=* role=vector_store,orchestrator,executor phase=plan tags=lookup,intel,vectors trigger=candidate_needed cmd="GET /api/v1/runs/<run_id>/vectors" use=ranked_vectors next=select_or_replan block=no_evidence
id=lookup.attack_chain mode=* role=orchestrator,vector_store,executor phase=plan tags=lookup,intel,chains trigger=multi_step_path cmd="GET /api/v1/runs/<run_id>/attack-chains" use=scored_paths next=validate_step block=unsafe_chain
id=lookup.providers mode=* role=orchestrator phase=startup tags=lookup,intel,providers trigger=model_or_runtime_question cmd="GET /api/v1/system/status; GET /api/v1/providers" use=runtime_status next=choose_codex_or_provider block=secret_missing
id=lookup.cracking mode=* role=researcher,executor phase=execute tags=lookup,intel,cracking trigger=hash_artifact cmd="bash scripts/crack-status.sh; cat agent_ops/config/cracking_nodes.example.yaml" use=node_capability next=dispatch_if_authorized block=no_scope|no_node
id=lookup.bugbounty mode=bugbounty role=recon,researcher phase=recon tags=lookup,intel,bugbounty trigger=program_scope cmd="cat agent_ops/config/targets.yaml; cat agent_ops/bugbounty/tools_installed.yaml" use=scope+tools next=program_safe_probe block=private_scope_missing
id=lookup.output mode=* role=* phase=all tags=lookup,intel,notes trigger=after_lookup cmd="write obs=[] evidence=[] focus={} loaded=[] next=[] blocked=[]" use=dense_notes next=memory_checkpoint block=narrative_padding

focus_schema: mode=<mode> tags=[] ports=[] svc=[] versions=[] cves=[] phase=<phase> role=<next_role> confidence=<0-1>
rule: recon owns focus_schema; downstream agents must lookup from focus before asking for broad context.
rule: never load full legacy archives during normal agent work; use archives only for human audit or missing dense record recovery.
