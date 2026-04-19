#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DENSE_HEADER = """# Dense Codex Context

fmt: id=<id> mode=<csv|*> role=<csv|*> phase=<phase> tags=<csv> ports=<csv> svc=<csv> pre=<conds> act=<bounded_action> verify=<proof> next=<next> block=<stop_conditions> refs=<paths>
load: use `python3 scripts/learn_engine.py --root . lookup tag:<tag> service:<svc> --format prompt`; do not read full playbooks unless no indexed match exists.
""".rstrip()

TARGET_FILES = [
    "PENTEST.md",
    "USAGE.md",
    "methods/ctf/ctf_techniques.md",
    "methods/ctf/ctfplaybook.md",
    "methods/ctf/xss_replay_commands.md",
    "methods/linux/linux_privesc_extended.md",
    "methods/linux/service_attacks.md",
    "methods/network/pivoting_tunneling.md",
    "methods/thm_general/koth_playbook.md",
    "methods/thm_general/koth_replay_fireworks.md",
    "methods/web/version_source_research.md",
    "methods/web/web_vuln_playbook.md",
    "methods/windows/ad_enumeration.md",
    "methods/windows/windows_koth.md",
    "methods/windows/windows_pentest_playbook.md",
    "runbooks/workflow.md",
]

DENSE_FILES: dict[str, list[str]] = {
    "AGENTS.md": [
        "id=agent.startup mode=* role=* phase=startup tags=startup,memory,lookup ports=* svc=* pre=session_start act=read_MEM+latest_session_index+targeted_context_lookup verify=obj+next+blockers_known next=work block=scope_unknown refs=MEM.md",
        "id=agent.memory mode=* role=* phase=all tags=memory,handoff ports=* svc=* pre=phase_change|blocker|switch|close act=memory-write_mode_phase_handoff_close verify=session_index_updated next=continue block=secret_or_private_topology refs=scripts/memory-write.py",
        "id=agent.lookup mode=* role=* phase=all tags=lookup,token ports=* svc=* pre=need_methodology act=learn_engine context mode:<mode> tag:<tag> service:<svc> port:<port> verify=relevant_records_only next=apply block=full_playbook_load refs=scripts/learn_engine.py",
        "id=agent.safety mode=* role=* phase=all tags=scope,safety ports=* svc=* pre=active_action act=confirm_scope+low_noise+proof_separation verify=obs_hypothesis_proof_split next=execute_or_block block=out_of_scope|dos|unknown_auth refs=agent_skills/shared/scope_guard.md",
        "id=agent.koth mode=koth,windows-koth role=* phase=all tags=koth,safety ports=9999 svc=koth pre=round_active act=preserve_availability+no_king_service_tamper+operator_hold_only verify=rules_checked next=continue block=rule_conflict refs=methods/thm_general/koth_playbook.md",
    ],
    "MEM.md": [
        "id=mem.sources mode=* role=* phase=startup tags=memory,startup ports=* svc=* pre=session_start act=load_AGENTS+latest_session_index+latest_handoff+targeted_lookup verify=current_state_known next=work block=missing_index refs=AGENTS.md",
        "id=mem.canonical mode=* role=* phase=all tags=memory,jsonl ports=* svc=* pre=memory_write act=append_session_index+session_journal_jsonl+compat_dense_mirror verify=valid_jsonl next=continue block=invalid_json refs=scripts/memory-write.py",
        "id=mem.local mode=* role=* phase=all tags=privacy,local ports=* svc=* pre=private_host_or_key_or_node act=write_memory/local_only verify=not_tracked next=continue block=secret_in_tracked_file refs=memory/local/MEM.local.example.md",
        "id=mem.runtime mode=* role=* phase=all tags=runtime,paths ports=* svc=* pre=artifact_or_prompt act=write_user_owned_runtime_root verify=path_under_SECOPS_RUNTIME_ROOT next=record_path block=root_owned_file refs=docs/permissions.md",
    ],
    "CLAUDE.md": [
        "id=claude.priorities mode=* role=* phase=startup tags=startup,codex ports=* svc=* pre=agent_session act=read_AGENTS+PLAN2+architecture_then_targeted_lookup verify=scope+next known next=work block=full_context_dump refs=AGENTS.md,docs/architecture.md",
        "id=claude.notes mode=* role=* phase=all tags=memory,dense ports=* svc=* pre=handoff_needed act=mode=handoff run=<id> phase=<phase> done=[] issues=[] next=[] files=[] facts=[] verify=memory_health next=transfer block=missing_next refs=scripts/codex-close.sh",
        "id=claude.guard mode=* role=* phase=all tags=safety,scope ports=* svc=* pre=ambiguous_scope act=block+ask_for_scope verify=authorization_known next=resume block=out_of_scope refs=agent_skills/shared/scope_guard.md",
    ],
    "PENTEST.md": [
        "id=core.scope mode=* role=* phase=init tags=scope,safety ports=* svc=* pre=target_known act=confirm_auth+scope+roe+stop_conditions verify=scope_note_written next=select_mode block=scope_unknown|out_of_scope refs=AGENTS.md,agent_skills/shared/scope_guard.md",
        "id=core.memory mode=* role=* phase=all tags=memory,handoff ports=* svc=* pre=phase_change|blocker|close act=write_dense_memory_phase_handoff_close verify=session_index_newer next=continue block=secrets_in_note refs=scripts/memory-write.py",
        "id=core.artifacts mode=* role=* phase=all tags=artifact,evidence ports=* svc=* pre=file_in_tmp|proof_generated act=save_to_runtime_or_artifacts+record_path verify=path_exists next=reference_in_memory block=private_secret refs=scripts/tmp-artifact-sweep.sh",
        "id=core.cve_gate mode=pentest,ctf,koth,bugbounty,windows-ctf,windows-koth role=researcher phase=research tags=cve,version ports=* svc=* pre=product_or_version act=query_local_cve+intel_search verify=cve_shortlist_or_negative_evidence next=plan_validation block=no_version refs=docs/cve_mcp.md",
        "id=core.ohvp mode=* role=* phase=all tags=method,proof ports=* svc=* pre=observation act=obs->hypothesis->bounded_validation->pivot verify=proof_or_negative_evidence next=store_vector block=tool_thrash refs=docs/agents.md",
        "id=core.no_spoilers mode=ctf,windows-ctf role=* phase=research tags=ctf,research ports=* svc=* pre=active_challenge act=use_vendor_docs_cve_tool_docs_only verify=no_writeup_source next=continue block=walkthrough|flag_lookup refs=AGENTS.md",
        "id=core.low_noise mode=pentest,bugbounty role=recon,executor phase=recon,execute tags=low-noise,safety ports=* svc=* pre=unknown_stability act=start_minimal+rate_limit+record_response verify=service_stable next=expand_if_needed block=instability refs=agent_skills/shared/execution_policy.md",
        "id=core.report mode=* role=reporter phase=report tags=report,evidence ports=* svc=* pre=finding_or_negative_result act=write_evidence+repro+impact+remediation+next verify=artifact_path next=close_memory block=unverified_claim refs=agent_ops/templates/report_template.md",
    ],
    "USAGE.md": [
        "id=usage.start mode=* role=* phase=startup tags=startup,memory ports=* svc=* pre=new_session act=read_MEM+latest_index+targeted_digest verify=current_obj+next_known next=work block=stale_memory refs=AGENTS.md,MEM.md",
        "id=usage.chat mode=pentest,bugbounty,ctf,koth,windows-ctf,windows-koth role=orchestrator phase=init tags=ui,api ports=* svc=* pre=target+objective act=POST_/api/v1/chat_or_UI_chat verify=run_id+messages next=review_skills block=missing_target refs=README.md,docs/api.md",
        "id=usage.skills mode=* role=orchestrator phase=plan tags=skills,prompt ports=* svc=* pre=run_exists act=GET_/runs/<id>/skills+POST_apply_if_context_changed verify=prompt_paths_exist next=handoff block=registry_missing refs=docs/skill-authoring.md",
        "id=usage.context_lookup mode=* role=* phase=all tags=lookup,token ports=* svc=* pre=target_facts act=learn_engine_lookup tag/service/port --format prompt verify=relevant_only next=load_slice block=no_index refs=scripts/learn_engine.py",
        "id=usage.close mode=* role=* phase=close tags=memory,handoff ports=* svc=* pre=stop_or_switch act=codex-close --mode handoff|close --objective --done --next verify=session_index+handoff_updated next=handoff block=missing_next refs=scripts/codex-close.sh",
    ],
    "methods/ctf/ctfplaybook.md": [
        "id=ctf.start mode=ctf role=orchestrator phase=init tags=ctf,startup ports=* svc=* pre=authorized_target act=create_workspace+load_dense_digest verify=target+scope+next next=recon block=spoiler_source refs=PENTEST.md",
        "id=ctf.recon mode=ctf role=recon phase=recon tags=ctf,recon ports=* svc=* pre=target_up act=nmap_top_then_full+service_enum verify=open_ports+versions next=cve_gate block=scan_noise refs=scripts/exploit-pipeline.sh",
        "id=ctf.web mode=ctf role=recon,researcher phase=web tags=web,ctf ports=80,443 svc=http,apache,nginx pre=http_open act=vhost+dir+param+tech_fingerprint verify=endpoints+version next=web_vector_lookup block=writeup_refs refs=methods/web/web_vuln_playbook.md",
        "id=ctf.privesc mode=ctf role=executor phase=privesc tags=linux,privesc ports=* svc=* pre=foothold act=sudo_suid_cron_capabilities_creds verify=user_to_root_path next=flag_sweep block=unstable_shell refs=methods/linux/linux_privesc_extended.md",
        "id=ctf.close mode=ctf role=reporter phase=close tags=ctf,report ports=* svc=* pre=proof_captured act=record_flags+chain+artifacts+lessons verify=replay_notes next=close_memory block=unverified_flag refs=runbooks/workflow.md",
    ],
    "methods/ctf/ctf_techniques.md": [
        "id=ctf.crypto mode=ctf role=researcher phase=analyze tags=crypto,ctf ports=* svc=* pre=ciphertext_or_encoding act=identify_encoding->frequency->known_plaintext->tool verify=decoded_signal next=validate_on_target block=random_guess refs=methods/ctf/ctf_techniques.md",
        "id=ctf.steg mode=ctf role=researcher phase=analyze tags=steg,forensics ports=* svc=* pre=image_audio_archive act=file+exiftool+binwalk+strings+stegsolve/zsteg verify=hidden_payload next=decode block=destructive_edit refs=methods/ctf/ctf_techniques.md",
        "id=ctf.rev mode=ctf role=developer phase=analyze tags=re,pwn ports=* svc=* pre=binary act=file+checksec+strings+ltrace+ghidra verify=input_constraint_or_bug next=poc block=unknown_arch refs=methods/ctf/ctf_techniques.md",
        "id=ctf.web_common mode=ctf role=researcher phase=web tags=sqli,xss,lfi,ssti,upload ports=80,443 svc=http pre=input_surface act=test_one_class_at_time verify=response_delta next=exploit_plan block=no_baseline refs=methods/web/web_vuln_playbook.md",
    ],
    "methods/ctf/xss_replay_commands.md": [
        "id=xss.replay mode=ctf,bugbounty,pentest role=executor phase=validate tags=xss,replay ports=80,443 svc=http pre=reflected_or_stored_input act=min_payload+context_breakout+browser_verify verify=callback_or_dom_execution next=report block=no_user_impact refs=methods/web/web_vuln_playbook.md",
        "id=xss.filter mode=ctf,bugbounty,pentest role=researcher phase=validate tags=xss,filter ports=80,443 svc=http pre=filter_detected act=test_case_encoding_event_handlers_svg_mathml verify=allowed_primitive next=payload_shape block=blind_random_payloads refs=methods/ctf/xss_replay_commands.md",
    ],
    "methods/web/web_vuln_playbook.md": [
        "id=web.baseline mode=pentest,bugbounty,ctf role=recon phase=web tags=web,recon ports=80,443 svc=http pre=http_open act=fetch_headers+routes+forms+auth_state+tech verify=baseline_saved next=class_tests block=no_baseline refs=PENTEST.md",
        "id=web.vhost mode=pentest,bugbounty,ctf role=recon phase=web tags=web,vhost ports=80,443 svc=http pre=ip+domain act=test_http_https_host_split+cert_SAN verify=valid_hosts next=content_enum block=wildcard_noise refs=PENTEST.md",
        "id=web.sqli mode=pentest,bugbounty,ctf role=executor phase=validate tags=sqli,web ports=80,443 svc=http pre=param_or_body_input act=boolean_error_time_ordered_tests verify=db_error_or_logic_delta next=bounded_extract block=data_overreach refs=agent_skills/packs/web_hunter/SKILL.md",
        "id=web.ssti mode=pentest,bugbounty,ctf role=executor phase=validate tags=ssti,web ports=80,443 svc=http pre=template_reflection act=polyglot_math+engine_fingerprint+safe_read verify=render_delta next=impact_check block=blind_rce_first refs=agent_skills/packs/web_hunter/SKILL.md",
        "id=web.xxe mode=pentest,bugbounty,ctf role=executor phase=validate tags=xxe,web ports=80,443 svc=http pre=xml_parser act=entity_probe+safe_file_or_ssrf_probe verify=parser_expansion_signal next=impact_check block=oob_without_approval refs=agent_skills/packs/web_hunter/SKILL.md",
        "id=web.idor mode=pentest,bugbounty role=executor phase=validate tags=idor,access-control ports=80,443 svc=http pre=two_objects_or_roles act=swap_ids+compare_authz verify=unauthorized_object_access next=report block=no_second_account refs=agent_skills/packs/bizlogic_hunter/SKILL.md",
        "id=web.jwt mode=pentest,bugbounty,ctf role=researcher phase=validate tags=jwt,auth ports=80,443 svc=http pre=jwt_seen act=decode_alg_claims_kid_jku_confusion_checks verify=auth_delta next=report_or_pivot block=token_theft refs=agent_skills/packs/api_security/SKILL.md",
        "id=web.oauth mode=pentest,bugbounty role=researcher phase=validate tags=oauth,auth ports=80,443 svc=http pre=oauth_flow act=redirect_uri_state_pkce_audience_checks verify=account_or_token_boundary_bypass next=report block=real_user_harm refs=agent_skills/packs/api_security/SKILL.md",
    ],
    "methods/web/version_source_research.md": [
        "id=research.version mode=pentest,bugbounty,ctf,koth role=researcher phase=research tags=version,cve,source ports=* svc=* pre=banner_or_version act=service-source-map+version-research+upstream_diff verify=reachable_code_path next=bounded_validation block=no_version refs=scripts/service-source-map.py,scripts/version-research.sh",
        "id=research.no_poc mode=* role=researcher phase=research tags=cve,source ports=* svc=* pre=cve_checks_fail act=inspect_patch_diff+release_notes+config_paths verify=hypothesis_or_negative next=recon_or_report block=exploit_thrashing refs=PENTEST.md",
    ],
    "methods/linux/linux_privesc_extended.md": [
        "id=lin.enum mode=pentest,ctf,koth role=executor phase=privesc tags=linux,privesc ports=* svc=* pre=shell act=id+sudo_l+suid+caps+cron+services+creds verify=ranked_paths next=test_top_path block=no_shell refs=methods/linux/linux_privesc_extended.md",
        "id=lin.sudo mode=pentest,ctf,koth role=executor phase=privesc tags=sudo,linux ports=* svc=* pre=sudo_l_output act=match_gtfobins+env+wildcards verify=uid_change next=stabilize block=destructive_command refs=methods/linux/linux_privesc_extended.md",
        "id=lin.suid mode=pentest,ctf,koth role=executor phase=privesc tags=suid,linux ports=* svc=* pre=suid_binary act=known_gtfobin_or_custom_trace verify=controlled_priv_read_or_shell next=proof block=unknown_binary_mutation refs=methods/linux/linux_privesc_extended.md",
        "id=lin.creds mode=pentest,ctf,koth role=researcher phase=privesc tags=credential,linux ports=* svc=* pre=local_read act=grep_configs_histories_keys_env verify=credential_validity next=pivot block=credential_theft_out_of_scope refs=agent_skills/packs/credential_tester/SKILL.md",
        "id=lin.kernel mode=ctf,koth,pentest role=researcher phase=privesc tags=kernel,linux,cve ports=* svc=* pre=old_kernel act=cve_check+safe_exploitability_probe verify=vulnerable_kernel_signal next=approval block=prod_system refs=docs/cve_mcp.md",
    ],
    "methods/linux/service_attacks.md": [
        "id=svc.ftp mode=pentest,ctf,koth role=recon phase=recon tags=ftp,service ports=21 svc=ftp pre=port21 act=anon_check+banner+write_test_if_allowed verify=listing_or_creds next=files_review block=write_without_scope refs=methods/linux/service_attacks.md",
        "id=svc.ssh mode=pentest,ctf,koth role=recon phase=recon tags=ssh,service ports=22 svc=openssh pre=port22 act=banner+auth_methods+known_creds_check verify=login_or_negative next=credential_policy block=spray refs=agent_skills/packs/credential_tester/SKILL.md",
        "id=svc.smb mode=pentest,ctf,koth,windows-ctf role=recon phase=recon tags=smb,windows ports=139,445 svc=smb pre=smb_open act=smbmap+smbclient_null+enum4linux verify=shares+signing+users next=cve_or_auth block=lockout refs=methods/windows/ad_enumeration.md",
        "id=svc.redis mode=pentest,ctf,koth role=executor phase=validate tags=redis,rce ports=6379 svc=redis pre=redis_open act=info+auth_check+config_safety verify=unauth_or_version next=impact_plan block=config_write_no_scope refs=methods/linux/service_attacks.md",
        "id=svc.db mode=pentest,ctf role=recon phase=recon tags=db,service ports=3306,5432,1433 svc=mysql,postgres,mssql pre=db_open act=banner+default_auth_policy+schema_if_creds verify=version+auth_state next=cve_or_app_link block=bruteforce refs=methods/linux/service_attacks.md",
    ],
    "methods/network/pivoting_tunneling.md": [
        "id=pivot.need mode=pentest,ctf,koth,windows-ctf,windows-koth role=orchestrator phase=pivot tags=pivoting,network ports=* svc=* pre=internal_route_needed act=map_routes+choose_socks_or_forward verify=internal_reachability next=targeted_recon block=out_of_scope_net refs=methods/network/pivoting_tunneling.md",
        "id=pivot.ssh mode=pentest,ctf,koth role=executor phase=pivot tags=ssh,pivoting ports=22 svc=ssh pre=ssh_creds act=ssh_dynamic_or_local_forward verify=proxy_test next=scan_internal block=credential_policy refs=methods/network/pivoting_tunneling.md",
        "id=pivot.chisel mode=ctf,koth,pentest role=executor phase=pivot tags=chisel,pivoting ports=* svc=* pre=upload_exec_allowed act=start_reverse_socks_with_operator_listener verify=socks_works next=proxychains block=egress_block refs=methods/network/pivoting_tunneling.md",
    ],
    "methods/thm_general/koth_playbook.md": [
        "id=koth.rules mode=koth,windows-koth role=* phase=all tags=koth,safety ports=9999 svc=koth pre=round_active act=preserve_availability+do_not_attack_king_service+no_dos verify=rules_checked next=continue block=rule_conflict refs=AGENTS.md",
        "id=koth.fast_recon mode=koth role=recon phase=recon tags=koth,recon ports=* svc=* pre=target_up act=nmap_low_noise+version_cve_gate+easy_path_sweep verify=entry_candidates next=foothold block=scan_instability refs=PENTEST.md",
        "id=koth.claim mode=koth role=executor phase=claim tags=koth,king ports=9999 svc=koth pre=root act=write_operator_to_/root/king.txt+verify_9999 verify=holder_matches next=hold block=immutable_or_bind_source refs=scripts/koth-claim-watch.sh",
        "id=koth.hold mode=koth role=executor phase=hold tags=koth,continuity ports=22,9999 svc=ssh,koth pre=king_claimed+operator_approval act=install_controlled_hold+backup_access verify=5_consecutive_holder_checks next=flag_sweep block=service_breakage refs=scripts/koth-continuity.sh",
        "id=koth.loss mode=koth role=executor phase=recover tags=koth,recover ports=22,9999 svc=ssh,koth pre=holder_changed act=check_root_ssh+backup_path+hold_state+retake_fast verify=holder_restored next=strengthen_hold block=no_access refs=scripts/koth-loss-recover.sh",
        "id=koth.opponent mode=koth role=researcher phase=observe tags=koth,opponent ports=* svc=* pre=opponent_artifact act=capture_before_neutralize+ingest_report verify=family_tags next=defense_update block=attacking_users refs=scripts/learn_engine.py",
    ],
    "methods/thm_general/koth_replay_fireworks.md": [
        "id=koth.replay.fireworks mode=koth role=executor phase=recover tags=koth,replay ports=9999 svc=koth pre=known_fireworks_box act=check_prior_paths+validate_live_before_reuse verify=current_proof next=claim block=stale_replay refs=methods/thm_general/koth_replay_fireworks.md",
    ],
    "methods/windows/windows_pentest_playbook.md": [
        "id=win.recon mode=windows-ctf,pentest role=recon phase=recon tags=windows,recon ports=135,139,445,3389,5985 svc=smb,rdp,winrm pre=windows_target act=nmap_smb_ldap_rdp_mssql+enum verify=domain_or_workgroup+services next=ad_or_local block=lockout refs=methods/windows/ad_enumeration.md",
        "id=win.smb mode=windows-ctf,pentest role=recon phase=recon tags=smb,windows ports=445 svc=smb pre=smb_open act=null_guest_share_enum+signing_check verify=shares+users+signing next=cve_or_creds block=auth_spray refs=methods/windows/windows_pentest_playbook.md",
        "id=win.winrm mode=windows-ctf,pentest role=executor phase=foothold tags=winrm,windows ports=5985,5986 svc=winrm pre=valid_creds act=evil-winrm_or_psrp_login verify=shell next=privesc block=unapproved_creds refs=methods/windows/windows_pentest_playbook.md",
        "id=win.local_priv mode=windows-ctf,pentest role=executor phase=privesc tags=windows,privesc ports=* svc=* pre=windows_shell act=whoami_priv+services+unquoted+alwaysinstall+creds verify=admin_path next=proof block=destructive_change refs=methods/windows/windows_pentest_playbook.md",
        "id=win.ms17 mode=windows-ctf,pentest role=researcher phase=validate tags=ms17-010,eternalblue,cve ports=445 svc=smb pre=legacy_smb act=nmap_smb_vuln_ms17_010 verify=vuln_script_positive next=approval block=prod_system refs=docs/cve_mcp.md",
    ],
    "methods/windows/ad_enumeration.md": [
        "id=ad.base mode=windows-ctf,pentest role=recon phase=ad tags=ad,ldap,kerberos ports=88,389,445 svc=ldap,kerberos,smb pre=domain_signals act=ldap_base+dns+time+domain_info verify=base_dn+dc next=user_enum block=no_domain refs=methods/windows/ad_enumeration.md",
        "id=ad.users mode=windows-ctf,pentest role=recon phase=ad tags=ad,user-enum ports=88,389 svc=kerberos,ldap pre=domain_known act=kerbrute_or_rpc_ldap_user_enum verify=user_list next=roast_checks block=lockout refs=agent_skills/packs/ad_attacker/SKILL.md",
        "id=ad.kerberoast mode=windows-ctf,pentest role=researcher phase=ad tags=kerberoast,ad ports=88,389 svc=kerberos pre=valid_creds+spn act=request_tgs+crack_offline verify=service_cred next=path_map block=spray refs=agent_ops/config/cracking_nodes.example.yaml",
        "id=ad.asrep mode=windows-ctf,pentest role=researcher phase=ad tags=asrep,ad ports=88 svc=kerberos pre=user_list act=GetNPUsers_safe_enum verify=hashes_or_negative next=crack_offline block=lockout refs=agent_skills/packs/ad_attacker/SKILL.md",
        "id=ad.bloodhound mode=windows-ctf,pentest role=researcher phase=ad tags=bloodhound,ad ports=389,445 svc=ldap,smb pre=domain_creds act=collect_minimal_edges verify=graph_loaded next=rank_paths block=no_approval refs=methods/windows/ad_enumeration.md",
    ],
    "methods/windows/windows_koth.md": [
        "id=winkoth.rules mode=windows-koth role=* phase=all tags=windows,koth,safety ports=* svc=* pre=round_active act=preserve_services+no_dos+no_game_service_tamper verify=rules_checked next=continue block=rule_conflict refs=AGENTS.md",
        "id=winkoth.claim mode=windows-koth role=executor phase=claim tags=windows,koth ports=* svc=* pre=admin act=write_operator_to_king_mechanism+verify_scoreboard verify=holder_matches next=continuity block=service_breakage refs=methods/windows/windows_koth.md",
        "id=winkoth.hold mode=windows-koth role=executor phase=hold tags=windows,koth,continuity ports=3389,5985 svc=rdp,winrm pre=claim+approval act=backup_access+monitor+minimal_defense verify=access_survives next=observe block=availability_impact refs=methods/windows/windows_koth.md",
    ],
    "runbooks/workflow.md": [
        "id=flow.start mode=* role=orchestrator phase=startup tags=workflow,startup ports=* svc=* pre=session_start act=load_MEM+latest_dense+targeted_context verify=current_obj next=plan block=missing_scope refs=AGENTS.md",
        "id=flow.loop mode=* role=orchestrator phase=all tags=workflow ports=* svc=* pre=new_evidence act=update_facts+reapply_skills+refresh_handoff verify=next_actions next=delegate block=contradiction refs=docs/agents.md",
        "id=flow.validate mode=* role=executor phase=execute tags=workflow,validation ports=* svc=* pre=selected_vector act=bounded_validation_only verify=proof_or_negative next=report_or_replan block=scope_gap refs=agent_skills/shared/execution_policy.md",
    ],
}

# Add aliases for playbooks that share another dense set.
DENSE_FILES["methods/sqli_resumable_wordpress/README.md"] = [
    "id=sqli.wp_resumable mode=ctf,pentest role=executor phase=validate tags=sqli,wordpress,resume ports=80,443 svc=wordpress pre=wp_sqli_signal act=extract_incrementally+checkpoint_offsets verify=recovered_rows next=crack_or_report block=data_overreach refs=methods/sqli_resumable_wordpress/README.md",
]

DENSE_FILES["methods/web/version_source_research.md"] = DENSE_FILES["methods/web/version_source_research.md"]


def now_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def is_dense(text: str) -> bool:
    return text.startswith("# Dense Codex Context") or "fmt: id=<id>" in text[:500]


def archive_file(root: Path, rel: str, archive_root: Path, stamp: str, dry_run: bool) -> Path | None:
    src = root / rel
    if not src.exists():
        return None
    dst = archive_root / stamp / rel
    if dry_run:
        print(f"archive {rel} -> {dst.relative_to(root)}")
        return dst
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    return dst


def write_dense_file(root: Path, rel: str, records: list[str], dry_run: bool) -> None:
    path = root / rel
    body = DENSE_HEADER + "\n\n" + "\n".join(records).rstrip() + "\n"
    if dry_run:
        print(f"write_dense {rel}: {len(records)} records")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


def compact_list(values: Any) -> str:
    if not values:
        return "[]"
    if isinstance(values, str):
        values = [values]
    out = []
    for item in values:
        text = str(item).replace("\n", " ").replace("|", "/").strip()
        if text:
            out.append(text[:180])
    return "[" + ";".join(out) + "]"


def row_to_dsl(row: dict[str, Any]) -> str:
    return (
        f"ts={row.get('ts','')} sid={row.get('sid') or row.get('session_id','')} "
        f"run={row.get('run_id','')} agent={row.get('agent') or row.get('agent_id','')} "
        f"mode={row.get('mode') or row.get('classification','checkpoint')} phase={row.get('phase','')} "
        f"ctx={compact_list(row.get('ctx') or row.get('tags'))} obj={compact_list(row.get('obj') or row.get('objective'))} "
        f"done={compact_list(row.get('done') or row.get('summary'))} issues={compact_list(row.get('issues') or row.get('blockers'))} "
        f"next={compact_list(row.get('next') or row.get('next_action'))} files={compact_list(row.get('files') or row.get('files_touched'))} "
        f"seq={row.get('seq','')}"
    )


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    if not path.exists():
        return rows
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            rows.append(json.loads(raw))
        except json.JSONDecodeError:
            continue
    return rows


def compact_memory(root: Path, stamp: str, dry_run: bool, keep: int) -> None:
    archive_root = root / "memory" / "archive" / stamp
    for rel in ["memory/session_journal.md", "memory/compaction_handoffs.md", "memory/session_index.jsonl"]:
        archive_file(root, rel, root / "memory" / "archive", stamp, dry_run)

    rows = load_jsonl(root / "memory" / "session_index.jsonl")
    recent = rows[-keep:]
    handoffs = [r for r in rows if r.get("mode") in {"handoff", "close", "failure"}][-max(20, keep // 4):]
    if dry_run:
        print(f"compact_memory recent={len(recent)} handoffs={len(handoffs)}")
        return
    mem = root / "memory"
    mem.mkdir(parents=True, exist_ok=True)
    (mem / "session_journal.md").write_text(
        "# Dense Session Journal\n\nfmt: ts=<utc> sid=<id> run=<id> agent=<id> mode=<mode> phase=<phase> ctx=[] obj=[] done=[] issues=[] next=[] files=[] seq=<n>\n"
        + "\n".join(row_to_dsl(r) for r in recent)
        + ("\n" if recent else ""),
        encoding="utf-8",
    )
    (mem / "compaction_handoffs.md").write_text(
        "# Dense Handoffs\n\nfmt: ts=<utc> sid=<id> run=<id> agent=<id> mode=<handoff|close|failure> phase=<phase> ctx=[] obj=[] done=[] issues=[] next=[] files=[] seq=<n>\n"
        + "\n".join(row_to_dsl(r) for r in handoffs)
        + ("\n" if handoffs else ""),
        encoding="utf-8",
    )
    with (mem / "session_index.jsonl").open("w", encoding="utf-8") as handle:
        for row in recent:
            handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")


def compact_learning_archives(root: Path, stamp: str, dry_run: bool) -> None:
    learning = root / "memory" / "learning"
    archive_dir = root / "memory" / "archive" / stamp / "learning"
    targets = ["events.archive.jsonl"]
    for name in targets:
        src = learning / name
        if not src.exists():
            continue
        if dry_run:
            print(f"archive learning/{name} -> {archive_dir / name}")
            continue
        archive_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, archive_dir / name)
        src.write_text("", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Archive verbose Codex context and write dense searchable records")
    parser.add_argument("--root", default=str(Path.cwd()))
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--keep-memory", type=int, default=80)
    args = parser.parse_args()
    if not args.dry_run and not args.apply:
        parser.error("use --dry-run or --apply")
    root = Path(args.root).resolve()
    stamp = now_stamp()
    archive_root = root / "docs" / "reference" / "legacy_playbooks"

    for rel, records in sorted(DENSE_FILES.items()):
        src = root / rel
        if not src.exists():
            continue
        text = src.read_text(encoding="utf-8", errors="ignore")
        if not is_dense(text):
            archive_file(root, rel, archive_root, stamp, args.dry_run)
        write_dense_file(root, rel, records, args.dry_run)

    compact_memory(root, stamp, args.dry_run, args.keep_memory)
    compact_learning_archives(root, stamp, args.dry_run)
    print(f"dense conversion {'dry-run' if args.dry_run else 'applied'} stamp={stamp}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
