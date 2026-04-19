# Dense Codex Context

fmt: id=<id> mode=<csv|*> role=<csv|*> phase=<phase> tags=<csv> ports=<csv> svc=<csv> pre=<conds> act=<bounded_action> verify=<proof> next=<next> block=<stop_conditions> refs=<paths>
load: use `python3 scripts/learn_engine.py --root . lookup tag:<tag> service:<svc> --format prompt`; do not read full playbooks unless no indexed match exists.

id=web.baseline mode=pentest,bugbounty,ctf role=recon phase=web tags=web,recon ports=80,443 svc=http pre=http_open act=fetch_headers+routes+forms+auth_state+tech verify=baseline_saved next=class_tests block=no_baseline refs=PENTEST.md
id=web.vhost mode=pentest,bugbounty,ctf role=recon phase=web tags=web,vhost ports=80,443 svc=http pre=ip+domain act=test_http_https_host_split+cert_SAN verify=valid_hosts next=content_enum block=wildcard_noise refs=PENTEST.md
id=web.sqli mode=pentest,bugbounty,ctf role=executor phase=validate tags=sqli,web ports=80,443 svc=http pre=param_or_body_input act=boolean_error_time_ordered_tests verify=db_error_or_logic_delta next=bounded_extract block=data_overreach refs=agent_skills/packs/web_hunter/SKILL.md
id=web.ssti mode=pentest,bugbounty,ctf role=executor phase=validate tags=ssti,web ports=80,443 svc=http pre=template_reflection act=polyglot_math+engine_fingerprint+safe_read verify=render_delta next=impact_check block=blind_rce_first refs=agent_skills/packs/web_hunter/SKILL.md
id=web.xxe mode=pentest,bugbounty,ctf role=executor phase=validate tags=xxe,web ports=80,443 svc=http pre=xml_parser act=entity_probe+safe_file_or_ssrf_probe verify=parser_expansion_signal next=impact_check block=oob_without_approval refs=agent_skills/packs/web_hunter/SKILL.md
id=web.idor mode=pentest,bugbounty role=executor phase=validate tags=idor,access-control ports=80,443 svc=http pre=two_objects_or_roles act=swap_ids+compare_authz verify=unauthorized_object_access next=report block=no_second_account refs=agent_skills/packs/bizlogic_hunter/SKILL.md
id=web.jwt mode=pentest,bugbounty,ctf role=researcher phase=validate tags=jwt,auth ports=80,443 svc=http pre=jwt_seen act=decode_alg_claims_kid_jku_confusion_checks verify=auth_delta next=report_or_pivot block=token_theft refs=agent_skills/packs/api_security/SKILL.md
id=web.oauth mode=pentest,bugbounty role=researcher phase=validate tags=oauth,auth ports=80,443 svc=http pre=oauth_flow act=redirect_uri_state_pkce_audience_checks verify=account_or_token_boundary_bypass next=report block=real_user_harm refs=agent_skills/packs/api_security/SKILL.md
