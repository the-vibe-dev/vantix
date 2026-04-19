# Dense Codex Context

fmt: id=<id> mode=<csv|*> role=<csv|*> phase=<phase> tags=<csv> ports=<csv> svc=<csv> pre=<conds> act=<bounded_action> verify=<proof> next=<next> block=<stop_conditions> refs=<paths>
load: use `python3 scripts/learn_engine.py --root . lookup tag:<tag> service:<svc> --format prompt`; do not read full playbooks unless no indexed match exists.

id=lin.enum mode=pentest,ctf,koth role=executor phase=privesc tags=linux,privesc ports=* svc=* pre=shell act=id+sudo_l+suid+caps+cron+services+creds verify=ranked_paths next=test_top_path block=no_shell refs=methods/linux/linux_privesc_extended.md
id=lin.sudo mode=pentest,ctf,koth role=executor phase=privesc tags=sudo,linux ports=* svc=* pre=sudo_l_output act=match_gtfobins+env+wildcards verify=uid_change next=stabilize block=destructive_command refs=methods/linux/linux_privesc_extended.md
id=lin.suid mode=pentest,ctf,koth role=executor phase=privesc tags=suid,linux ports=* svc=* pre=suid_binary act=known_gtfobin_or_custom_trace verify=controlled_priv_read_or_shell next=proof block=unknown_binary_mutation refs=methods/linux/linux_privesc_extended.md
id=lin.creds mode=pentest,ctf,koth role=researcher phase=privesc tags=credential,linux ports=* svc=* pre=local_read act=grep_configs_histories_keys_env verify=credential_validity next=pivot block=credential_theft_out_of_scope refs=agent_skills/packs/credential_tester/SKILL.md
id=lin.kernel mode=ctf,koth,pentest role=researcher phase=privesc tags=kernel,linux,cve ports=* svc=* pre=old_kernel act=cve_check+safe_exploitability_probe verify=vulnerable_kernel_signal next=approval block=prod_system refs=docs/cve_mcp.md
