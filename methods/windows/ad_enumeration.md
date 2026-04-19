# Dense Codex Context

fmt: id=<id> mode=<csv|*> role=<csv|*> phase=<phase> tags=<csv> ports=<csv> svc=<csv> pre=<conds> act=<bounded_action> verify=<proof> next=<next> block=<stop_conditions> refs=<paths>
load: use `python3 scripts/learn_engine.py --root . lookup tag:<tag> service:<svc> --format prompt`; do not read full playbooks unless no indexed match exists.

id=ad.base mode=windows-ctf,pentest role=recon phase=ad tags=ad,ldap,kerberos ports=88,389,445 svc=ldap,kerberos,smb pre=domain_signals act=ldap_base+dns+time+domain_info verify=base_dn+dc next=user_enum block=no_domain refs=methods/windows/ad_enumeration.md
id=ad.users mode=windows-ctf,pentest role=recon phase=ad tags=ad,user-enum ports=88,389 svc=kerberos,ldap pre=domain_known act=kerbrute_or_rpc_ldap_user_enum verify=user_list next=roast_checks block=lockout refs=agent_skills/packs/ad_attacker/SKILL.md
id=ad.kerberoast mode=windows-ctf,pentest role=researcher phase=ad tags=kerberoast,ad ports=88,389 svc=kerberos pre=valid_creds+spn act=request_tgs+crack_offline verify=service_cred next=path_map block=spray refs=agent_ops/config/cracking_nodes.example.yaml
id=ad.asrep mode=windows-ctf,pentest role=researcher phase=ad tags=asrep,ad ports=88 svc=kerberos pre=user_list act=GetNPUsers_safe_enum verify=hashes_or_negative next=crack_offline block=lockout refs=agent_skills/packs/ad_attacker/SKILL.md
id=ad.bloodhound mode=windows-ctf,pentest role=researcher phase=ad tags=bloodhound,ad ports=389,445 svc=ldap,smb pre=domain_creds act=collect_minimal_edges verify=graph_loaded next=rank_paths block=no_approval refs=methods/windows/ad_enumeration.md
