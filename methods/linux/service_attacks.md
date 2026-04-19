# Dense Codex Context

fmt: id=<id> mode=<csv|*> role=<csv|*> phase=<phase> tags=<csv> ports=<csv> svc=<csv> pre=<conds> act=<bounded_action> verify=<proof> next=<next> block=<stop_conditions> refs=<paths>
load: use `python3 scripts/learn_engine.py --root . lookup tag:<tag> service:<svc> --format prompt`; do not read full playbooks unless no indexed match exists.

id=svc.ftp mode=pentest,ctf,koth role=recon phase=recon tags=ftp,service ports=21 svc=ftp pre=port21 act=anon_check+banner+write_test_if_allowed verify=listing_or_creds next=files_review block=write_without_scope refs=methods/linux/service_attacks.md
id=svc.ssh mode=pentest,ctf,koth role=recon phase=recon tags=ssh,service ports=22 svc=openssh pre=port22 act=banner+auth_methods+known_creds_check verify=login_or_negative next=credential_policy block=spray refs=agent_skills/packs/credential_tester/SKILL.md
id=svc.smb mode=pentest,ctf,koth,windows-ctf role=recon phase=recon tags=smb,windows ports=139,445 svc=smb pre=smb_open act=smbmap+smbclient_null+enum4linux verify=shares+signing+users next=cve_or_auth block=lockout refs=methods/windows/ad_enumeration.md
id=svc.redis mode=pentest,ctf,koth role=executor phase=validate tags=redis,rce ports=6379 svc=redis pre=redis_open act=info+auth_check+config_safety verify=unauth_or_version next=impact_plan block=config_write_no_scope refs=methods/linux/service_attacks.md
id=svc.db mode=pentest,ctf role=recon phase=recon tags=db,service ports=3306,5432,1433 svc=mysql,postgres,mssql pre=db_open act=banner+default_auth_policy+schema_if_creds verify=version+auth_state next=cve_or_app_link block=bruteforce refs=methods/linux/service_attacks.md
