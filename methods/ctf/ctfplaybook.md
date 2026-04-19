# Dense Codex Context

fmt: id=<id> mode=<csv|*> role=<csv|*> phase=<phase> tags=<csv> ports=<csv> svc=<csv> pre=<conds> act=<bounded_action> verify=<proof> next=<next> block=<stop_conditions> refs=<paths>
load: use `python3 scripts/learn_engine.py --root . lookup tag:<tag> service:<svc> --format prompt`; do not read full playbooks unless no indexed match exists.

id=ctf.start mode=ctf role=orchestrator phase=init tags=ctf,startup ports=* svc=* pre=authorized_target act=create_workspace+load_dense_digest verify=target+scope+next next=recon block=spoiler_source refs=PENTEST.md
id=ctf.recon mode=ctf role=recon phase=recon tags=ctf,recon ports=* svc=* pre=target_up act=nmap_top_then_full+service_enum verify=open_ports+versions next=cve_gate block=scan_noise refs=scripts/exploit-pipeline.sh
id=ctf.web mode=ctf role=recon,researcher phase=web tags=web,ctf ports=80,443 svc=http,apache,nginx pre=http_open act=vhost+dir+param+tech_fingerprint verify=endpoints+version next=web_vector_lookup block=writeup_refs refs=methods/web/web_vuln_playbook.md
id=ctf.privesc mode=ctf role=executor phase=privesc tags=linux,privesc ports=* svc=* pre=foothold act=sudo_suid_cron_capabilities_creds verify=user_to_root_path next=flag_sweep block=unstable_shell refs=methods/linux/linux_privesc_extended.md
id=ctf.close mode=ctf role=reporter phase=close tags=ctf,report ports=* svc=* pre=proof_captured act=record_flags+chain+artifacts+lessons verify=replay_notes next=close_memory block=unverified_flag refs=runbooks/workflow.md
