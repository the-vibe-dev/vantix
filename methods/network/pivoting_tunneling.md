# Dense Codex Context

fmt: id=<id> mode=<csv|*> role=<csv|*> phase=<phase> tags=<csv> ports=<csv> svc=<csv> pre=<conds> act=<bounded_action> verify=<proof> next=<next> block=<stop_conditions> refs=<paths>
load: use `python3 scripts/learn_engine.py --root . lookup tag:<tag> service:<svc> --format prompt`; do not read full playbooks unless no indexed match exists.

id=pivot.need mode=pentest,ctf,koth,windows-ctf,windows-koth role=orchestrator phase=pivot tags=pivoting,network ports=* svc=* pre=internal_route_needed act=map_routes+choose_socks_or_forward verify=internal_reachability next=targeted_recon block=out_of_scope_net refs=methods/network/pivoting_tunneling.md
id=pivot.ssh mode=pentest,ctf,koth role=executor phase=pivot tags=ssh,pivoting ports=22 svc=ssh pre=ssh_creds act=ssh_dynamic_or_local_forward verify=proxy_test next=scan_internal block=credential_policy refs=methods/network/pivoting_tunneling.md
id=pivot.chisel mode=ctf,koth,pentest role=executor phase=pivot tags=chisel,pivoting ports=* svc=* pre=upload_exec_allowed act=start_reverse_socks_with_operator_listener verify=socks_works next=proxychains block=egress_block refs=methods/network/pivoting_tunneling.md
