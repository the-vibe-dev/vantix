# Dense Codex Context

fmt: id=<id> mode=<csv|*> role=<csv|*> phase=<phase> tags=<csv> ports=<csv> svc=<csv> pre=<conds> act=<bounded_action> verify=<proof> next=<next> block=<stop_conditions> refs=<paths>
load: use `python3 scripts/learn_engine.py --root . lookup tag:<tag> service:<svc> --format prompt`; do not read full playbooks unless no indexed match exists.

id=sqli.wp_resumable mode=ctf,pentest role=executor phase=validate tags=sqli,wordpress,resume ports=80,443 svc=wordpress pre=wp_sqli_signal act=extract_incrementally+checkpoint_offsets verify=recovered_rows next=crack_or_report block=data_overreach refs=methods/sqli_resumable_wordpress/README.md
