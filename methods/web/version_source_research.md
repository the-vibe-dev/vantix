# Dense Codex Context

fmt: id=<id> mode=<csv|*> role=<csv|*> phase=<phase> tags=<csv> ports=<csv> svc=<csv> pre=<conds> act=<bounded_action> verify=<proof> next=<next> block=<stop_conditions> refs=<paths>
load: use `python3 scripts/learn_engine.py --root . lookup tag:<tag> service:<svc> --format prompt`; do not read full playbooks unless no indexed match exists.

id=research.version mode=pentest,bugbounty,ctf,koth role=researcher phase=research tags=version,cve,source ports=* svc=* pre=banner_or_version act=service-source-map+version-research+upstream_diff verify=reachable_code_path next=bounded_validation block=no_version refs=scripts/service-source-map.py,scripts/version-research.sh
id=research.no_poc mode=* role=researcher phase=research tags=cve,source ports=* svc=* pre=cve_checks_fail act=inspect_patch_diff+release_notes+config_paths verify=hypothesis_or_negative next=recon_or_report block=exploit_thrashing refs=PENTEST.md
