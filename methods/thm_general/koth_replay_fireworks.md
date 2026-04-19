# Dense Codex Context

fmt: id=<id> mode=<csv|*> role=<csv|*> phase=<phase> tags=<csv> ports=<csv> svc=<csv> pre=<conds> act=<bounded_action> verify=<proof> next=<next> block=<stop_conditions> refs=<paths>
load: use `python3 scripts/learn_engine.py --root . lookup tag:<tag> service:<svc> --format prompt`; do not read full playbooks unless no indexed match exists.

id=koth.replay.fireworks mode=koth role=executor phase=recover tags=koth,replay ports=9999 svc=koth pre=known_fireworks_box act=check_prior_paths+validate_live_before_reuse verify=current_proof next=claim block=stale_replay refs=methods/thm_general/koth_replay_fireworks.md
