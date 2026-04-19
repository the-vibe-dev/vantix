# Dense Codex Context

fmt: id=<id> mode=<csv|*> role=<csv|*> phase=<phase> tags=<csv> ports=<csv> svc=<csv> pre=<conds> act=<bounded_action> verify=<proof> next=<next> block=<stop_conditions> refs=<paths>
load: use `python3 scripts/learn_engine.py --root . lookup tag:<tag> service:<svc> --format prompt`; do not read full playbooks unless no indexed match exists.

id=xss.replay mode=ctf,bugbounty,pentest role=executor phase=validate tags=xss,replay ports=80,443 svc=http pre=reflected_or_stored_input act=min_payload+context_breakout+browser_verify verify=callback_or_dom_execution next=report block=no_user_impact refs=methods/web/web_vuln_playbook.md
id=xss.filter mode=ctf,bugbounty,pentest role=researcher phase=validate tags=xss,filter ports=80,443 svc=http pre=filter_detected act=test_case_encoding_event_handlers_svg_mathml verify=allowed_primitive next=payload_shape block=blind_random_payloads refs=methods/ctf/xss_replay_commands.md
