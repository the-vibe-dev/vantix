# Dense Codex Context

fmt: id=<id> mode=<csv|*> role=<csv|*> phase=<phase> tags=<csv> ports=<csv> svc=<csv> pre=<conds> act=<bounded_action> verify=<proof> next=<next> block=<stop_conditions> refs=<paths>
load: use `python3 scripts/learn_engine.py --root . lookup tag:<tag> service:<svc> --format prompt`; do not read full playbooks unless no indexed match exists.

id=winkoth.rules mode=windows-koth role=* phase=all tags=windows,koth,safety ports=* svc=* pre=round_active act=preserve_services+no_dos+no_game_service_tamper verify=rules_checked next=continue block=rule_conflict refs=AGENTS.md
id=winkoth.claim mode=windows-koth role=executor phase=claim tags=windows,koth ports=* svc=* pre=admin act=write_operator_to_king_mechanism+verify_scoreboard verify=holder_matches next=continuity block=service_breakage refs=methods/windows/windows_koth.md
id=winkoth.hold mode=windows-koth role=executor phase=hold tags=windows,koth,continuity ports=3389,5985 svc=rdp,winrm pre=claim+approval act=backup_access+monitor+minimal_defense verify=access_survives next=observe block=availability_impact refs=methods/windows/windows_koth.md
