# Dense Codex Context

fmt: id=<id> mode=<csv|*> role=<csv|*> phase=<phase> tags=<csv> ports=<csv> svc=<csv> pre=<conds> act=<bounded_action> verify=<proof> next=<next> block=<stop_conditions> refs=<paths>
load: use `python3 scripts/learn_engine.py --root . lookup tag:<tag> service:<svc> --format prompt`; do not read full playbooks unless no indexed match exists.

id=koth.rules mode=koth,windows-koth role=* phase=all tags=koth,safety ports=9999 svc=koth pre=round_active act=preserve_availability+do_not_attack_king_service+no_dos verify=rules_checked next=continue block=rule_conflict refs=AGENTS.md
id=koth.fast_recon mode=koth role=recon phase=recon tags=koth,recon ports=* svc=* pre=target_up act=nmap_low_noise+version_cve_gate+easy_path_sweep verify=entry_candidates next=foothold block=scan_instability refs=PENTEST.md
id=koth.claim mode=koth role=executor phase=claim tags=koth,king ports=9999 svc=koth pre=root act=write_operator_to_/root/king.txt+verify_9999 verify=holder_matches next=hold block=immutable_or_bind_source refs=scripts/koth-claim-watch.sh
id=koth.hold mode=koth role=executor phase=hold tags=koth,continuity ports=22,9999 svc=ssh,koth pre=king_claimed+operator_approval act=install_controlled_hold+backup_access verify=5_consecutive_holder_checks next=flag_sweep block=service_breakage refs=scripts/koth-continuity.sh
id=koth.loss mode=koth role=executor phase=recover tags=koth,recover ports=22,9999 svc=ssh,koth pre=holder_changed act=check_root_ssh+backup_path+hold_state+retake_fast verify=holder_restored next=strengthen_hold block=no_access refs=scripts/koth-loss-recover.sh
id=koth.opponent mode=koth role=researcher phase=observe tags=koth,opponent ports=* svc=* pre=opponent_artifact act=capture_before_neutralize+ingest_report verify=family_tags next=defense_update block=attacking_users refs=scripts/learn_engine.py
