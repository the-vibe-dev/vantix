# Dense Codex Context

fmt: id=<id> mode=<csv|*> role=<csv|*> phase=<phase> tags=<csv> ports=<csv> svc=<csv> pre=<conds> act=<bounded_action> verify=<proof> next=<next> block=<stop_conditions> refs=<paths>
load: use `python3 scripts/learn_engine.py --root . lookup tag:<tag> service:<svc> --format prompt`; do not read full playbooks unless no indexed match exists.

id=ctf.crypto mode=ctf role=researcher phase=analyze tags=crypto,ctf ports=* svc=* pre=ciphertext_or_encoding act=identify_encoding->frequency->known_plaintext->tool verify=decoded_signal next=validate_on_target block=random_guess refs=methods/ctf/ctf_techniques.md
id=ctf.steg mode=ctf role=researcher phase=analyze tags=steg,forensics ports=* svc=* pre=image_audio_archive act=file+exiftool+binwalk+strings+stegsolve/zsteg verify=hidden_payload next=decode block=destructive_edit refs=methods/ctf/ctf_techniques.md
id=ctf.rev mode=ctf role=developer phase=analyze tags=re,pwn ports=* svc=* pre=binary act=file+checksec+strings+ltrace+ghidra verify=input_constraint_or_bug next=poc block=unknown_arch refs=methods/ctf/ctf_techniques.md
id=ctf.web_common mode=ctf role=researcher phase=web tags=sqli,xss,lfi,ssti,upload ports=80,443 svc=http pre=input_surface act=test_one_class_at_time verify=response_delta next=exploit_plan block=no_baseline refs=methods/web/web_vuln_playbook.md
