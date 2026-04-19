from pathlib import Path
from types import SimpleNamespace

from scripts.learn_engine import load_dense_playbook_records, parse_dense_record
from secops.mode_profiles import get_mode_profile
from secops.services.context_builder import ContextBuilder
from secops.services.memory_writer import DenseMemoryRecord, MemoryWriteService
from secops.services.skills import PromptAssembler


def test_dense_record_parser_indexes_core_fields() -> None:
    line = "id=web.sqli mode=pentest,ctf role=executor phase=validate tags=sqli,web ports=80,443 svc=http pre=input act=test verify=delta next=report block=none refs=PENTEST.md"
    record = parse_dense_record(line, source_path="PENTEST.md")
    assert record is not None
    assert record["id"] == "web.sqli"
    assert record["mode"] == ["pentest", "ctf"]
    assert record["role"] == ["executor"]
    assert record["tags"] == ["sqli", "web"]
    assert record["ports"] == ["80", "443"]
    assert record["svc"] == ["http"]


def test_dense_record_parser_keeps_quoted_lookup_command() -> None:
    line = 'id=lookup.playbook mode=* role=* phase=all tags=lookup,intel trigger=need_method cmd="python3 scripts/learn_engine.py --root . context mode:<mode> tag:<tag>" use=playbook_records next=apply_bounded block=full_playbook_load'
    record = parse_dense_record(line, source_path="LOOKUP.md")
    assert record is not None
    assert record["phase"] == "all"
    assert record["tags"] == ["lookup", "intel"]
    assert record["cmd"] == "python3 scripts/learn_engine.py --root . context mode:<mode> tag:<tag>"


def test_dense_playbooks_are_loadable_from_repo() -> None:
    records = load_dense_playbook_records(Path.cwd())
    ids = {record["id"] for record in records}
    assert "agent.lookup" in ids
    assert "core.scope" in ids
    assert "lookup.playbook" in ids
    assert "web.sqli" in ids
    assert "koth.rules" in ids


def test_context_builder_uses_dense_slices_not_full_playbooks() -> None:
    bundle = ContextBuilder().build(profile=get_mode_profile("pentest"), target="10.10.10.10", ports=["80"], services=["http"], extra_tags=["web"])
    assembled = bundle["assembled_prompt"]
    assert "id=core.scope" in assembled
    assert "web.sqli" in assembled or "web.baseline" in assembled
    assert "## Official THM KoTH Rules (verbatim)" not in assembled
    assert len(assembled) < 30000


def test_memory_writer_compat_mirror_is_dense(tmp_path: Path) -> None:
    writer = MemoryWriteService(repo_root=tmp_path)
    writer.write(DenseMemoryRecord(mode="handoff", phase="test", objective="obj", done=["done"], issues=["none"], next_action="next", context=["ctf"]))
    mirror = (tmp_path / "memory" / "compaction_handoffs.md").read_text(encoding="utf-8")
    assert "fmt: ts=<utc>" in mirror
    assert "mode=handoff" in mirror
    assert "- Current objective:" not in mirror


def test_prompt_assembler_includes_focus_and_lookup_guidance() -> None:
    run = SimpleNamespace(
        mode="pentest",
        target="10.10.10.10",
        objective="Validate web exposure",
        config_json={"tags": ["web"], "ports": ["80"], "services": ["http"]},
    )
    facts = [
        SimpleNamespace(kind="service", source="recon", value="apache", metadata_json={}),
        SimpleNamespace(kind="version", source="recon", value="Apache httpd 2.4.49", metadata_json={}),
        SimpleNamespace(kind="cve", source="intel", value="CVE-2021-41773", metadata_json={}),
    ]
    prompt = PromptAssembler().assemble(run, "researcher", [], facts)
    assert "## Intelligence Lookup" in prompt
    assert "focus: mode=pentest" in prompt
    assert "svc=apache,http" in prompt or "svc=http,apache" in prompt
    assert "cves=CVE-2021-41773" in prompt
    assert "id=lookup.playbook" in prompt
    assert "id=lookup.recon_focus" in prompt
