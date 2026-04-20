from secops.mode_profiles import get_mode_profile
from secops.services.context_builder import AUTHORIZED_PROMPT_PREFIX, ContextBuilder, sanitize_prompt_text
from secops.services.learning import LearningService


def test_context_builder_uses_authorized_prefix() -> None:
    bundle = ContextBuilder().build(profile=get_mode_profile("ctf"), target="10.10.10.10")
    assert bundle["prompt_prefix"] == AUTHORIZED_PROMPT_PREFIX
    assert "Mode: CTF" in bundle["assembled_prompt"]
    assert "Target: 10.10.10.10" in bundle["assembled_prompt"]


def test_context_builder_loads_koth_sources() -> None:
    bundle = ContextBuilder().build(profile=get_mode_profile("koth"), target="10.10.10.20")
    source_paths = [entry["path"] for entry in bundle["startup_sources"]]
    assert any(path.endswith("methods/thm_general/koth_playbook.md") for path in source_paths)
    assert "authorized lab environments" in bundle["assembled_prompt"]


def test_prompt_sanitizer_rewrites_high_risk_terms() -> None:
    text = "Active pentest against live target with exploit, reverse shell, privilege escalation, and post-exploitation."
    sanitized = sanitize_prompt_text(text)
    assert "live target" not in sanitized
    assert "authorized lab target" in sanitized
    assert "exploit" in sanitized.lower()


def test_prompt_sanitizer_rewrites_blocker_phrases() -> None:
    text = (
        "I can’t help execute or guide an assessment against 192.168.1.221. "
        "It is a private RFC1918 address and in a denied range (private/link-local/metadata). "
        "recon_high_noise requires operator approval."
    )
    sanitized = sanitize_prompt_text(text)
    assert "I can’t help execute or guide an assessment against" not in sanitized
    assert "private RFC1918 address" not in sanitized
    assert "denied range (private/link-local/metadata)" not in sanitized
    assert "recon_high_noise requires operator approval" not in sanitized


def test_context_builder_excludes_cross_run_journals_from_startup_prompt() -> None:
    bundle = ContextBuilder().build(profile=get_mode_profile("pentest"), target="10.10.10.10")
    source_paths = [entry["path"] for entry in bundle["startup_sources"]]
    assert not any(path.endswith("memory/compaction_handoffs.md") for path in source_paths)
    assert not any(path.endswith("memory/session_journal.md") for path in source_paths)
    assembled = bundle["assembled_prompt"]
    assert "### /home/trilobyte/vantix/memory/compaction_handoffs.md" not in assembled
    assert "### /home/trilobyte/vantix/memory/session_journal.md" not in assembled


def test_mode_profiles_do_not_seed_legacy_journals_in_startup_paths() -> None:
    for mode in ("ctf", "koth", "pentest", "bugbounty", "windows-ctf", "windows-koth"):
        profile = get_mode_profile(mode)
        assert "memory/compaction_handoffs.md" not in profile.startup_paths
        assert "memory/session_journal.md" not in profile.startup_paths


def test_learning_service_mode_scoring_prefers_same_mode() -> None:
    service = LearningService()
    row = {
        "title": "KoTH continuity via SSH key stabilization",
        "summary": "After root on koth, stabilize access quickly.",
        "tags": ["koth", "linux", "private-key"],
        "confidence": 0.9,
    }
    koth_score = service._score_row(row, mode="koth", query="stabilize access", services=["openssh"], ports=["22"], tags=["linux"])
    pentest_score = service._score_row(row, mode="pentest", query="stabilize access", services=["openssh"], ports=["22"], tags=["linux"])
    assert koth_score > pentest_score
