from secops.mode_profiles import get_mode_profile
from secops.services.context_builder import AUTHORIZED_PROMPT_PREFIX, ContextBuilder
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
