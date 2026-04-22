"""P2-6 — deterministic attack-chain scorer."""
from __future__ import annotations

from secops.services.skills import compute_attack_chain_score


def test_score_is_deterministic():
    a = compute_attack_chain_score(
        validated_step_count=3, total_step_count=5, max_severity="high",
        exploitability=0.6, blast_radius=0.4,
    )
    b = compute_attack_chain_score(
        validated_step_count=3, total_step_count=5, max_severity="high",
        exploitability=0.6, blast_radius=0.4,
    )
    assert a == b
    assert 0 <= a["score"] <= 100


def test_validated_ratio_dominates_when_others_equal():
    low = compute_attack_chain_score(
        validated_step_count=0, total_step_count=5, max_severity="medium",
        exploitability=0.5, blast_radius=0.5,
    )
    high = compute_attack_chain_score(
        validated_step_count=5, total_step_count=5, max_severity="medium",
        exploitability=0.5, blast_radius=0.5,
    )
    assert high["score"] > low["score"]
    # 35-point gap from validated-ratio swing.
    assert high["score"] - low["score"] >= 30


def test_severity_moves_the_score():
    info = compute_attack_chain_score(
        validated_step_count=1, total_step_count=1, max_severity="info",
        exploitability=0.0, blast_radius=0.0,
    )
    critical = compute_attack_chain_score(
        validated_step_count=1, total_step_count=1, max_severity="critical",
        exploitability=0.0, blast_radius=0.0,
    )
    assert critical["score"] > info["score"]


def test_score_is_clamped_to_upper_bound():
    out = compute_attack_chain_score(
        validated_step_count=99, total_step_count=1, max_severity="critical",
        exploitability=5.0, blast_radius=5.0,
    )
    assert out["score"] == 100
    assert out["components"]["validated_step_count"] == 1  # clamped to total
    assert out["components"]["exploitability"] == 1.0
    assert out["components"]["blast_radius"] == 1.0


def test_zero_inputs_handled():
    out = compute_attack_chain_score(
        validated_step_count=0, total_step_count=0, max_severity="",
        exploitability=0.0, blast_radius=0.0,
    )
    assert 0 <= out["score"] <= 100
    assert out["components"]["total_step_count"] == 1  # guarded against div-by-zero
    assert out["components"]["max_severity"] == "info"  # empty string falls through to info


def test_unknown_severity_falls_through_to_info():
    out = compute_attack_chain_score(
        validated_step_count=0, total_step_count=1, max_severity="bogus",
        exploitability=0.0, blast_radius=0.0,
    )
    assert out["components"]["severity_points"] == 2  # info weight
