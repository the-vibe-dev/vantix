from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass(frozen=True)
class ModeProfile:
    id: str
    label: str
    description: str
    ruleset: str
    startup_paths: list[str]
    pentest_keywords: list[str]
    learn_tags: list[str] = field(default_factory=list)
    allowed_adapters: list[str] = field(default_factory=list)
    report_style: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


MODE_PROFILES: dict[str, ModeProfile] = {
    "ctf": ModeProfile(
        id="ctf",
        label="CTF",
        description="Training and challenge mode with replayable artifacts and solve-focused learning.",
        ruleset="standard-ctf",
        startup_paths=[
            "MEM.md",
            "PENTEST.md",
            "methods/ctf/ctfplaybook.md",
        ],
        pentest_keywords=["Purpose", "Session Learning Loop", "Core Rules", "Research Policy"],
        learn_tags=["ctf"],
        allowed_adapters=["codex", "learn_engine", "binary_re", "exploit_pipeline", "vpn_watch"],
        report_style="Objective chain, validated answers, artifacts, and replay notes.",
    ),
    "koth": ModeProfile(
        id="koth",
        label="KoTH",
        description="King-of-the-Hill mode with availability rules, continuity, and opponent intelligence.",
        ruleset="thm-koth",
        startup_paths=[
            "MEM.md",
            "PENTEST.md",
            "methods/thm_general/koth_playbook.md",
        ],
        pentest_keywords=[
            "Purpose",
            "Authorization and Safety Gate",
            "Core Rules",
            "KoTH Quick Reference",
            "Opponent Intelligence",
        ],
        learn_tags=["koth", "linux"],
        allowed_adapters=["codex", "learn_engine", "vpn_watch", "koth_ops", "exploit_pipeline"],
        report_style="Claim path, patch path, hold path, opponent intel, and rules compliance.",
    ),
    "pentest": ModeProfile(
        id="pentest",
        label="Pentest",
        description="Authorized assessment mode with evidence-driven validation and remediation.",
        ruleset="authorized-pentest",
        startup_paths=[
            "MEM.md",
            "PENTEST.md",
        ],
        pentest_keywords=[
            "Purpose",
            "Mission Priorities",
            "Authorization and Safety Gate",
            "Core Rules",
            "Operating Model: Observation → Hypothesis → Validation → Pivot",
        ],
        learn_tags=["web", "linux", "windows"],
        allowed_adapters=["codex", "learn_engine", "source_audit", "exploit_pipeline", "vpn_watch"],
        report_style="Findings, severity, evidence, reproduction, and remediation.",
    ),
    "bugbounty": ModeProfile(
        id="bugbounty",
        label="Bug Bounty",
        description="Program-safe recon and validation mode with scope enforcement and report generation.",
        ruleset="bugbounty-safe",
        startup_paths=[
            "MEM.md",
            "PENTEST.md",
            "agent_ops/README.md",
        ],
        pentest_keywords=[
            "Purpose",
            "Mission Priorities",
            "Authorization and Safety Gate",
            "Research Policy",
        ],
        learn_tags=["web", "bugbounty"],
        allowed_adapters=["codex", "learn_engine", "bugbounty_hunter", "source_audit", "exploit_pipeline"],
        report_style="Program-safe evidence and report-ready reproduction steps.",
    ),
    "windows-ctf": ModeProfile(
        id="windows-ctf",
        label="Windows CTF",
        description="Windows-focused challenge mode with AD and WinRM workflows.",
        ruleset="windows-ctf",
        startup_paths=[
            "MEM.md",
            "WINDOWS.md",
            "PENTEST.md",
            "methods/windows/windows_pentest_playbook.md",
        ],
        pentest_keywords=["Core Rules", "Research Policy"],
        learn_tags=["windows", "ctf"],
        allowed_adapters=["codex", "windows_ops", "learn_engine", "vpn_watch"],
        report_style="Validated Windows/AD chain with challenge artifacts.",
    ),
    "windows-koth": ModeProfile(
        id="windows-koth",
        label="Windows KoTH",
        description="Windows hill-control mode with hold mechanics and continuity constraints.",
        ruleset="windows-koth",
        startup_paths=[
            "MEM.md",
            "WINDOWS.md",
            "PENTEST.md",
            "methods/windows/windows_koth.md",
        ],
        pentest_keywords=["Core Rules", "KoTH Quick Reference", "Opponent Intelligence"],
        learn_tags=["windows", "koth"],
        allowed_adapters=["codex", "windows_ops", "learn_engine", "vpn_watch", "koth_ops"],
        report_style="Hold mechanics, continuity, adversary behavior, and rules compliance.",
    ),
}


def get_mode_profile(mode: str) -> ModeProfile:
    if mode not in MODE_PROFILES:
        raise KeyError(f"Unknown mode: {mode}")
    return MODE_PROFILES[mode]
