from __future__ import annotations

PHASE_SEQUENCE = [
    "context-bootstrap",
    "source-intake",
    "source-analysis",
    "learning-recall",
    "recon-sidecar",
    "browser-assessment",
    "cve-analysis",
    "orchestrate",
    "learn-ingest",
    "report",
]


def next_phase(current_phase: str) -> str | None:
    try:
        idx = PHASE_SEQUENCE.index(current_phase)
    except ValueError:
        return None
    if idx + 1 >= len(PHASE_SEQUENCE):
        return None
    return PHASE_SEQUENCE[idx + 1]
