"""canonical_event_types

Revision ID: 0011_canonical_event_types
Revises: 0010_run_turn_checkpoint
Create Date: 2026-04-25 01:00:00.000000

V25-14 — Backfills ``bus_events.type`` from legacy short names
(``plan``, ``action``, ``observation``, ``critique``, ``policy_decision``)
to the canonical Literal vocabulary (``plan_proposed``, ``action_dispatched``,
``observation_recorded``, ``turn_committed``, ``policy_evaluated``).

Per critical-decision #5: rewrite, don't version-tag.
"""
from typing import Sequence, Union

from alembic import op


revision: str = "0011_canonical_event_types"
down_revision: Union[str, Sequence[str], None] = "0010_run_turn_checkpoint"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_FORWARD = [
    ("plan", "plan_proposed"),
    ("action", "action_dispatched"),
    ("observation", "observation_recorded"),
    ("critique", "turn_committed"),
    ("policy_decision", "policy_evaluated"),
]


def upgrade() -> None:
    for legacy, canonical in _FORWARD:
        op.execute(
            f"UPDATE bus_events SET type = '{canonical}' WHERE type = '{legacy}'"
        )


def downgrade() -> None:
    # Reverse: collapse canonical names back to legacy. Some canonical
    # types have no legacy equivalent (plan_revised/plan_blocked/run_*),
    # so map them to the closest legacy name (policy_decision) to keep
    # the DB consistent with the pre-0011 vocabulary.
    reverse = [
        ("plan_proposed", "plan"),
        ("plan_revised", "policy_decision"),
        ("plan_blocked", "policy_decision"),
        ("action_dispatched", "action"),
        ("observation_recorded", "observation"),
        ("turn_committed", "critique"),
        ("policy_evaluated", "policy_decision"),
        ("proof_created", "policy_decision"),
        ("fact_promoted", "policy_decision"),
        ("run_paused", "policy_decision"),
        ("run_resumed", "policy_decision"),
        ("run_branched", "policy_decision"),
    ]
    for canonical, legacy in reverse:
        op.execute(
            f"UPDATE bus_events SET type = '{legacy}' WHERE type = '{canonical}'"
        )
