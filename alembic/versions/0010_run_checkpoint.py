"""run_turn_checkpoint

Revision ID: 0010_run_turn_checkpoint
Revises: 0009_replay_engine
Create Date: 2026-04-25 00:30:00.000000

V25-11 — adds the RunTurnCheckpoint table written by the planner-loop
at the end of every turn so V25-12 can resume after a crash by
replaying bus events forward from the latest checkpoint. Distinct from
the phase-level ``run_checkpoints`` table owned by the workflow engine.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0010_run_turn_checkpoint"
down_revision: Union[str, Sequence[str], None] = "0009_replay_engine"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "run_turn_checkpoints",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("branch_id", sa.String(length=64), nullable=False, server_default="main"),
        sa.Column("turn_id", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("seq", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("run_state_blob_sha", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["run_id"], ["workspace_runs.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_run_turn_checkpoints_run_id", "run_turn_checkpoints", ["run_id"])
    op.create_index("ix_run_turn_checkpoints_run_branch_turn", "run_turn_checkpoints", ["run_id", "branch_id", "turn_id"])


def downgrade() -> None:
    op.drop_index("ix_run_turn_checkpoints_run_branch_turn", table_name="run_turn_checkpoints")
    op.drop_index("ix_run_turn_checkpoints_run_id", table_name="run_turn_checkpoints")
    op.drop_table("run_turn_checkpoints")
