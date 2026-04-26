"""replay_engine

Revision ID: 0009_replay_engine
Revises: 0008_llm_cache
Create Date: 2026-04-25 00:00:00.000000

V25-04 — adds ReplaySpec/ReplayRun/ReplayStep/ReplayDiff tables that back
the Phase 3 replay execution engine. The signed turn manifest from
secops.replay.turn_manifest is materialized as a ReplaySpec; each
``vantix-replay <spec-id>`` invocation produces a ReplayRun with one
ReplayStep per turn and N ReplayDiff rows for any divergences.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0009_replay_engine"
down_revision: Union[str, Sequence[str], None] = "0008_llm_cache"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "replay_specs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("branch_id", sa.String(length=64), nullable=False, server_default="main"),
        sa.Column("manifest_sha256", sa.String(length=64), nullable=False),
        sa.Column("manifest_json", sa.JSON(), nullable=False),
        sa.Column("signed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("signed_by", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["run_id"], ["workspace_runs.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_replay_specs_run_id", "replay_specs", ["run_id"])
    op.create_index("ix_replay_specs_manifest_sha256", "replay_specs", ["manifest_sha256"])

    op.create_table(
        "replay_runs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("spec_id", sa.String(length=36), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="running"),
        sa.Column("divergence_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("summary", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(["spec_id"], ["replay_specs.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_replay_runs_spec_id", "replay_runs", ["spec_id"])

    op.create_table(
        "replay_steps",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("replay_run_id", sa.String(length=36), nullable=False),
        sa.Column("turn_id", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("seq", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("agent", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("type", sa.String(length=32), nullable=False, server_default=""),
        sa.Column("expected_msg_sha256", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("actual_msg_sha256", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("divergence_kind", sa.String(length=32), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["replay_run_id"], ["replay_runs.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_replay_steps_replay_run_id", "replay_steps", ["replay_run_id"])
    op.create_index("ix_replay_steps_run_turn", "replay_steps", ["replay_run_id", "turn_id"])

    op.create_table(
        "replay_diffs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("replay_run_id", sa.String(length=36), nullable=False),
        sa.Column("turn_id", sa.Integer(), nullable=True),
        sa.Column("kind", sa.String(length=32), nullable=False, server_default=""),
        sa.Column("lhs_blob_sha", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("rhs_blob_sha", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("summary", sa.Text(), nullable=False, server_default=""),
        sa.Column("detail", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["replay_run_id"], ["replay_runs.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_replay_diffs_replay_run_id", "replay_diffs", ["replay_run_id"])


def downgrade() -> None:
    op.drop_index("ix_replay_diffs_replay_run_id", table_name="replay_diffs")
    op.drop_table("replay_diffs")
    op.drop_index("ix_replay_steps_run_turn", table_name="replay_steps")
    op.drop_index("ix_replay_steps_replay_run_id", table_name="replay_steps")
    op.drop_table("replay_steps")
    op.drop_index("ix_replay_runs_spec_id", table_name="replay_runs")
    op.drop_table("replay_runs")
    op.drop_index("ix_replay_specs_manifest_sha256", table_name="replay_specs")
    op.drop_index("ix_replay_specs_run_id", table_name="replay_specs")
    op.drop_table("replay_specs")
