"""bus_events

Revision ID: 0007_bus_events
Revises: 0006_content_blob
Create Date: 2026-04-23 00:10:00.000000

Adds the durable agent-message bus event table.

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0007_bus_events"
down_revision: Union[str, Sequence[str], None] = "0006_content_blob"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "bus_events",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("branch_id", sa.String(length=64), nullable=False, server_default="main"),
        sa.Column("seq", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("turn_id", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("agent", sa.String(length=64), nullable=False),
        sa.Column("type", sa.String(length=32), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("parent_turn_id", sa.Integer(), nullable=True),
        sa.Column("caused_by_fact_ids", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("content_hash", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["run_id"], ["workspace_runs.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_bus_events_run_id", "bus_events", ["run_id"], unique=False)
    op.create_index("ix_bus_events_run_turn", "bus_events", ["run_id", "turn_id"], unique=False)
    op.create_index(
        "ix_bus_events_run_branch_seq",
        "bus_events",
        ["run_id", "branch_id", "seq"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_bus_events_run_branch_seq", table_name="bus_events")
    op.drop_index("ix_bus_events_run_turn", table_name="bus_events")
    op.drop_index("ix_bus_events_run_id", table_name="bus_events")
    op.drop_table("bus_events")
