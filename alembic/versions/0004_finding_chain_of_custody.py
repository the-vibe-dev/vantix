"""finding_chain_of_custody

Revision ID: 0004_finding_chain_of_custody
Revises: 0003_validation_and_evidence
Create Date: 2026-04-21 00:00:00.000000

P2-3 — chain-of-custody columns on findings:
  * promoted_at      — when the finding was auto-promoted from a Fact
  * reviewed_at      — when a human reviewer acted on the finding
  * reviewer_user_id — FK to users.id for accountability
  * disposition      — draft | reviewed | confirmed | dismissed

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0004_finding_chain_of_custody"
down_revision: Union[str, Sequence[str], None] = "0003_validation_and_evidence"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("findings", schema=None) as batch_op:
        batch_op.add_column(sa.Column("promoted_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("reviewer_user_id", sa.String(length=36), nullable=True))
        batch_op.add_column(
            sa.Column(
                "disposition",
                sa.String(length=32),
                nullable=False,
                server_default="draft",
            )
        )
        batch_op.create_index(
            "ix_findings_reviewer_user_id", ["reviewer_user_id"], unique=False
        )
        batch_op.create_foreign_key(
            "fk_findings_reviewer_user_id_users",
            "users",
            ["reviewer_user_id"],
            ["id"],
        )


def downgrade() -> None:
    with op.batch_alter_table("findings", schema=None) as batch_op:
        batch_op.drop_constraint("fk_findings_reviewer_user_id_users", type_="foreignkey")
        batch_op.drop_index("ix_findings_reviewer_user_id")
        batch_op.drop_column("disposition")
        batch_op.drop_column("reviewer_user_id")
        batch_op.drop_column("reviewed_at")
        batch_op.drop_column("promoted_at")
