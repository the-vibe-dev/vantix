"""validation_and_evidence

Revision ID: 0003_validation_and_evidence
Revises: 0002_users_and_roles
Create Date: 2026-04-20 15:30:00.000000

Phase 1 Pentest Improvement:
- facts.validated (bool), facts.fingerprint (str, indexed) for proof-before-promotion + dedup
- findings.fingerprint, findings.evidence_ids, findings.reproduction_script for evidence linkage

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0003_validation_and_evidence"
down_revision: Union[str, Sequence[str], None] = "0002_users_and_roles"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("facts", schema=None) as batch_op:
        batch_op.add_column(sa.Column("validated", sa.Boolean(), nullable=False, server_default=sa.false()))
        batch_op.add_column(sa.Column("fingerprint", sa.String(length=64), nullable=True))
        batch_op.create_index(batch_op.f("ix_facts_fingerprint"), ["fingerprint"], unique=False)

    with op.batch_alter_table("findings", schema=None) as batch_op:
        batch_op.add_column(sa.Column("fingerprint", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("evidence_ids", sa.JSON(), nullable=False, server_default=sa.text("'[]'")))
        batch_op.add_column(sa.Column("reproduction_script", sa.Text(), nullable=False, server_default=""))
        batch_op.create_index("ix_findings_run_fingerprint", ["run_id", "fingerprint"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("findings", schema=None) as batch_op:
        batch_op.drop_index("ix_findings_run_fingerprint")
        batch_op.drop_column("reproduction_script")
        batch_op.drop_column("evidence_ids")
        batch_op.drop_column("fingerprint")

    with op.batch_alter_table("facts", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_facts_fingerprint"))
        batch_op.drop_column("fingerprint")
        batch_op.drop_column("validated")
