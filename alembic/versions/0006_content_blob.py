"""content_blob

Revision ID: 0006_content_blob
Revises: 0005_attack_graph
Create Date: 2026-04-23 00:00:00.000000

Adds the content-addressed blob table used by the replay layer to pin
LLM prompt/response and tool stdout/stderr bytes by sha256.

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0006_content_blob"
down_revision: Union[str, Sequence[str], None] = "0005_attack_graph"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "content_blobs",
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("content_type", sa.String(length=128), nullable=False, server_default="application/octet-stream"),
        sa.Column("size_bytes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("data", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("sha256"),
    )


def downgrade() -> None:
    op.drop_table("content_blobs")
