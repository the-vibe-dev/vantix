"""llm_cache

Revision ID: 0008_llm_cache
Revises: 0007_bus_events
Create Date: 2026-04-23 00:00:00.000000

Adds the LLM cache table used by the replay layer (V2-11). Strict keying
(model + params_sha256 + prompt_sha256) so cached replays are bit-identical.
Response bodies are stored in ``content_blobs`` and referenced by sha256.

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0008_llm_cache"
down_revision: Union[str, Sequence[str], None] = "0007_bus_events"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "llm_cache_entries",
        sa.Column("key_sha256", sa.String(length=64), nullable=False),
        sa.Column("model", sa.String(length=128), nullable=False),
        sa.Column("params_sha256", sa.String(length=64), nullable=False),
        sa.Column("prompt_sha256", sa.String(length=64), nullable=False),
        sa.Column("response_blob_sha256", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("key_sha256"),
    )
    op.create_index(
        "ix_llm_cache_model_params",
        "llm_cache_entries",
        ["model", "params_sha256"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_llm_cache_model_params", table_name="llm_cache_entries")
    op.drop_table("llm_cache_entries")
