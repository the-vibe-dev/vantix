"""attack_graph

Revision ID: 0005_attack_graph
Revises: 0004_finding_chain_of_custody
Create Date: 2026-04-22 00:00:00.000000

Adds a lightweight per-run attack graph using relational node/edge tables.
This keeps Vantix replayable and install-light while giving the planner and UI
a stable target knowledge representation.

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0005_attack_graph"
down_revision: Union[str, Sequence[str], None] = "0004_finding_chain_of_custody"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "attack_graph_nodes",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("node_type", sa.String(length=64), nullable=False),
        sa.Column("stable_key", sa.String(length=255), nullable=False),
        sa.Column("label", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("source_kind", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("source_id", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0"),
        sa.Column("metadata", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["run_id"], ["workspace_runs.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("run_id", "node_type", "stable_key", name="uq_attack_graph_node_run_type_key"),
    )
    op.create_index("ix_attack_graph_nodes_run_id", "attack_graph_nodes", ["run_id"], unique=False)
    op.create_index("ix_attack_graph_nodes_node_type", "attack_graph_nodes", ["node_type"], unique=False)
    op.create_index("ix_attack_graph_nodes_stable_key", "attack_graph_nodes", ["stable_key"], unique=False)
    op.create_index("ix_attack_graph_nodes_source_id", "attack_graph_nodes", ["source_id"], unique=False)
    op.create_index("ix_attack_graph_nodes_run_type", "attack_graph_nodes", ["run_id", "node_type"], unique=False)

    op.create_table(
        "attack_graph_edges",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("source_node_id", sa.String(length=36), nullable=False),
        sa.Column("target_node_id", sa.String(length=36), nullable=False),
        sa.Column("edge_type", sa.String(length=64), nullable=False),
        sa.Column("source_kind", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("source_id", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0"),
        sa.Column("metadata", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["run_id"], ["workspace_runs.id"]),
        sa.ForeignKeyConstraint(["source_node_id"], ["attack_graph_nodes.id"]),
        sa.ForeignKeyConstraint(["target_node_id"], ["attack_graph_nodes.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("run_id", "source_node_id", "edge_type", "target_node_id", name="uq_attack_graph_edge_run_src_type_dst"),
    )
    op.create_index("ix_attack_graph_edges_run_id", "attack_graph_edges", ["run_id"], unique=False)
    op.create_index("ix_attack_graph_edges_source_node_id", "attack_graph_edges", ["source_node_id"], unique=False)
    op.create_index("ix_attack_graph_edges_target_node_id", "attack_graph_edges", ["target_node_id"], unique=False)
    op.create_index("ix_attack_graph_edges_edge_type", "attack_graph_edges", ["edge_type"], unique=False)
    op.create_index("ix_attack_graph_edges_source_id", "attack_graph_edges", ["source_id"], unique=False)
    op.create_index("ix_attack_graph_edges_run_type", "attack_graph_edges", ["run_id", "edge_type"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_attack_graph_edges_run_type", table_name="attack_graph_edges")
    op.drop_index("ix_attack_graph_edges_source_id", table_name="attack_graph_edges")
    op.drop_index("ix_attack_graph_edges_edge_type", table_name="attack_graph_edges")
    op.drop_index("ix_attack_graph_edges_target_node_id", table_name="attack_graph_edges")
    op.drop_index("ix_attack_graph_edges_source_node_id", table_name="attack_graph_edges")
    op.drop_index("ix_attack_graph_edges_run_id", table_name="attack_graph_edges")
    op.drop_table("attack_graph_edges")

    op.drop_index("ix_attack_graph_nodes_run_type", table_name="attack_graph_nodes")
    op.drop_index("ix_attack_graph_nodes_source_id", table_name="attack_graph_nodes")
    op.drop_index("ix_attack_graph_nodes_stable_key", table_name="attack_graph_nodes")
    op.drop_index("ix_attack_graph_nodes_node_type", table_name="attack_graph_nodes")
    op.drop_index("ix_attack_graph_nodes_run_id", table_name="attack_graph_nodes")
    op.drop_table("attack_graph_nodes")
