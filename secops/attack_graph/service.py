from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

from secops.models import AttackGraphEdge, AttackGraphNode, Fact, Finding, WorkspaceRun


@dataclass(frozen=True)
class GraphSyncResult:
    nodes_created: int = 0
    nodes_updated: int = 0
    edges_created: int = 0
    edges_updated: int = 0


@dataclass
class _Counter:
    nodes_created: int = 0
    nodes_updated: int = 0
    edges_created: int = 0
    edges_updated: int = 0


class AttackGraphService:
    """Build and query a compact attack graph from run facts/findings."""

    def sync_run(self, db: Session, run: WorkspaceRun) -> GraphSyncResult:
        result = _Counter()
        target = self._upsert_node(
            db,
            run,
            node_type="target",
            stable_key=f"target:{run.target or run.id}",
            label=run.target or run.workspace_id,
            source_kind="run",
            source_id=run.id,
            confidence=1.0,
            metadata={"mode": run.mode, "objective": run.objective},
            counter=result,
        )

        facts = db.query(Fact).filter(Fact.run_id == run.id).order_by(Fact.created_at.asc()).all()
        for fact in facts:
            self._ingest_fact(db, run, target, fact, result)

        findings = db.query(Finding).filter(Finding.run_id == run.id).order_by(Finding.created_at.asc()).all()
        for finding in findings:
            self._ingest_finding(db, run, target, finding, result)

        db.flush()
        return GraphSyncResult(
            nodes_created=result.nodes_created,
            nodes_updated=result.nodes_updated,
            edges_created=result.edges_created,
            edges_updated=result.edges_updated,
        )

    def read_run(self, db: Session, run: WorkspaceRun, *, sync: bool = True) -> dict[str, Any]:
        if sync:
            self.sync_run(db, run)
        nodes = (
            db.query(AttackGraphNode)
            .filter(AttackGraphNode.run_id == run.id)
            .order_by(AttackGraphNode.node_type.asc(), AttackGraphNode.label.asc())
            .all()
        )
        edges = (
            db.query(AttackGraphEdge)
            .filter(AttackGraphEdge.run_id == run.id)
            .order_by(AttackGraphEdge.edge_type.asc(), AttackGraphEdge.created_at.asc())
            .all()
        )
        return {
            "run_id": run.id,
            "summary": self._summary(nodes, edges),
            "nodes": [self._serialize_node(node) for node in nodes],
            "edges": [self._serialize_edge(edge) for edge in edges],
        }

    def _ingest_fact(self, db: Session, run: WorkspaceRun, target: AttackGraphNode, fact: Fact, counter: "_Counter") -> None:
        kind = str(fact.kind or "").strip().lower()
        value = str(fact.value or "").strip()
        if not value:
            return
        metadata = {"fact_id": fact.id, "source": fact.source, "tags": list(fact.tags or []), **dict(fact.metadata_json or {})}
        if kind == "port":
            node = self._upsert_node(
                db,
                run,
                node_type="service",
                stable_key=f"service:{run.target}:{value}",
                label=f"{run.target}:{value}" if run.target else f"port {value}",
                source_kind="fact",
                source_id=fact.id,
                confidence=fact.confidence,
                metadata={**metadata, "port": value},
                counter=counter,
            )
            self._upsert_edge(db, run, target, node, "exposes", "fact", fact.id, fact.confidence, metadata, counter)
        elif kind == "service":
            node = self._upsert_node(
                db,
                run,
                node_type="service",
                stable_key=f"service-name:{run.target}:{value.lower()}",
                label=value,
                source_kind="fact",
                source_id=fact.id,
                confidence=fact.confidence,
                metadata=metadata,
                counter=counter,
            )
            self._upsert_edge(db, run, target, node, "runs", "fact", fact.id, fact.confidence, metadata, counter)
        elif kind in {"route", "form", "browser-session"} or value.startswith(("http://", "https://", "/")):
            node = self._upsert_node(
                db,
                run,
                node_type="endpoint",
                stable_key=f"endpoint:{value}",
                label=value,
                source_kind="fact",
                source_id=fact.id,
                confidence=fact.confidence,
                metadata=metadata,
                counter=counter,
            )
            self._upsert_edge(db, run, target, node, "has_endpoint", "fact", fact.id, fact.confidence, metadata, counter)
        elif kind in {"cve", "intel"} or value.upper().startswith("CVE-"):
            node = self._upsert_node(
                db,
                run,
                node_type="cve",
                stable_key=f"cve:{value.upper()}",
                label=value.upper(),
                source_kind="fact",
                source_id=fact.id,
                confidence=fact.confidence,
                metadata=metadata,
                counter=counter,
            )
            self._upsert_edge(db, run, target, node, "has_intel", "fact", fact.id, fact.confidence, metadata, counter)
        elif kind in {"vector", "vector_hypothesis", "attack_chain", "negative_evidence", "no_finding"}:
            node_type = "negative_evidence" if kind in {"negative_evidence", "no_finding"} else "hypothesis"
            node = self._upsert_node(
                db,
                run,
                node_type=node_type,
                stable_key=f"{node_type}:{fact.fingerprint or fact.id}",
                label=str((fact.metadata_json or {}).get("title") or value)[:255],
                source_kind="fact",
                source_id=fact.id,
                confidence=fact.confidence,
                metadata={**metadata, "validated": bool(fact.validated), "fingerprint": fact.fingerprint or ""},
                counter=counter,
            )
            edge_type = "refutes" if node_type == "negative_evidence" else "has_hypothesis"
            self._upsert_edge(db, run, target, node, edge_type, "fact", fact.id, fact.confidence, metadata, counter)

    def _ingest_finding(self, db: Session, run: WorkspaceRun, target: AttackGraphNode, finding: Finding, counter: "_Counter") -> None:
        metadata = {
            "finding_id": finding.id,
            "severity": finding.severity,
            "status": finding.status,
            "disposition": finding.disposition,
            "evidence_ids": list(finding.evidence_ids or []),
            "fingerprint": finding.fingerprint or "",
        }
        node = self._upsert_node(
            db,
            run,
            node_type="finding",
            stable_key=f"finding:{finding.fingerprint or finding.id}",
            label=finding.title,
            source_kind="finding",
            source_id=finding.id,
            confidence=finding.confidence,
            metadata=metadata,
            counter=counter,
        )
        self._upsert_edge(db, run, target, node, "has_finding", "finding", finding.id, finding.confidence, metadata, counter)
        for evidence_id in finding.evidence_ids or []:
            source = (
                db.query(AttackGraphNode)
                .filter(AttackGraphNode.run_id == run.id, AttackGraphNode.source_id == evidence_id)
                .order_by(AttackGraphNode.created_at.asc())
                .first()
            )
            if source is not None:
                self._upsert_edge(db, run, source, node, "validated_by", "finding", finding.id, finding.confidence, metadata, counter)

    def _upsert_node(
        self,
        db: Session,
        run: WorkspaceRun,
        *,
        node_type: str,
        stable_key: str,
        label: str,
        source_kind: str,
        source_id: str,
        confidence: float,
        metadata: dict[str, Any],
        counter: "_Counter",
    ) -> AttackGraphNode:
        node = (
            db.query(AttackGraphNode)
            .filter(
                AttackGraphNode.run_id == run.id,
                AttackGraphNode.node_type == node_type,
                AttackGraphNode.stable_key == stable_key,
            )
            .first()
        )
        if node is None:
            node = AttackGraphNode(
                run_id=run.id,
                node_type=node_type,
                stable_key=stable_key,
                label=label[:255],
                source_kind=source_kind,
                source_id=source_id,
                confidence=float(confidence or 0.0),
                metadata_json=dict(metadata or {}),
            )
            db.add(node)
            db.flush()
            counter.nodes_created += 1
            return node
        changed = False
        if label and node.label != label[:255]:
            node.label = label[:255]
            changed = True
        if float(confidence or 0.0) > float(node.confidence or 0.0):
            node.confidence = float(confidence or 0.0)
            changed = True
        merged = {**dict(node.metadata_json or {}), **dict(metadata or {})}
        if merged != dict(node.metadata_json or {}):
            node.metadata_json = merged
            changed = True
        if changed:
            counter.nodes_updated += 1
        return node

    def _upsert_edge(
        self,
        db: Session,
        run: WorkspaceRun,
        source: AttackGraphNode,
        target: AttackGraphNode,
        edge_type: str,
        source_kind: str,
        source_id: str,
        confidence: float,
        metadata: dict[str, Any],
        counter: "_Counter",
    ) -> AttackGraphEdge:
        edge = (
            db.query(AttackGraphEdge)
            .filter(
                AttackGraphEdge.run_id == run.id,
                AttackGraphEdge.source_node_id == source.id,
                AttackGraphEdge.target_node_id == target.id,
                AttackGraphEdge.edge_type == edge_type,
            )
            .first()
        )
        if edge is None:
            edge = AttackGraphEdge(
                run_id=run.id,
                source_node_id=source.id,
                target_node_id=target.id,
                edge_type=edge_type,
                source_kind=source_kind,
                source_id=source_id,
                confidence=float(confidence or 0.0),
                metadata_json=dict(metadata or {}),
            )
            db.add(edge)
            db.flush()
            counter.edges_created += 1
            return edge
        changed = False
        if float(confidence or 0.0) > float(edge.confidence or 0.0):
            edge.confidence = float(confidence or 0.0)
            changed = True
        merged = {**dict(edge.metadata_json or {}), **dict(metadata or {})}
        if merged != dict(edge.metadata_json or {}):
            edge.metadata_json = merged
            changed = True
        if changed:
            counter.edges_updated += 1
        return edge

    def _summary(self, nodes: list[AttackGraphNode], edges: list[AttackGraphEdge]) -> dict[str, Any]:
        node_types: dict[str, int] = {}
        edge_types: dict[str, int] = {}
        for node in nodes:
            node_types[node.node_type] = node_types.get(node.node_type, 0) + 1
        for edge in edges:
            edge_types[edge.edge_type] = edge_types.get(edge.edge_type, 0) + 1
        return {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "node_types": node_types,
            "edge_types": edge_types,
        }

    def _serialize_node(self, node: AttackGraphNode) -> dict[str, Any]:
        return {
            "id": node.id,
            "type": node.node_type,
            "key": node.stable_key,
            "label": node.label,
            "source_kind": node.source_kind,
            "source_id": node.source_id,
            "confidence": node.confidence,
            "metadata": dict(node.metadata_json or {}),
        }

    def _serialize_edge(self, edge: AttackGraphEdge) -> dict[str, Any]:
        return {
            "id": edge.id,
            "source": edge.source_node_id,
            "target": edge.target_node_id,
            "type": edge.edge_type,
            "source_kind": edge.source_kind,
            "source_id": edge.source_id,
            "confidence": edge.confidence,
            "metadata": dict(edge.metadata_json or {}),
        }
