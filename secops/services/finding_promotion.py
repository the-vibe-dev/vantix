from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from secops.models import Fact, Finding, WorkspaceRun
from secops.services.events import RunEventService


class FindingPromotionService:
    def __init__(self) -> None:
        self.events = RunEventService()

    def promote(self, db: Session, run: WorkspaceRun, payload: dict[str, Any]) -> Finding:
        source_kind = str(payload.get("source_kind") or "")
        source_id = str(payload.get("source_id") or "")
        fact = db.get(Fact, source_id)
        if fact is None or fact.run_id != run.id:
            raise ValueError("Source record not found")
        if source_kind == "vector" and fact.kind != "vector":
            raise ValueError("Source is not a vector")
        if source_kind == "attack_chain" and fact.kind != "attack_chain":
            raise ValueError("Source is not an attack chain")

        data = self._finding_payload(fact, payload)
        finding = Finding(run_id=run.id, **data)
        db.add(finding)
        db.flush()

        metadata = dict(fact.metadata_json or {})
        metadata["finding_id"] = finding.id
        metadata["promoted"] = True
        metadata["finding_status"] = finding.status
        fact.metadata_json = metadata
        if "finding" not in fact.tags:
            fact.tags = sorted(set([*fact.tags, "finding"]))

        self.events.emit(
            db,
            run.id,
            "finding",
            f"Promoted {source_kind} to finding draft: {finding.title}",
            payload={
                "source_kind": source_kind,
                "source_id": fact.id,
                "finding_id": finding.id,
                "finding_title": finding.title,
                "finding_status": finding.status,
                "severity": finding.severity,
            },
        )
        return finding

    def _finding_payload(self, fact: Fact, payload: dict[str, Any]) -> dict[str, Any]:
        meta = dict(fact.metadata_json or {})
        title = str(payload.get("title") or meta.get("title") or meta.get("name") or fact.value or "Promoted finding")
        summary = str(payload.get("summary") or meta.get("summary") or meta.get("notes") or "")
        evidence = str(payload.get("evidence") or meta.get("evidence") or meta.get("notes") or "")
        remediation = str(payload.get("remediation") or meta.get("remediation") or "Validate scope, reproduce safely, then document a minimal remediation path.")
        reproduction = str(payload.get("reproduction") or meta.get("next_action") or self._render_reproduction(meta))
        severity = str(payload.get("severity") or meta.get("severity") or self._severity_for_fact(fact))
        status = str(payload.get("status") or "draft")
        confidence = float(payload.get("confidence") if payload.get("confidence") is not None else fact.confidence)
        return {
            "title": title,
            "severity": severity,
            "status": status,
            "summary": summary,
            "evidence": evidence,
            "reproduction": reproduction,
            "remediation": remediation,
            "confidence": confidence,
        }

    def _severity_for_fact(self, fact: Fact) -> str:
        meta = dict(fact.metadata_json or {})
        if fact.kind == "attack_chain":
            score = int(meta.get("score") or round((fact.confidence or 0.0) * 100))
            if score >= 85:
                return "critical"
            if score >= 65:
                return "high"
            if score >= 40:
                return "medium"
            return "low"
        severity = str(meta.get("severity") or "info").lower()
        return severity if severity in {"info", "low", "medium", "high", "critical"} else "info"

    def _render_reproduction(self, meta: dict[str, Any]) -> str:
        steps = meta.get("steps")
        if isinstance(steps, list) and steps:
            return "\n".join(f"- {step}" for step in steps)
        return str(meta.get("next_action") or "")
