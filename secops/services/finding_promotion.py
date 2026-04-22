from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from secops.config import settings
from secops.models import Fact, Finding, WorkspaceRun
from secops.services.events import RunEventService
from secops.services.fingerprint import fingerprint_from_meta


class ValidationRequired(ValueError):
    """Raised when a fact is promoted without validation while the gate is active."""


class SuppressedByNegativeEvidence(ValueError):
    """Raised when a matching negative_evidence fact suppresses promotion."""


class FindingPromotionService:
    def __init__(self) -> None:
        self.events = RunEventService()

    def promote(self, db: Session, run: WorkspaceRun, payload: dict[str, Any]) -> Finding:
        source_kind = str(payload.get("source_kind") or "")
        source_id = str(payload.get("source_id") or "")
        fact = db.get(Fact, source_id)
        if fact is None or fact.run_id != run.id:
            raise ValueError("Source record not found")
        if source_kind == "vector" and fact.kind not in {"vector", "vector_hypothesis"}:
            raise ValueError("Source is not a vector")
        if source_kind == "attack_chain" and fact.kind != "attack_chain":
            raise ValueError("Source is not an attack chain")

        fingerprint = fact.fingerprint or fingerprint_from_meta(
            dict(fact.metadata_json or {}), fact_kind=fact.kind
        )
        if not fact.fingerprint:
            fact.fingerprint = fingerprint

        # P0-4: require validated=True when gate is active and source is a vector.
        if (
            settings.require_validated_promotion
            and source_kind == "vector"
            and not fact.validated
        ):
            raise ValidationRequired(
                "Vector is not validated; run exploit_validation before promoting."
            )

        # P0-5: suppress when matching negative_evidence exists (newer than fact).
        neg = self._matching_negative_evidence(db, run.id, fingerprint, fact)
        if neg is not None:
            self.events.emit(
                db,
                run.id,
                "finding_suppressed",
                f"Suppressed by negative evidence: {fingerprint[:8]}",
                payload={
                    "source_kind": source_kind,
                    "source_id": fact.id,
                    "negative_evidence_id": neg.id,
                    "fingerprint": fingerprint,
                },
            )
            raise SuppressedByNegativeEvidence(
                f"Matching negative evidence ({neg.id}) supersedes this vector; not promoting."
            )

        # P0-6: dedup by fingerprint within the run.
        existing = (
            db.query(Finding)
            .filter(Finding.run_id == run.id, Finding.fingerprint == fingerprint)
            .first()
        )
        if existing is not None:
            evidence_ids = list(existing.evidence_ids or [])
            if fact.id not in evidence_ids:
                evidence_ids.append(fact.id)
            for artifact_id in self._artifact_ids_from_fact(fact):
                if artifact_id and artifact_id not in evidence_ids:
                    evidence_ids.append(artifact_id)
            existing.evidence_ids = evidence_ids
            self._tag_fact_as_promoted(fact, existing)
            self.events.emit(
                db,
                run.id,
                "dedup_merged",
                f"Duplicate vector merged into finding {existing.id[:8]}",
                payload={
                    "source_kind": source_kind,
                    "source_id": fact.id,
                    "finding_id": existing.id,
                    "fingerprint": fingerprint,
                },
            )
            return existing

        data = self._finding_payload(fact, payload)
        data["fingerprint"] = fingerprint
        evidence_ids: list[str] = [fact.id]
        for artifact_id in self._artifact_ids_from_fact(fact):
            if artifact_id and artifact_id not in evidence_ids:
                evidence_ids.append(artifact_id)
        data["evidence_ids"] = evidence_ids
        data["reproduction_script"] = str(
            payload.get("reproduction_script")
            or (fact.metadata_json or {}).get("reproduction_script")
            or ""
        )
        data["promoted_at"] = datetime.now(timezone.utc)
        data.setdefault("disposition", "draft")
        finding = Finding(run_id=run.id, **data)
        db.add(finding)
        db.flush()

        self._tag_fact_as_promoted(fact, finding)

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
                "fingerprint": fingerprint,
            },
        )
        return finding

    def _matching_negative_evidence(
        self, db: Session, run_id: str, fingerprint: str, fact: Fact
    ) -> Fact | None:
        """Return a newer negative_evidence Fact with the same fingerprint, if any."""
        if not fingerprint:
            return None
        q = (
            db.query(Fact)
            .filter(
                Fact.run_id == run_id,
                Fact.kind == "negative_evidence",
                Fact.fingerprint == fingerprint,
            )
            .order_by(Fact.created_at.desc())
        )
        for candidate in q.all():
            if candidate.id == fact.id:
                continue
            if candidate.created_at and fact.created_at and candidate.created_at < fact.created_at:
                continue
            return candidate
        return None

    def _artifact_ids_from_fact(self, fact: Fact) -> list[str]:
        """Pull linked evidence artifact IDs out of fact.metadata.

        Recognizes ``evidence_artifact_ids: [...]`` and, for convenience,
        a scalar ``screenshot_artifact_id`` / ``proof_artifact_id``.
        """
        meta = dict(fact.metadata_json or {})
        ids: list[str] = []
        raw = meta.get("evidence_artifact_ids")
        if isinstance(raw, (list, tuple)):
            for item in raw:
                text = str(item or "").strip()
                if text:
                    ids.append(text)
        for key in ("screenshot_artifact_id", "proof_artifact_id"):
            scalar = meta.get(key)
            if scalar:
                text = str(scalar).strip()
                if text and text not in ids:
                    ids.append(text)
        return ids

    def _tag_fact_as_promoted(self, fact: Fact, finding: Finding) -> None:
        metadata = dict(fact.metadata_json or {})
        metadata["finding_id"] = finding.id
        metadata["promoted"] = True
        metadata["finding_status"] = finding.status
        fact.metadata_json = metadata
        if "finding" not in fact.tags:
            fact.tags = sorted(set([*fact.tags, "finding"]))

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
