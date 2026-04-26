from __future__ import annotations

import json
from datetime import datetime, timezone

from secops.models import ApprovalRequest, Fact, RunMessage, WorkspaceRun
from secops.services.exploit_validation import ExploitValidationService
from secops.services.fingerprint import fingerprint_from_meta
from secops.services.memory_writer import DenseMemoryRecord
from secops.services.storage import StorageLayout


class DecisionMixin:
    """Approvals, memory writes, policy emission, post-orchestrate sweep, learning block.

    Extracted from ExecutionManager. Methods rely on ``self.events``,
    ``self.memory`` from peer mixins / __init__.
    """

    def _sweep_orchestrator_vectors(self, db, run: WorkspaceRun, *, session_started_at) -> None:
        """Post-orchestrate: fingerprint vectors and replay any with a validation spec.

        Vectors without a `replay` spec in their metadata stay kind=vector but
        validated=False, so they will not promote when SECOPS_REQUIRE_VALIDATED_PROMOTION
        is enabled. Vectors with a spec are replayed via ExploitValidationService,
        which marks validated=True on success or writes a negative_evidence Fact
        with a matching fingerprint on failure.
        """
        cutoff = session_started_at
        q = (
            db.query(Fact)
            .filter(
                Fact.run_id == run.id,
                Fact.kind.in_(["vector", "vector_hypothesis"]),
            )
        )
        if cutoff is not None:
            q = q.filter(Fact.created_at >= cutoff)
        vectors = q.all()
        if not vectors:
            return
        validator = ExploitValidationService()
        for fact in vectors:
            meta = dict(fact.metadata_json or {})
            if not fact.fingerprint:
                fact.fingerprint = fingerprint_from_meta(meta, fact_kind=fact.kind)
            replay = meta.get("replay")
            if not (isinstance(replay, dict) and replay.get("type") == "http"):
                continue
            if fact.validated:
                continue
            try:
                validator.validate_vector(db, run, fact)
            except Exception as exc:  # noqa: BLE001
                self.events.emit(
                    db,
                    run.id,
                    "terminal",
                    f"Exploit validation raised for fact {fact.id[:8]}: {exc}",
                    level="warning",
                )
        db.flush()

    def _learning_block(self, paths: StorageLayout) -> str:
        learning_path = paths.facts / "learning_hits.json"
        if not learning_path.exists():
            return ""
        try:
            rows = json.loads(learning_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return ""
        lines = []
        for row in rows[:5]:
            title = str(row.get("title", "")).strip()
            summary = str(row.get("summary_short") or row.get("summary") or "").strip()
            rank = row.get("rank", "")
            if not title:
                continue
            line = f"- {title}"
            if rank != "":
                line += f" (rank {rank})"
            if summary:
                line += f": {summary}"
            lines.append(line)
        return "\n".join(lines)

    def _create_approval(
        self,
        db,
        run_id: str,
        title: str,
        detail: str,
        reason: str,
        metadata: dict | None = None,
    ) -> ApprovalRequest:
        metadata = metadata or {}
        existing = (
            db.query(ApprovalRequest)
            .filter(
                ApprovalRequest.run_id == run_id,
                ApprovalRequest.reason == reason,
                ApprovalRequest.status == "pending",
            )
            .order_by(ApprovalRequest.created_at.desc())
            .first()
        )
        if existing is not None and (not metadata or all(existing.metadata_json.get(key) == value for key, value in metadata.items())):
            return existing
        latest = (
            db.query(ApprovalRequest)
            .filter(ApprovalRequest.run_id == run_id, ApprovalRequest.reason == reason)
            .order_by(ApprovalRequest.created_at.desc())
            .first()
        )
        if latest is not None and latest.status == "approved":
            same_context = not metadata or all((latest.metadata_json or {}).get(key) == value for key, value in metadata.items())
            approved_recently = (datetime.now(timezone.utc) - latest.updated_at).total_seconds() <= 300
            if same_context and approved_recently:
                return latest
        approval = ApprovalRequest(run_id=run_id, title=title, detail=detail, reason=reason, status="pending", metadata_json=metadata)
        db.add(approval)
        self.events.emit(db, run_id, "approval", title, level="warning", payload={"reason": reason, **metadata})
        db.add(
            RunMessage(
                run_id=run_id,
                role="system",
                author="System",
                content=f"Approval required: {title}. {detail}",
                metadata_json={"approval_reason": reason, **metadata},
            )
        )
        return approval

    def _write_memory(
        self,
        db,
        run: WorkspaceRun | None,
        *,
        mode: str,
        phase: str,
        done: list[str] | None = None,
        issues: list[str] | None = None,
        files: list[str] | None = None,
        facts: list[list[str]] | None = None,
        next_action: str = "",
    ) -> None:
        if run is None:
            return
        try:
            self.memory.write(
                DenseMemoryRecord(
                    mode=mode,
                    run_id=run.id,
                    phase=phase,
                    objective=run.objective,
                    done=done or [],
                    issues=issues or [],
                    files=files or [],
                    facts=facts or [],
                    next_action=next_action,
                    context=[run.mode, *run.config_json.get("tags", [])],
                ),
                db=db,
            )
        except Exception as exc:  # noqa: BLE001
            self.events.emit(db, run.id, "memory_error", f"Memory write failed: {exc}", level="warning")

    def _emit_policy_decision(
        self,
        db,
        *,
        run_id: str,
        action_kind: str,
        verdict: str,
        reason: str,
        audit: bool,
    ) -> None:
        self.events.emit(
            db,
            run_id,
            "policy_decision",
            f"policy:{action_kind}:{verdict}",
            level="warning" if verdict in {"block", "require_approval"} else "info",
            payload={"action_kind": action_kind, "verdict": verdict, "reason": reason, "audit": audit},
        )
