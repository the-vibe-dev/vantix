"""P2-5 — Finding review service.

Transitions a Finding's disposition (draft → reviewed|confirmed|dismissed)
while stamping the reviewer identity and review timestamp for chain-of-custody.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from secops.models import Finding, User, WorkspaceRun
from secops.services.events import RunEventService


ALLOWED_DISPOSITIONS = frozenset({"draft", "reviewed", "confirmed", "dismissed"})
TERMINAL_DISPOSITIONS = frozenset({"confirmed", "dismissed"})


class ReviewError(ValueError):
    """Raised when a review request is invalid (bad disposition, missing reviewer, etc.)."""


class FindingReviewService:
    def __init__(self) -> None:
        self.events = RunEventService()

    def review(
        self,
        db: Session,
        run: WorkspaceRun,
        finding_id: str,
        *,
        reviewer_username: str,
        disposition: str,
        note: str = "",
    ) -> Finding:
        disposition = (disposition or "").strip().lower()
        if disposition not in ALLOWED_DISPOSITIONS:
            raise ReviewError(
                f"Invalid disposition '{disposition}'. Allowed: {sorted(ALLOWED_DISPOSITIONS)}"
            )
        finding = db.get(Finding, finding_id)
        if finding is None or finding.run_id != run.id:
            raise ReviewError("Finding not found for this run")

        # Terminal dispositions latch — prevent silent overwrites.
        if finding.disposition in TERMINAL_DISPOSITIONS and disposition != finding.disposition:
            raise ReviewError(
                f"Finding already {finding.disposition}; cannot transition to {disposition}"
            )

        reviewer_user_id = self._resolve_reviewer_id(db, reviewer_username)

        previous = finding.disposition
        finding.disposition = disposition
        finding.reviewed_at = datetime.now(timezone.utc)
        finding.reviewer_user_id = reviewer_user_id
        # Auto-lift status from "draft" when a reviewer acts, but leave
        # explicit statuses (e.g., "validated") alone.
        if disposition in TERMINAL_DISPOSITIONS and str(finding.status or "").lower() == "draft":
            finding.status = "reviewed"

        self.events.emit(
            db,
            run.id,
            "finding_reviewed",
            f"Finding {finding.id[:8]} {previous} → {disposition} by {reviewer_username}",
            payload={
                "finding_id": finding.id,
                "previous_disposition": previous,
                "disposition": disposition,
                "reviewer_username": reviewer_username,
                "reviewer_user_id": reviewer_user_id,
                "note": note[:500],
            },
        )
        return finding

    def _resolve_reviewer_id(self, db: Session, username: str) -> str | None:
        uname = (username or "").strip()
        if not uname:
            return None
        user = db.query(User).filter(User.username == uname).first()
        return user.id if user is not None else None
