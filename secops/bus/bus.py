"""AgentMessageBus — durable, typed pub/sub on the ``bus_events`` table.

Every message the planner/executor/evaluator exchanges is persisted as a
``BusEvent`` row carrying a vantix.event.v2 envelope. Subscribers read by
``(run_id, branch_id)`` cursor. The bus is intentionally dumb: it does
not know about agents or turns beyond what the envelope carries.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Iterable, Iterator

from sqlalchemy import select
from sqlalchemy.orm import Session

from secops.bus.messages import BusEnvelope
from secops.models import BusEvent


@dataclass
class BusCursor:
    last_seq: int = 0


def _content_hash(payload: dict) -> str:
    canon = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canon).hexdigest()


class AgentMessageBus:
    def __init__(self, db: Session) -> None:
        self._db = db

    def publish(self, envelope: BusEnvelope) -> BusEvent:
        """Append an envelope to the bus and return the persisted row."""
        last_seq = (
            self._db.execute(
                select(BusEvent.seq)
                .where(BusEvent.run_id == envelope.run_id)
                .where(BusEvent.branch_id == envelope.branch_id)
                .order_by(BusEvent.seq.desc())
                .limit(1)
            ).scalar()
            or 0
        )
        payload = envelope.payload
        digest = envelope.content_hash or _content_hash(payload)
        row = BusEvent(
            run_id=envelope.run_id,
            branch_id=envelope.branch_id,
            seq=last_seq + 1,
            turn_id=envelope.turn_id,
            agent=envelope.agent,
            type=envelope.type,
            payload_json=payload,
            parent_turn_id=envelope.parent_turn_id,
            caused_by_fact_ids=list(envelope.caused_by_fact_ids),
            content_hash=digest,
            created_at=envelope.ts,
        )
        self._db.add(row)
        self._db.flush()
        return row

    def read(
        self,
        run_id: str,
        *,
        branch_id: str = "main",
        after_seq: int = 0,
        limit: int | None = None,
    ) -> list[BusEvent]:
        stmt = (
            select(BusEvent)
            .where(BusEvent.run_id == run_id)
            .where(BusEvent.branch_id == branch_id)
            .where(BusEvent.seq > after_seq)
            .order_by(BusEvent.seq.asc())
        )
        if limit is not None:
            stmt = stmt.limit(limit)
        return list(self._db.execute(stmt).scalars())

    def tail(
        self,
        run_id: str,
        *,
        branch_id: str = "main",
        cursor: BusCursor | None = None,
    ) -> Iterator[BusEvent]:
        """Drain all messages newer than the cursor; advance the cursor in-place."""
        c = cursor or BusCursor()
        rows = self.read(run_id, branch_id=branch_id, after_seq=c.last_seq)
        for row in rows:
            c.last_seq = row.seq
            yield row

    def envelopes(self, rows: Iterable[BusEvent]) -> list[BusEnvelope]:
        """Convert persisted rows back into typed envelopes."""
        out: list[BusEnvelope] = []
        for row in rows:
            out.append(
                BusEnvelope(
                    run_id=row.run_id,
                    branch_id=row.branch_id,
                    turn_id=row.turn_id,
                    agent=row.agent,  # type: ignore[arg-type]
                    type=row.type,  # type: ignore[arg-type]
                    payload=dict(row.payload_json or {}),
                    parent_turn_id=row.parent_turn_id,
                    caused_by_fact_ids=list(row.caused_by_fact_ids or []),
                    content_hash=row.content_hash,
                    ts=row.created_at,
                )
            )
        return out
