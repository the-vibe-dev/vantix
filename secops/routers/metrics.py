"""P3-8 — Prometheus-compatible ``/metrics`` endpoint.

Surfaces the policy-decision counters that already land on ``run_events``
(``event_type == "policy_decision"``) plus a handful of runtime gauges
(active leases, lease states, worker heartbeats) so Prometheus can scrape
without needing the authenticated runs API. No new data is produced; this
is a read-through aggregator over the existing schema.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable

from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session

from secops.db import get_db
from secops.models import RunEvent, WorkerLease, WorkerRuntimeStatus


router = APIRouter(tags=["metrics"])


def _escape_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n")


def _format_metric(
    name: str,
    help_text: str,
    metric_type: str,
    samples: Iterable[tuple[dict[str, str], float]],
) -> list[str]:
    lines = [f"# HELP {name} {help_text}", f"# TYPE {name} {metric_type}"]
    for labels, value in samples:
        if labels:
            rendered = ",".join(f'{k}="{_escape_label(str(v))}"' for k, v in sorted(labels.items()))
            lines.append(f"{name}{{{rendered}}} {value}")
        else:
            lines.append(f"{name} {value}")
    return lines


def _policy_decision_counters(db: Session) -> list[tuple[dict[str, str], float]]:
    # Aggregate in Python because payload_json equality under SQLite's JSON
    # text storage is unreliable for GROUP BY.
    rows = (
        db.query(RunEvent.payload_json)
        .filter(RunEvent.event_type == "policy_decision")
        .all()
    )
    tallies: dict[tuple[str, str], int] = {}
    for (payload,) in rows:
        if not isinstance(payload, dict):
            continue
        key = (
            str(payload.get("action_kind") or "unknown"),
            str(payload.get("verdict") or "unknown"),
        )
        tallies[key] = tallies.get(key, 0) + 1
    return [
        ({"action_kind": ak, "verdict": vd}, float(total))
        for (ak, vd), total in sorted(tallies.items())
    ]


def _lease_state_gauges(db: Session) -> list[tuple[dict[str, str], float]]:
    rows = db.query(WorkerLease.status).all()
    tallies: dict[str, int] = {}
    for (status,) in rows:
        key = str(status or "unknown")
        tallies[key] = tallies.get(key, 0) + 1
    return [({"state": k}, float(v)) for k, v in sorted(tallies.items())]


def _worker_heartbeat_gauge(db: Session) -> float:
    latest = (
        db.query(WorkerRuntimeStatus.heartbeat_at)
        .order_by(WorkerRuntimeStatus.heartbeat_at.desc())
        .first()
    )
    if not latest or latest[0] is None:
        return 0.0
    heartbeat_at = latest[0]
    if heartbeat_at.tzinfo is None:
        heartbeat_at = heartbeat_at.replace(tzinfo=timezone.utc)
    return max(0.0, (datetime.now(timezone.utc) - heartbeat_at).total_seconds())


@router.get("/metrics")
def prometheus_metrics(db: Session = Depends(get_db)) -> Response:
    lines: list[str] = []
    lines.extend(
        _format_metric(
            name="vantix_policy_decisions_total",
            help_text="Count of policy-decision events by action_kind and verdict.",
            metric_type="counter",
            samples=_policy_decision_counters(db),
        )
    )
    lines.extend(
        _format_metric(
            name="vantix_worker_leases",
            help_text="Number of worker leases by state.",
            metric_type="gauge",
            samples=_lease_state_gauges(db),
        )
    )
    lines.extend(
        _format_metric(
            name="vantix_worker_heartbeat_age_seconds",
            help_text="Age of the most recent worker heartbeat.",
            metric_type="gauge",
            samples=[({}, _worker_heartbeat_gauge(db))],
        )
    )
    body = "\n".join(lines) + "\n"
    return Response(content=body, media_type="text/plain; version=0.0.4; charset=utf-8")
