#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from secops.config import settings
from secops.db import Base, SessionLocal, engine
from secops.models import utcnow
from secops.services.intel_sources import adapter_for, available_sources
from secops.services.vuln_intel import VulnIntelService


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Update the sidecar vulnerability intelligence database.")
    parser.add_argument("--source", action="append", default=[], help="Source name to update. Can be supplied multiple times.")
    parser.add_argument("--all", action="store_true", help="Update all known sources, including optional token-gated sources.")
    parser.add_argument("--dry-run", action="store_true", help="Fetch and normalize records without writing to the DB.")
    parser.add_argument("--limit", type=int, default=100, help="Per-source adapter limit where supported.")
    parser.add_argument("--since-year", type=int, default=0, help="Only keep records with published/modified timestamp on or after Jan 1 of this year.")
    parser.add_argument("--report-json", default="", help="Path for the update report JSON. Defaults under artifacts/secops/vuln-intel/.")
    return parser.parse_args()


def default_report_path() -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return settings.reports_root / "vuln-intel" / f"update_{stamp}.json"


def update_source(name: str, *, limit: int, dry_run: bool, since_year: int) -> dict:
    adapter = adapter_for(name)
    result = adapter.fetch_since({"limit": limit})
    source_url = getattr(adapter, "url", "")
    cutoff = datetime(since_year, 1, 1, tzinfo=timezone.utc) if since_year >= 1970 else None
    records = list(result.records)
    fetched_count = len(records)
    deduped_by_external: dict[str, object] = {}
    for record in records:
        external_id = str(getattr(record, "external_id", "") or "").strip()
        if not external_id:
            continue
        deduped_by_external[external_id] = record
    records = list(deduped_by_external.values())
    deduped_count = len(records)
    with_cve_count = sum(1 for record in records if getattr(record, "cve_ids", None))
    without_cve_count = deduped_count - with_cve_count
    cutoff_relaxed = False
    filtered_by_date = len(records)
    kept_cve_relaxation = 0
    if cutoff is not None:
        filtered = [record for record in records if (record.modified_at or record.published_at or datetime(1970, 1, 1, tzinfo=timezone.utc)) >= cutoff]
        filtered_by_date = len(filtered)
        # ExploitDB CSV can be stale on publish dates while still carrying useful CVE-linked PoC metadata.
        # Avoid silently dropping the entire source when a strict year cutoff yields zero rows.
        if name == "exploitdb" and records and not filtered:
            cutoff_relaxed = True
            relaxed = [record for record in records if getattr(record, "cve_ids", None)]
            kept_cve_relaxation = len(relaxed)
            records = relaxed or records
        else:
            records = filtered
    report = {
        "source": name,
        "url": source_url,
        "fetched": fetched_count,
        "deduped": deduped_count,
        "filtered": len(records),
        "since_year": since_year,
        "cutoff_relaxed": cutoff_relaxed,
        "filter_stats": {
            "after_external_id_dedup": deduped_count,
            "after_date_filter": filtered_by_date,
            "kept_with_cve_relaxation": kept_cve_relaxation,
            "accepted_with_cve": with_cve_count,
            "accepted_without_cve": without_cve_count,
        },
        "cursor": result.cursor,
        "error": result.error,
        "dry_run": dry_run,
        "db": {"seen": 0, "upserted": 0, "skipped": 0, "references": 0},
    }
    if dry_run:
        return report
    with SessionLocal() as db:
        service = VulnIntelService(db)
        source = service.source(name, source_type=getattr(adapter, "source_type", "api"), url=source_url)
        if result.error:
            source.last_error = result.error
            db.commit()
            return report
        report["db"] = service.upsert_records(records, commit=False)
        source.cursor_json = result.cursor
        source.last_success_at = utcnow()
        source.last_error = ""
        db.commit()
    return report


def main() -> int:
    args = parse_args()
    Base.metadata.create_all(bind=engine)
    if args.all:
        sources = available_sources(include_optional=True)
    elif args.source:
        sources = args.source
    else:
        sources = available_sources(include_optional=False)
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "dry_run": args.dry_run,
        "sources": [],
    }
    for source in sources:
        report["sources"].append(update_source(source, limit=args.limit, dry_run=args.dry_run, since_year=args.since_year))
    report_path = Path(args.report_json) if args.report_json else default_report_path()
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    print(f"Report written: {report_path}", file=sys.stderr)
    return 1 if any(item.get("error") for item in report["sources"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
