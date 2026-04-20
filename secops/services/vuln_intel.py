from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

from sqlalchemy import or_, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from secops.models import IntelSource, VulnerabilityIntel, VulnerabilityIntelReference, utcnow

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def normalize_cve_id(value: str) -> str:
    return value.strip().upper()


def extract_cve_ids(*values: str | Iterable[str] | None) -> list[str]:
    found: set[str] = set()
    for value in values:
        if value is None:
            continue
        if isinstance(value, str):
            candidates = [value]
        else:
            candidates = [str(item) for item in value]
        for candidate in candidates:
            for match in CVE_RE.findall(candidate):
                found.add(normalize_cve_id(match))
    return sorted(found)


def parse_datetime(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw:
        return None
    if raw.endswith("Z"):
        raw = f"{raw[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%a, %d %b %Y %H:%M:%S %z"):
            try:
                parsed = datetime.strptime(value.strip(), fmt)
                break
            except ValueError:
                continue
        else:
            return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


@dataclass(frozen=True)
class IntelRecord:
    source: str
    external_id: str
    title: str = ""
    summary: str = ""
    url: str = ""
    cve_ids: list[str] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)
    published_at: datetime | None = None
    modified_at: datetime | None = None
    severity: str = ""
    cvss: float = 0.0
    epss: float = 0.0
    epss_percentile: float = 0.0
    kev: bool = False
    exploit_available: bool = False
    scanner_template_available: bool = False
    confidence: float = 0.5
    metadata: dict[str, Any] = field(default_factory=dict)

    def normalized(self) -> "IntelRecord":
        cves = set(extract_cve_ids(self.external_id, self.title, self.summary, self.cve_ids, self.aliases, self.url))
        aliases = {alias.strip() for alias in self.aliases if alias and alias.strip()}
        aliases.update(cves)
        return IntelRecord(
            source=self.source.strip(),
            external_id=self.external_id.strip() or ":".join(sorted(aliases)),
            title=self.title.strip(),
            summary=self.summary.strip(),
            url=self.url.strip(),
            cve_ids=sorted(cves),
            aliases=sorted(aliases),
            published_at=self.published_at,
            modified_at=self.modified_at,
            severity=self.severity.strip().lower(),
            cvss=float(self.cvss or 0.0),
            epss=float(self.epss or 0.0),
            epss_percentile=float(self.epss_percentile or 0.0),
            kev=bool(self.kev),
            exploit_available=bool(self.exploit_available),
            scanner_template_available=bool(self.scanner_template_available),
            confidence=max(0.0, min(float(self.confidence or 0.0), 1.0)),
            metadata=dict(self.metadata),
        )


class VulnIntelService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def source(self, name: str, *, source_type: str = "", url: str = "") -> IntelSource:
        existing = self.db.execute(select(IntelSource).where(IntelSource.name == name)).scalar_one_or_none()
        if existing is not None:
            if url and not existing.url:
                existing.url = url
            if source_type and existing.source_type != source_type:
                existing.source_type = source_type
            return existing
        source = IntelSource(name=name, source_type=source_type or "api", url=url, enabled=True)
        self.db.add(source)
        self.db.flush()
        return source

    def upsert_records(self, records: Iterable[IntelRecord], *, commit: bool = True) -> dict[str, Any]:
        counts = {"seen": 0, "upserted": 0, "skipped": 0, "references": 0}
        normalized_records: list[IntelRecord] = []
        for raw_record in records:
            counts["seen"] += 1
            record = raw_record.normalized()
            if not record.source or not record.external_id:
                counts["skipped"] += 1
                continue
            normalized_records.append(record)

        max_attempts = 4
        for attempt in range(1, max_attempts + 1):
            try:
                for record in normalized_records:
                    source = self.source(record.source)
                    intel = self.db.execute(
                        select(VulnerabilityIntel).where(
                            VulnerabilityIntel.source_id == source.id,
                            VulnerabilityIntel.external_id == record.external_id,
                        )
                    ).scalar_one_or_none()
                    if intel is None:
                        intel = VulnerabilityIntel(source_id=source.id, external_id=record.external_id)
                        self.db.add(intel)
                        self.db.flush()
                    self._apply_record(intel, record)
                    counts["upserted"] += 1
                    counts["references"] += self._sync_references(intel, record)
                    source.last_success_at = utcnow()
                    source.last_error = ""
                if commit:
                    self.db.commit()
                return counts
            except OperationalError as exc:
                message = str(exc).lower()
                if "database is locked" not in message and "database table is locked" not in message:
                    raise
                self.db.rollback()
                if attempt >= max_attempts:
                    raise
                time.sleep(0.2 * attempt)
                counts["upserted"] = 0
                counts["references"] = 0
                continue
        return counts

    def enrich_results(self, results: list[dict[str, Any]]) -> list[dict[str, Any]]:
        for row in results:
            cve_id = self._row_cve_id(row)
            intel = self.for_cve(cve_id) if cve_id else []
            row["intel"] = intel
            row["priority_score"] = max([entry["priority_score"] for entry in intel], default=self._base_result_score(row))
        results.sort(key=lambda row: float(row.get("priority_score", 0) or 0), reverse=True)
        return results

    def for_cve(self, cve_id: str) -> list[dict[str, Any]]:
        normalized = normalize_cve_id(cve_id)
        refs = self.db.execute(
            select(VulnerabilityIntelReference)
            .where(VulnerabilityIntelReference.cve_id == normalized)
            .order_by(VulnerabilityIntelReference.created_at.desc())
        ).scalars().all()
        seen: set[str] = set()
        items: list[dict[str, Any]] = []
        for ref in refs:
            if ref.intel_id in seen:
                continue
            seen.add(ref.intel_id)
            items.append(self.serialize(ref.intel))
        items.sort(key=lambda item: float(item.get("priority_score", 0) or 0), reverse=True)
        return items

    def recent(self, days: int = 7, limit: int = 100) -> list[dict[str, Any]]:
        # Use updated_at instead of complex DB-specific interval expressions; filtering in Python keeps SQLite/Postgres behavior identical here.
        rows = self.db.execute(
            select(VulnerabilityIntel).order_by(VulnerabilityIntel.priority_score.desc(), VulnerabilityIntel.updated_at.desc()).limit(max(limit * 3, limit))
        ).scalars().all()
        cutoff = datetime.now(timezone.utc).timestamp() - max(days, 1) * 86400
        items = []
        for row in rows:
            timestamp = row.modified_at or row.published_at or row.updated_at
            if timestamp and timestamp.timestamp() >= cutoff:
                items.append(self.serialize(row))
            if len(items) >= limit:
                break
        return items

    def search(self, term: str, *, limit: int = 100, sources: list[str] | None = None) -> list[dict[str, Any]]:
        query = term.strip()
        if not query:
            return []
        cve_ids = extract_cve_ids(query)
        if cve_ids:
            combined: dict[str, dict[str, Any]] = {}
            for cve_id in cve_ids:
                for item in self.for_cve(cve_id):
                    combined[item["id"]] = item
            results = list(combined.values())
            return self._filter_serialized_results(results, sources=sources)[:limit]

        like = f"%{query.lower()}%"
        statement = (
            select(VulnerabilityIntel)
            .join(IntelSource)
            .where(
                or_(
                    VulnerabilityIntel.external_id.ilike(like),
                    VulnerabilityIntel.title.ilike(like),
                    VulnerabilityIntel.summary.ilike(like),
                    VulnerabilityIntel.url.ilike(like),
                )
            )
            .order_by(VulnerabilityIntel.priority_score.desc(), VulnerabilityIntel.updated_at.desc())
            .limit(max(limit, 1))
        )
        if sources:
            statement = statement.where(IntelSource.name.in_(sources))
        return [self.serialize(row) for row in self.db.execute(statement).scalars().all()]

    def filter_records_by_term(self, records: Iterable[IntelRecord], term: str) -> list[IntelRecord]:
        query = term.strip()
        if not query:
            return []
        query_lower = query.lower()
        query_cves = set(extract_cve_ids(query))
        matched: list[IntelRecord] = []
        for record in records:
            normalized = record.normalized()
            if query_cves:
                record_cves = set(normalized.cve_ids) | set(extract_cve_ids(normalized.aliases, normalized.title, normalized.summary))
                if query_cves & record_cves:
                    matched.append(normalized)
                continue
            haystack = " ".join(
                [
                    normalized.external_id,
                    normalized.title,
                    normalized.summary,
                    normalized.url,
                    " ".join(normalized.aliases),
                    " ".join(normalized.cve_ids),
                ]
            ).lower()
            if query_lower in haystack:
                matched.append(normalized)
        return matched

    def serialize(self, intel: VulnerabilityIntel) -> dict[str, Any]:
        source_name = intel.source.name if intel.source is not None else ""
        return {
            "id": intel.id,
            "source": source_name,
            "external_id": intel.external_id,
            "title": intel.title,
            "summary": intel.summary,
            "url": intel.url,
            "aliases": intel.aliases or [],
            "cve_ids": intel.cve_ids or [],
            "published_at": intel.published_at.isoformat() if intel.published_at else None,
            "modified_at": intel.modified_at.isoformat() if intel.modified_at else None,
            "severity": intel.severity,
            "cvss": intel.cvss,
            "epss": intel.epss,
            "epss_percentile": intel.epss_percentile,
            "kev": intel.kev,
            "exploit_available": intel.exploit_available,
            "scanner_template_available": intel.scanner_template_available,
            "confidence": intel.confidence,
            "priority_score": intel.priority_score,
            "metadata": intel.metadata_json or {},
        }

    def _filter_serialized_results(self, results: list[dict[str, Any]], *, sources: list[str] | None = None) -> list[dict[str, Any]]:
        if sources:
            allowed = set(sources)
            results = [item for item in results if item.get("source") in allowed]
        results.sort(key=lambda item: float(item.get("priority_score", 0) or 0), reverse=True)
        return results

    def _apply_record(self, intel: VulnerabilityIntel, record: IntelRecord) -> None:
        intel.title = record.title
        intel.summary = record.summary
        intel.url = record.url
        intel.aliases = record.aliases
        intel.cve_ids = record.cve_ids
        intel.published_at = record.published_at
        intel.modified_at = record.modified_at
        intel.severity = record.severity
        intel.cvss = record.cvss
        intel.epss = record.epss
        intel.epss_percentile = record.epss_percentile
        intel.kev = record.kev
        intel.exploit_available = record.exploit_available
        intel.scanner_template_available = record.scanner_template_available
        intel.confidence = record.confidence
        intel.priority_score = self.priority_score(record)
        intel.metadata_json = record.metadata
        intel.updated_at = utcnow()

    def _sync_references(self, intel: VulnerabilityIntel, record: IntelRecord) -> int:
        expected: set[tuple[str, str, str]] = set()
        for cve_id in record.cve_ids:
            expected.add((cve_id, "cve", cve_id))
        for alias in record.aliases:
            alias_type = "cve" if CVE_RE.fullmatch(alias) else "alias"
            cve_id = alias if alias_type == "cve" else ""
            expected.add((cve_id, alias_type, alias))
        if record.url:
            # URL references are unique on (intel_id, reference_type, reference_value);
            # store one canonical URL reference per intel row.
            expected.add(("", "url", record.url))
        existing = {(ref.cve_id, ref.reference_type, ref.reference_value): ref for ref in intel.references}
        # Include unflushed references already staged in this session so repeated
        # rows for the same external_id in one batch do not attempt duplicate inserts.
        for pending in self.db.new:
            if isinstance(pending, VulnerabilityIntelReference) and pending.intel_id == intel.id:
                existing[(pending.cve_id, pending.reference_type, pending.reference_value)] = pending
        for key, ref in list(existing.items()):
            if key not in expected:
                self.db.delete(ref)
        created = 0
        for cve_id, ref_type, value in sorted(expected):
            if not value or (cve_id, ref_type, value) in existing:
                continue
            self.db.add(VulnerabilityIntelReference(intel_id=intel.id, cve_id=cve_id, reference_type=ref_type, reference_value=value))
            created += 1
        return created

    def priority_score(self, record: IntelRecord) -> float:
        score = 0.0
        if record.kev:
            score += 50.0
        if record.exploit_available:
            score += 20.0
        if record.scanner_template_available:
            score += 12.0
        score += min(record.epss_percentile * 15.0, 15.0)
        score += min(record.cvss, 10.0)
        if record.severity in {"critical", "high"}:
            score += 5.0 if record.severity == "critical" else 3.0
        score += record.confidence * 8.0
        return round(score, 3)

    def _base_result_score(self, row: dict[str, Any]) -> float:
        try:
            return float(row.get("cvss", 0) or 0)
        except (TypeError, ValueError):
            return 0.0

    def _row_cve_id(self, row: dict[str, Any]) -> str:
        for key in ("id", "cve", "cve_id", "cveId"):
            value = row.get(key)
            if isinstance(value, str) and CVE_RE.fullmatch(value.strip()):
                return normalize_cve_id(value)
        cves = extract_cve_ids(str(row))
        return cves[0] if cves else ""
