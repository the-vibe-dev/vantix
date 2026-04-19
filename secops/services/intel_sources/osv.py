from __future__ import annotations

from secops.services.intel_sources.base import SourceUpdateResult, http_client, safe_float
from secops.services.vuln_intel import IntelRecord, extract_cve_ids, parse_datetime


class OsvAdapter:
    name = "osv"
    source_type = "api"
    url = "https://api.osv.dev/v1/vulns/"

    def fetch_since(self, cursor: dict | None = None) -> SourceUpdateResult:
        # OSV does not provide a small global "latest" endpoint. This adapter enriches aliases explicitly provided in the cursor.
        vuln_ids = list((cursor or {}).get("ids", []))
        if not vuln_ids:
            return SourceUpdateResult(source=self.name, records=[], cursor={"count": 0, "note": "set cursor.ids to OSV/GHSA IDs for targeted enrichment"})
        records = []
        try:
            with http_client() as client:
                for vuln_id in vuln_ids[: int((cursor or {}).get("limit", 100))]:
                    data = client.get(f"{self.url}{vuln_id}").raise_for_status().json()
                    records.append(self._record(data))
        except Exception as exc:  # noqa: BLE001
            return SourceUpdateResult(source=self.name, records=records, error=str(exc))
        return SourceUpdateResult(source=self.name, records=records, cursor={"count": len(records)})

    def _record(self, row: dict) -> IntelRecord:
        aliases = [row.get("id", ""), *row.get("aliases", [])]
        cves = extract_cve_ids(aliases, row.get("summary", ""), row.get("details", ""))
        severity = ""
        cvss = 0.0
        for severity_row in row.get("severity", []):
            if severity_row.get("type", "").upper().startswith("CVSS"):
                severity = severity_row.get("score", "")
        database_specific = row.get("database_specific") or {}
        if isinstance(database_specific, dict):
            cvss = safe_float(database_specific.get("cvss"))
        references = row.get("references", [])
        first_ref = references[0].get("url", "") if references and isinstance(references[0], dict) else ""
        return IntelRecord(
            source=self.name,
            external_id=row.get("id", ""),
            title=row.get("summary", ""),
            summary=row.get("details", ""),
            url=first_ref,
            cve_ids=cves,
            aliases=[alias for alias in aliases if alias],
            published_at=parse_datetime(row.get("published")),
            modified_at=parse_datetime(row.get("modified")),
            severity=severity,
            cvss=cvss,
            confidence=0.75,
            metadata=row,
        )
