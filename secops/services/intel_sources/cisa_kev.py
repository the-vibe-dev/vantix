from __future__ import annotations

from secops.services.intel_sources.base import SourceUpdateResult, http_client
from secops.services.vuln_intel import IntelRecord, parse_datetime


class CisaKevAdapter:
    name = "cisa_kev"
    source_type = "api"
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def fetch_since(self, cursor: dict | None = None) -> SourceUpdateResult:
        try:
            with http_client() as client:
                data = client.get(self.url).raise_for_status().json()
        except Exception as exc:  # noqa: BLE001
            return SourceUpdateResult(source=self.name, records=[], error=str(exc))
        records = []
        for row in data.get("vulnerabilities", []):
            cve_id = row.get("cveID", "")
            records.append(
                IntelRecord(
                    source=self.name,
                    external_id=cve_id,
                    title=f"{row.get('vendorProject', '')} {row.get('product', '')}".strip(),
                    summary=row.get("shortDescription", ""),
                    url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                    cve_ids=[cve_id] if cve_id else [],
                    aliases=[cve_id] if cve_id else [],
                    published_at=parse_datetime(row.get("dateAdded")),
                    modified_at=parse_datetime(row.get("dateUpdated")) or parse_datetime(row.get("dateAdded")),
                    kev=True,
                    severity="high",
                    confidence=0.95,
                    metadata=row,
                )
            )
        return SourceUpdateResult(source=self.name, records=records, cursor={"count": len(records)})
